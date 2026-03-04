locals {
  ghe_key_lookup_enabled = var.enable_ghe_key_lookup && var.ghe_key_lookup_count > 0

  ghe_key_lookup_listen_port = var.ghe_key_lookup_listen_ports[0]
  ghe_key_lookup_vpc_id      = var.ghe_key_lookup_vpc_id != null ? var.ghe_key_lookup_vpc_id : local.vpc_id
  ghe_key_lookup_subnet_ids  = length(var.ghe_key_lookup_subnet_ids) > 0 ? var.ghe_key_lookup_subnet_ids : [local.private_subnet_id]
  ghe_key_lookup_share_vpc   = var.ghe_key_lookup_vpc_id == null || var.ghe_key_lookup_vpc_id == local.vpc_id

  create_ghe_key_lookup_security_group = local.ghe_key_lookup_enabled && length(var.ghe_key_lookup_security_group_ids) == 0
  ghe_key_lookup_security_group_ids = local.ghe_key_lookup_enabled ? (
    local.create_ghe_key_lookup_security_group ? [aws_security_group.ghe_key_lookup[0].id] : var.ghe_key_lookup_security_group_ids
  ) : []
}

check "ghe_key_lookup_requires_target_endpoint" {
  assert {
    condition     = !local.ghe_key_lookup_enabled || trimspace(var.ghe_key_lookup_ssh_target_endpoint) != ""
    error_message = "ghe_key_lookup_ssh_target_endpoint must be set when enable_ghe_key_lookup is true."
  }
}

check "ghe_key_lookup_ingress_when_cross_vpc" {
  assert {
    condition = (
      !local.create_ghe_key_lookup_security_group ||
      local.ghe_key_lookup_share_vpc ||
      length(var.ghe_key_lookup_allowed_cidrs) > 0
    )
    error_message = "When ghe_key_lookup_vpc_id is different from the forgeproxy VPC and module-managed SG is used, set ghe_key_lookup_allowed_cidrs or provide ghe_key_lookup_security_group_ids."
  }
}

resource "aws_security_group" "ghe_key_lookup" {
  count = local.create_ghe_key_lookup_security_group ? 1 : 0

  name        = "${var.name_prefix}-ghe-key-lookup-sg"
  description = "Security group for ghe-key-lookup instances"
  vpc_id      = local.ghe_key_lookup_vpc_id

  dynamic "ingress" {
    for_each = local.ghe_key_lookup_share_vpc ? var.ghe_key_lookup_listen_ports : []
    content {
      from_port       = ingress.value
      to_port         = ingress.value
      protocol        = "tcp"
      security_groups = [local.forgeproxy_security_group_id]
      description     = "ghe-key-lookup from forgeproxy instances"
    }
  }

  dynamic "ingress" {
    for_each = var.ghe_key_lookup_listen_ports
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = var.ghe_key_lookup_allowed_cidrs
      description = "ghe-key-lookup from allowed CIDRs"
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
  }

  tags = {
    Name = "${var.name_prefix}-ghe-key-lookup-sg"
  }
}

resource "aws_lb" "ghe_key_lookup" {
  count = local.ghe_key_lookup_enabled ? 1 : 0

  name               = "${var.name_prefix}-ghe-key-lookup"
  internal           = true
  load_balancer_type = "network"
  subnets            = local.ghe_key_lookup_subnet_ids

  tags = {
    Name = "${var.name_prefix}-ghe-key-lookup-nlb"
  }
}

resource "aws_lb_target_group" "ghe_key_lookup" {
  count = local.ghe_key_lookup_enabled ? 1 : 0

  name        = "${var.name_prefix}-ghe-key-lookup"
  port        = local.ghe_key_lookup_listen_port
  protocol    = "TCP"
  vpc_id      = local.ghe_key_lookup_vpc_id
  target_type = "instance"

  health_check {
    enabled             = true
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 6
    interval            = 20
    port                = tostring(local.ghe_key_lookup_listen_port)
    protocol            = "HTTP"
    path                = "/healthz"
    matcher             = "200-299"
  }

  tags = {
    Name = "${var.name_prefix}-ghe-key-lookup-tg"
  }
}

resource "aws_lb_listener" "ghe_key_lookup" {
  count = local.ghe_key_lookup_enabled ? length(var.ghe_key_lookup_listen_ports) : 0

  load_balancer_arn = aws_lb.ghe_key_lookup[0].arn
  port              = var.ghe_key_lookup_listen_ports[count.index]
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ghe_key_lookup[0].arn
  }
}

resource "aws_instance" "ghe_key_lookup" {
  count = local.ghe_key_lookup_enabled ? var.ghe_key_lookup_count : 0

  ami                         = data.aws_ami.ghe_key_lookup[0].id
  instance_type               = var.ghe_key_lookup_instance_type
  subnet_id                   = local.ghe_key_lookup_subnet_ids[count.index % length(local.ghe_key_lookup_subnet_ids)]
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.ghe_key_lookup[0].name
  vpc_security_group_ids      = local.ghe_key_lookup_security_group_ids
  user_data                   = var.name_prefix

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.ghe_key_lookup_root_volume_gb
    encrypted             = true
    delete_on_termination = true
    tags = {
      Name = "${var.name_prefix}-ghe-key-lookup-${count.index + 1}-root"
    }
  }

  monitoring = true

  tags = {
    Name = "${var.name_prefix}-ghe-key-lookup-${count.index + 1}"
    Role = "ghe-key-lookup"
  }

  depends_on = [
    null_resource.build_ghe_key_lookup_ami,
    aws_secretsmanager_secret_version.ghe_key_lookup_admin_key,
    aws_secretsmanager_secret_version.ghe_key_lookup_config,
  ]

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_target_group_attachment" "ghe_key_lookup" {
  count = local.ghe_key_lookup_enabled ? var.ghe_key_lookup_count : 0

  target_group_arn = aws_lb_target_group.ghe_key_lookup[0].arn
  target_id        = aws_instance.ghe_key_lookup[count.index].id
  port             = local.ghe_key_lookup_listen_port

  lifecycle {
    create_before_destroy = true
  }
}
