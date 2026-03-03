# ── Valkey Instance ────────────────────────────────────────────────────────
resource "aws_instance" "valkey" {
  ami                         = data.aws_ami.valkey.id
  instance_type               = var.valkey_instance_type
  subnet_id                   = local.private_subnet_id
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.valkey.name
  vpc_security_group_ids      = [local.valkey_security_group_id]
  user_data                   = <<-EOT
    # SM_PREFIX=${var.name_prefix}
    { ... }: {}
  EOT

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.valkey_root_volume_gb
    encrypted             = true
    delete_on_termination = true
    tags = {
      Name = "${var.name_prefix}-valkey-root"
    }
  }

  monitoring = true

  tags = {
    Name = "${var.name_prefix}-valkey"
    Role = "valkey"
  }

  depends_on = [
    null_resource.build_valkey_ami,
    aws_secretsmanager_secret_version.valkey_auth_token,
  ]

  lifecycle {
    create_before_destroy = true
  }
}

# ── forgeproxy Instances (count) ───────────────────────────────────────────
resource "aws_instance" "forgeproxy" {
  count                       = var.forgeproxy_count
  ami                         = data.aws_ami.forgeproxy.id
  instance_type               = var.forgeproxy_instance_type
  subnet_id                   = local.private_subnet_id
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.forgeproxy.name
  vpc_security_group_ids      = [local.forgeproxy_security_group_id]
  key_name                    = var.ec2_key_pair_name != "" ? var.ec2_key_pair_name : null
  user_data                   = <<-EOT
    # SM_PREFIX=${var.name_prefix}
    { ... }: {}
  EOT

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.forgeproxy_root_volume_gb
    encrypted             = true
    delete_on_termination = true
    tags = {
      Name = "${var.name_prefix}-forgeproxy-${count.index + 1}-root"
    }
  }

  monitoring = true

  tags = {
    Name = "${var.name_prefix}-forgeproxy-${count.index + 1}"
    Role = "forgeproxy"
  }

  depends_on = [
    null_resource.build_forgeproxy_ami,
    aws_instance.valkey,
    aws_secretsmanager_secret_version.forgeproxy_config,
    aws_secretsmanager_secret_version.forge_admin_token,
    aws_secretsmanager_secret_version.valkey_auth_token,
    aws_secretsmanager_secret_version.webhook_secret,
    aws_secretsmanager_secret_version.nginx_upstream_hostname,
    aws_secretsmanager_secret_version.nginx_upstream_port,
    aws_secretsmanager_secret_version.nginx_tls_cert,
    aws_secretsmanager_secret_version.nginx_tls_key,
  ]

  lifecycle {
    create_before_destroy = true
    replace_triggered_by  = [aws_instance.valkey.id]
  }
}

# ── NLB Target Group Attachments: HTTPS ────────────────────────────────────
resource "aws_lb_target_group_attachment" "forgeproxy_https" {
  count            = var.forgeproxy_count
  target_group_arn = aws_lb_target_group.https.arn
  target_id        = aws_instance.forgeproxy[count.index].id
  port             = 443

  lifecycle {
    create_before_destroy = true
  }
}

# ── NLB Target Group Attachments: SSH Git ─────────────────────────────────
resource "aws_lb_target_group_attachment" "forgeproxy_ssh" {
  count            = var.forgeproxy_count
  target_group_arn = aws_lb_target_group.ssh.arn
  target_id        = aws_instance.forgeproxy[count.index].id
  port             = 2222

  lifecycle {
    create_before_destroy = true
  }
}
