# ── Locals ──────────────────────────────────────────────────────────────────
locals {
  # When vpc_id is null the module creates all networking resources.
  # When vpc_id is provided the module reuses the caller's VPC and subnets.
  create_network    = var.vpc_id == null
  vpc_id            = local.create_network ? aws_vpc.main[0].id : var.vpc_id
  private_subnet_id = local.create_network ? aws_subnet.private[0].id : var.private_subnet_id
  # public_subnet_id is optional when bringing your own VPC and the NLB is
  # internal: an internal NLB can live in the private subnet. When
  # nlb_internal = false a public subnet is required and must be supplied.
  public_subnet_id = local.create_network ? aws_subnet.public[0].id : (
    var.public_subnet_id != null ? var.public_subnet_id : var.private_subnet_id
  )

  # When forgeproxy_security_group_id is null the module creates both security
  # groups. Both must be provided together (or neither) because the keydb SG
  # rule references the forgeproxy SG – that relationship is the caller's
  # responsibility when bringing their own SGs.
  create_security_groups       = var.forgeproxy_security_group_id == null
  forgeproxy_security_group_id = local.create_security_groups ? aws_security_group.forgeproxy[0].id : var.forgeproxy_security_group_id
  keydb_security_group_id      = local.create_security_groups ? aws_security_group.keydb[0].id : var.keydb_security_group_id
}

# Validate that forgeproxy_security_group_id and keydb_security_group_id are
# either both set or both null.
check "sg_inputs_consistent" {
  assert {
    condition     = (var.forgeproxy_security_group_id == null) == (var.keydb_security_group_id == null)
    error_message = "forgeproxy_security_group_id and keydb_security_group_id must both be set (bring-your-own SGs) or both be null (module creates security groups)."
  }
}

# When bringing your own VPC, private_subnet_id is always required.
check "private_subnet_required" {
  assert {
    condition     = var.vpc_id == null || var.private_subnet_id != null
    error_message = "private_subnet_id must be set when vpc_id is provided."
  }
}

# A public subnet is only required when the NLB is internet-facing; an
# internal NLB can be placed in the private subnet.
check "public_subnet_required_for_external_nlb" {
  assert {
    condition     = var.nlb_internal || local.create_network || var.public_subnet_id != null
    error_message = "public_subnet_id must be set when vpc_id is provided and nlb_internal is false."
  }
}

# ── VPC ────────────────────────────────────────────────────────────────────
resource "aws_vpc" "main" {
  count                = local.create_network ? 1 : 0
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

# ── Internet Gateway ────────────────────────────────────────────────────────
resource "aws_internet_gateway" "main" {
  count  = local.create_network ? 1 : 0
  vpc_id = aws_vpc.main[0].id

  tags = {
    Name = "${var.name_prefix}-igw"
  }
}

# ── Public Subnet (for NLB) ─────────────────────────────────────────────────
resource "aws_subnet" "public" {
  count             = local.create_network ? 1 : 0
  vpc_id            = aws_vpc.main[0].id
  cidr_block        = var.public_subnet_cidr
  availability_zone = data.aws_region.current.name

  tags = {
    Name = "${var.name_prefix}-public-subnet"
    Tier = "public"
  }
}

# ── Private Subnet (for instances) ──────────────────────────────────────────
resource "aws_subnet" "private" {
  count             = local.create_network ? 1 : 0
  vpc_id            = aws_vpc.main[0].id
  cidr_block        = var.private_subnet_cidr
  availability_zone = data.aws_region.current.name

  tags = {
    Name = "${var.name_prefix}-private-subnet"
    Tier = "private"
  }
}

# ── Elastic IP for NAT Gateway ──────────────────────────────────────────────
resource "aws_eip" "nat" {
  count  = local.create_network ? 1 : 0
  domain = "vpc"

  tags = {
    Name = "${var.name_prefix}-nat-eip"
  }

  depends_on = [aws_internet_gateway.main]
}

# ── NAT Gateway (for private subnet egress) ─────────────────────────────────
resource "aws_nat_gateway" "main" {
  count         = local.create_network ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${var.name_prefix}-nat-gateway"
  }

  depends_on = [aws_internet_gateway.main]
}

# ── Public Route Table ──────────────────────────────────────────────────────
resource "aws_route_table" "public" {
  count  = local.create_network ? 1 : 0
  vpc_id = aws_vpc.main[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main[0].id
  }

  tags = {
    Name = "${var.name_prefix}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = local.create_network ? 1 : 0
  subnet_id      = aws_subnet.public[0].id
  route_table_id = aws_route_table.public[0].id
}

# ── Private Route Table ─────────────────────────────────────────────────────
resource "aws_route_table" "private" {
  count  = local.create_network ? 1 : 0
  vpc_id = aws_vpc.main[0].id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[0].id
  }

  tags = {
    Name = "${var.name_prefix}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  count          = local.create_network ? 1 : 0
  subnet_id      = aws_subnet.private[0].id
  route_table_id = aws_route_table.private[0].id
}

# ── Security Group: forgeproxy instances ────────────────────────────────────
resource "aws_security_group" "forgeproxy" {
  count       = local.create_security_groups ? 1 : 0
  name        = "${var.name_prefix}-forgeproxy-sg"
  description = "Security group for forgeproxy instances"
  vpc_id      = local.vpc_id

  # HTTPS from allowed clients
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_client_cidrs
    description = "HTTPS from allowed clients"
  }

  # SSH Git protocol (port 2222) from allowed clients
  ingress {
    from_port   = 2222
    to_port     = 2222
    protocol    = "tcp"
    cidr_blocks = var.allowed_client_cidrs
    description = "SSH Git protocol from allowed clients"
  }

  # Prometheus metrics from allowed scrapers
  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = var.metrics_scrape_cidrs
    description = "Prometheus metrics from allowed scrapers"
  }

  # All outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
  }

  tags = {
    Name = "${var.name_prefix}-forgeproxy-sg"
  }
}

# ── Security Group: KeyDB instance ──────────────────────────────────────────
resource "aws_security_group" "keydb" {
  count       = local.create_security_groups ? 1 : 0
  name        = "${var.name_prefix}-keydb-sg"
  description = "Security group for KeyDB instance"
  vpc_id      = local.vpc_id

  # KeyDB TLS port from forgeproxy instances
  ingress {
    from_port       = 6380
    to_port         = 6380
    protocol        = "tcp"
    security_groups = [aws_security_group.forgeproxy[0].id]
    description     = "KeyDB TLS port from forgeproxy instances"
  }

  # KeyDB plaintext port from forgeproxy instances (for development/testing)
  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.forgeproxy[0].id]
    description     = "KeyDB plaintext port from forgeproxy instances"
  }

  # All outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
  }

  tags = {
    Name = "${var.name_prefix}-keydb-sg"
  }
}

# ── Elastic IP for NLB (optional, only if internet-facing) ──────────────────
resource "aws_eip" "nlb" {
  count  = var.nlb_internal ? 0 : 1
  domain = "vpc"

  tags = {
    Name = "${var.name_prefix}-nlb-eip"
  }

  depends_on = [aws_internet_gateway.main]
}

# ── Network Load Balancer ──────────────────────────────────────────────────
resource "aws_lb" "nlb" {
  name                       = "${var.name_prefix}-nlb"
  internal                   = var.nlb_internal
  load_balancer_type         = "network"
  subnets                    = [local.public_subnet_id]
  enable_deletion_protection = false

  # Use the EIP only if NLB is internet-facing
  dynamic "subnet_mapping" {
    for_each = var.nlb_internal ? [] : [1]
    content {
      subnet_id     = local.public_subnet_id
      allocation_id = aws_eip.nlb[0].id
    }
  }

  tags = {
    Name = "${var.name_prefix}-nlb"
  }

  lifecycle {
    precondition {
      condition     = local.public_subnet_id != null
      error_message = "Could not determine a subnet for the NLB. When vpc_id is set, private_subnet_id is required (it doubles as the NLB subnet for internal deployments). For internet-facing deployments also set public_subnet_id."
    }
  }
}

# ── Target Group: HTTPS (port 443) ──────────────────────────────────────────
resource "aws_lb_target_group" "https" {
  name        = "${var.name_prefix}-https-tg"
  port        = 443
  protocol    = "TCP"
  vpc_id      = local.vpc_id
  target_type = "instance"

  health_check {
    enabled             = true
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 10
    interval            = 30
    port                = "443"
    protocol            = "HTTPS"
    path                = "/healthz"
    matcher             = "200-299"
  }

  tags = {
    Name = "${var.name_prefix}-https-tg"
  }
}

# ── Target Group: SSH Git (port 2222) ───────────────────────────────────────
resource "aws_lb_target_group" "ssh" {
  name        = "${var.name_prefix}-ssh-tg"
  port        = 2222
  protocol    = "TCP"
  vpc_id      = local.vpc_id
  target_type = "instance"

  health_check {
    enabled             = true
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 10
    interval            = 30
    port                = "443"
    protocol            = "HTTPS"
    path                = "/healthz"
    matcher             = "200-299"
  }

  tags = {
    Name = "${var.name_prefix}-ssh-tg"
  }
}

# ── Listener: HTTPS (port 443) ──────────────────────────────────────────────
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.nlb.arn
  port              = 443
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.https.arn
  }
}

# ── Listener: SSH Git (port 2222) ──────────────────────────────────────────
resource "aws_lb_listener" "ssh" {
  load_balancer_arn = aws_lb.nlb.arn
  port              = 2222
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ssh.arn
  }
}
