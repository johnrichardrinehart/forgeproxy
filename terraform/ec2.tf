# ── KeyDB Instance ────────────────────────────────────────────────────────
resource "aws_instance" "keydb" {
  ami                         = data.aws_ami.keydb.id
  instance_type               = var.keydb_instance_type
  subnet_id                   = local.private_subnet_id
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.keydb.name
  vpc_security_group_ids      = [local.keydb_security_group_id]

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.keydb_root_volume_gb
    encrypted             = true
    delete_on_termination = true
    tags = {
      Name = "${var.name_prefix}-keydb-root"
    }
  }

  monitoring = true

  tags = {
    Name = "${var.name_prefix}-keydb"
    Role = "keydb"
  }

  depends_on = [
    null_resource.build_keydb_ami,
    aws_secretsmanager_secret_version.keydb_auth_token,
  ]
}

# ── forgeproxy Instances (count) ───────────────────────────────────────────
resource "aws_instance" "forgeproxy" {
  count                       = var.forgeproxy_count
  ami                         = data.aws_ami.forgecache.id
  instance_type               = var.forgeproxy_instance_type
  subnet_id                   = local.private_subnet_id
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.forgeproxy.name
  vpc_security_group_ids      = [local.forgeproxy_security_group_id]
  key_name                    = var.ec2_key_pair_name != "" ? var.ec2_key_pair_name : null

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
    null_resource.build_forgecache_ami,
    aws_instance.keydb,
    aws_secretsmanager_secret_version.forgecache_config,
    aws_secretsmanager_secret_version.forge_admin_token,
    aws_secretsmanager_secret_version.keydb_auth_token,
    aws_secretsmanager_secret_version.webhook_secret,
    aws_secretsmanager_secret_version.nginx_upstream_hostname,
    aws_secretsmanager_secret_version.nginx_upstream_port,
    aws_secretsmanager_secret_version.nginx_tls_cert,
    aws_secretsmanager_secret_version.nginx_tls_key,
  ]
}

# ── NLB Target Group Attachments: HTTPS ────────────────────────────────────
resource "aws_lb_target_group_attachment" "forgeproxy_https" {
  count            = var.forgeproxy_count
  target_group_arn = aws_lb_target_group.https.arn
  target_id        = aws_instance.forgeproxy[count.index].id
  port             = 443
}

# ── NLB Target Group Attachments: SSH Git ─────────────────────────────────
resource "aws_lb_target_group_attachment" "forgeproxy_ssh" {
  count            = var.forgeproxy_count
  target_group_arn = aws_lb_target_group.ssh.arn
  target_id        = aws_instance.forgeproxy[count.index].id
  port             = 2222
}
