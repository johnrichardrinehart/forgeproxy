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

locals {
  forgeproxy_slots = toset(["blue", "green"])
}

# ── forgeproxy Launch Template + Blue/Green ASGs ───────────────────────────
resource "aws_launch_template" "forgeproxy" {
  for_each      = local.forgeproxy_slots
  name          = "${var.name_prefix}-forgeproxy-${each.key}"
  image_id      = data.aws_ami.forgeproxy.id
  instance_type = var.forgeproxy_instance_type
  key_name      = var.ec2_key_pair_name != "" ? var.ec2_key_pair_name : null
  user_data = base64encode(<<-EOT
    # SM_PREFIX=${var.name_prefix}
    # FORGEPROXY_SSH_HOST_KEY_SECRET_ARN=${var.forgeproxy_ssh_host_key_secret_arn != null ? var.forgeproxy_ssh_host_key_secret_arn : ""}
    # FORGEPROXY_DEPLOYMENT_SLOT=${each.key}
    # FORGEPROXY_CACHE_EBS_ENABLED=${var.forgeproxy_cache_volume_enabled ? "true" : "false"}
    # FORGEPROXY_CACHE_VOLUME_GB=${var.forgeproxy_cache_volume_gb}
    # FORGEPROXY_CACHE_VOLUME_TYPE=${var.forgeproxy_cache_volume_type}
    # FORGEPROXY_CACHE_VOLUME_IOPS=${var.forgeproxy_cache_volume_iops}
    # FORGEPROXY_CACHE_VOLUME_THROUGHPUT_MBPS=${var.forgeproxy_cache_volume_throughput_mbps}
    # FORGEPROXY_CACHE_VOLUME_DEVICE_NAME=${var.forgeproxy_cache_volume_device_name}
    # FORGEPROXY_CACHE_VOLUME_FS_TYPE=${var.forgeproxy_cache_volume_fs_type}
    # FORGEPROXY_CACHE_VOLUME_LABEL=${var.forgeproxy_cache_volume_label}
    # FORGEPROXY_CACHE_MOUNT_DIR=/var/cache/forgeproxy
    # FORGEPROXY_CACHE_MOUNT_OPTIONS=${var.forgeproxy_cache_volume_mount_options}
    { ... }: {}
  EOT
  )
  vpc_security_group_ids = [local.forgeproxy_security_group_id]
  update_default_version = true

  iam_instance_profile {
    name = aws_iam_instance_profile.forgeproxy.name
  }

  block_device_mappings {
    device_name = data.aws_ami.forgeproxy.root_device_name

    ebs {
      volume_type           = "gp3"
      volume_size           = var.forgeproxy_root_volume_gb
      iops                  = var.forgeproxy_root_volume_iops
      throughput            = var.forgeproxy_root_volume_throughput_mbps
      encrypted             = true
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name           = "${var.name_prefix}-forgeproxy-${each.key}"
      Role           = "forgeproxy"
      DeploymentSlot = each.key
      CacheEbs       = var.forgeproxy_cache_volume_enabled ? "enabled" : "disabled"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Name           = "${var.name_prefix}-forgeproxy-${each.key}-root"
      Role           = "forgeproxy"
      DeploymentSlot = each.key
      CacheEbs       = var.forgeproxy_cache_volume_enabled ? "enabled" : "disabled"
    }
  }

  tags = {
    Name           = "${var.name_prefix}-forgeproxy-${each.key}"
    Role           = "forgeproxy"
    DeploymentSlot = each.key
    CacheEbs       = var.forgeproxy_cache_volume_enabled ? "enabled" : "disabled"
  }

  depends_on = [
    null_resource.build_forgeproxy_ami,
    aws_instance.valkey,
    aws_secretsmanager_secret_version.forgeproxy_config,
    aws_secretsmanager_secret_version.forgeproxy_otel_collector_config,
    aws_secretsmanager_secret_version.forge_admin_token,
    aws_secretsmanager_secret_version.valkey_auth_token,
    aws_secretsmanager_secret_version.webhook_secret,
    aws_secretsmanager_secret_version.nginx_upstream_hostname,
    aws_secretsmanager_secret_version.nginx_upstream_port,
    aws_secretsmanager_secret_version.nginx_upstream_ssh_port,
    aws_secretsmanager_secret_version.nginx_tls_cert,
    aws_secretsmanager_secret_version.nginx_tls_key,
  ]
}

resource "aws_autoscaling_group" "forgeproxy" {
  for_each = local.forgeproxy_slots

  name                      = "${var.name_prefix}-forgeproxy-${each.key}"
  min_size                  = 0
  desired_capacity          = 0
  max_size                  = local.forgeproxy_max_count
  health_check_type         = "ELB"
  health_check_grace_period = var.forgeproxy_health_check_grace_period_secs
  wait_for_elb_capacity     = 0
  wait_for_capacity_timeout = "0"
  vpc_zone_identifier       = [local.private_subnet_id]
  target_group_arns = [
    aws_lb_target_group.https[each.key].arn,
    aws_lb_target_group.ssh[each.key].arn,
  ]
  termination_policies = ["OldestLaunchTemplate", "OldestInstance"]

  launch_template {
    id      = aws_launch_template.forgeproxy[each.key].id
    version = aws_launch_template.forgeproxy[each.key].latest_version
  }

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-forgeproxy-${each.key}"
    propagate_at_launch = true
  }

  tag {
    key                 = "Role"
    value               = "forgeproxy"
    propagate_at_launch = true
  }

  tag {
    key                 = "DeploymentSlot"
    value               = each.key
    propagate_at_launch = true
  }

  tag {
    key                 = "forgeproxy-valkey-instance-id"
    value               = aws_instance.valkey.id
    propagate_at_launch = true
  }

  lifecycle {
    ignore_changes = [
      desired_capacity,
      min_size,
    ]
  }
}

resource "null_resource" "forgeproxy_rollout_prepare" {
  triggers = {
    active_slot                  = local.forgeproxy_target_slot
    desired_count                = tostring(var.forgeproxy_count)
    max_count                    = tostring(local.forgeproxy_max_count)
    blue_asg_name                = aws_autoscaling_group.forgeproxy["blue"].name
    green_asg_name               = aws_autoscaling_group.forgeproxy["green"].name
    active_https_target_group    = aws_lb_target_group.https[local.forgeproxy_target_slot].arn
    active_ssh_target_group      = aws_lb_target_group.ssh[local.forgeproxy_target_slot].arn
    blue_launch_template_version = tostring(aws_launch_template.forgeproxy["blue"].latest_version)
    green_launch_template_version = tostring(
      aws_launch_template.forgeproxy["green"].latest_version
    )
    valkey_instance_id            = aws_instance.valkey.id
    cache_volume_enabled          = tostring(var.forgeproxy_cache_volume_enabled)
    cache_volume_gb               = tostring(var.forgeproxy_cache_volume_gb)
    cache_volume_type             = var.forgeproxy_cache_volume_type
    cache_volume_iops             = tostring(var.forgeproxy_cache_volume_iops)
    cache_volume_throughput_mbps  = tostring(var.forgeproxy_cache_volume_throughput_mbps)
    cache_seed_wait_for_snapshots = tostring(var.forgeproxy_cache_seed_wait_for_snapshots)
  }

  depends_on = [
    aws_autoscaling_group.forgeproxy,
    aws_lb_target_group.https,
    aws_lb_target_group.ssh,
  ]

  provisioner "local-exec" {
    command = "${path.module}/scripts/forgeproxy-rollout-prepare.sh"
    environment = {
      AWS_REGION                   = var.aws_region
      AWS_PROFILE_FALLBACK         = var.aws_profile
      ACTIVE_SLOT                  = local.forgeproxy_target_slot
      CURRENT_LIVE_SLOT            = local.forgeproxy_current_live_slot
      DESIRED_COUNT                = tostring(var.forgeproxy_count)
      MAX_COUNT                    = tostring(local.forgeproxy_max_count)
      BLUE_ASG_NAME                = aws_autoscaling_group.forgeproxy["blue"].name
      GREEN_ASG_NAME               = aws_autoscaling_group.forgeproxy["green"].name
      ACTIVE_HTTPS_TARGET_ARN      = aws_lb_target_group.https[local.forgeproxy_target_slot].arn
      ACTIVE_SSH_TARGET_ARN        = aws_lb_target_group.ssh[local.forgeproxy_target_slot].arn
      BLUE_HTTPS_TARGET_ARN        = aws_lb_target_group.https["blue"].arn
      GREEN_HTTPS_TARGET_ARN       = aws_lb_target_group.https["green"].arn
      NLB_ARN                      = aws_lb.nlb.arn
      NAME_PREFIX                  = var.name_prefix
      CACHE_EBS_ENABLED            = tostring(var.forgeproxy_cache_volume_enabled)
      CACHE_VOLUME_GB              = tostring(var.forgeproxy_cache_volume_gb)
      CACHE_VOLUME_TYPE            = var.forgeproxy_cache_volume_type
      CACHE_VOLUME_IOPS            = tostring(var.forgeproxy_cache_volume_iops)
      CACHE_VOLUME_THROUGHPUT_MBPS = tostring(var.forgeproxy_cache_volume_throughput_mbps)
      CACHE_SEED_WAIT_FOR_SNAPSHOTS = tostring(
        var.forgeproxy_cache_seed_wait_for_snapshots
      )
      BLUE_LAUNCH_TEMPLATE_VERSION = tostring(aws_launch_template.forgeproxy["blue"].latest_version)
      GREEN_LAUNCH_TEMPLATE_VERSION = tostring(
        aws_launch_template.forgeproxy["green"].latest_version
      )
    }
    interpreter = ["/usr/bin/env", "bash"]
  }
}

resource "null_resource" "forgeproxy_rollout_cleanup" {
  triggers = {
    active_slot                  = local.forgeproxy_target_slot
    desired_count                = tostring(var.forgeproxy_count)
    blue_asg_name                = aws_autoscaling_group.forgeproxy["blue"].name
    green_asg_name               = aws_autoscaling_group.forgeproxy["green"].name
    blue_launch_template_version = tostring(aws_launch_template.forgeproxy["blue"].latest_version)
    green_launch_template_version = tostring(
      aws_launch_template.forgeproxy["green"].latest_version
    )
    listener_https_arn                  = aws_lb_listener.https.arn
    listener_ssh_arn                    = aws_lb_listener.ssh.arn
    nlb_dns_name                        = aws_lb.nlb.dns_name
    client_facing_hostnames             = join(",", local.configured_proxy_hostnames)
    cutover_check_interval_secs         = tostring(var.forgeproxy_cutover_check_interval_secs)
    cutover_required_consecutive_checks = tostring(var.forgeproxy_cutover_required_consecutive_successes)
    cutover_timeout_secs                = tostring(var.forgeproxy_cutover_timeout_secs)
  }

  depends_on = [
    null_resource.forgeproxy_rollout_prepare,
    aws_lb_listener.https,
    aws_lb_listener.ssh,
  ]

  provisioner "local-exec" {
    command = "${path.module}/scripts/forgeproxy-rollout-cleanup.sh"
    environment = {
      AWS_REGION                             = var.aws_region
      AWS_PROFILE_FALLBACK                   = var.aws_profile
      ACTIVE_SLOT                            = local.forgeproxy_target_slot
      BLUE_ASG_NAME                          = aws_autoscaling_group.forgeproxy["blue"].name
      GREEN_ASG_NAME                         = aws_autoscaling_group.forgeproxy["green"].name
      NLB_DNS_NAME                           = aws_lb.nlb.dns_name
      CLIENT_FACING_HOSTNAMES                = join(",", local.configured_proxy_hostnames)
      CUTOVER_CHECK_INTERVAL_SECONDS         = tostring(var.forgeproxy_cutover_check_interval_secs)
      CUTOVER_REQUIRED_CONSECUTIVE_SUCCESSES = tostring(var.forgeproxy_cutover_required_consecutive_successes)
      CUTOVER_TIMEOUT_SECONDS                = tostring(var.forgeproxy_cutover_timeout_secs)
    }
    interpreter = ["/usr/bin/env", "bash"]
  }
}
