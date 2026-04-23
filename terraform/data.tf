# Get current AWS partition and region information
data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

data "external" "forgeproxy_rollout_slot" {
  program = ["bash", "-c", <<-EOT
    set -euo pipefail
    export LB_NAME='${var.name_prefix}-nlb'
    export BLUE_TARGET_GROUP_NAME='${var.name_prefix}-blue-https-tg'
    export GREEN_TARGET_GROUP_NAME='${var.name_prefix}-green-https-tg'
    export AWS_REGION='${var.aws_region}'
    export AWS_PROFILE_FALLBACK='${var.aws_profile}'
    exec bash '${path.module}/scripts/forgeproxy-resolve-slot.sh'
  EOT
  ]
}

locals {
  forgeproxy_current_live_slot = data.external.forgeproxy_rollout_slot.result.current_slot
  forgeproxy_target_slot = (
    var.forgeproxy_active_slot != null
    ? var.forgeproxy_active_slot
    : data.external.forgeproxy_rollout_slot.result.target_slot
  )
}

data "aws_instances" "forgeproxy_blue" {
  instance_state_names = ["pending", "running"]

  filter {
    name   = "tag:aws:autoscaling:groupName"
    values = [aws_autoscaling_group.forgeproxy["blue"].name]
  }

  depends_on = [aws_autoscaling_group.forgeproxy["blue"]]
}

data "aws_instances" "forgeproxy_green" {
  instance_state_names = ["pending", "running"]

  filter {
    name   = "tag:aws:autoscaling:groupName"
    values = [aws_autoscaling_group.forgeproxy["green"].name]
  }

  depends_on = [aws_autoscaling_group.forgeproxy["green"]]
}
