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

data "external" "forgeproxy_asg_launch_template_versions" {
  program = ["bash", "-c", <<-EOT
    set -euo pipefail
    export BLUE_ASG_NAME='${local.forgeproxy_asg_names.blue}'
    export GREEN_ASG_NAME='${local.forgeproxy_asg_names.green}'
    export AWS_REGION='${var.aws_region}'
    export AWS_PROFILE_FALLBACK='${var.aws_profile}'
    exec bash '${path.module}/scripts/forgeproxy-resolve-asg-launch-templates.sh'
  EOT
  ]
}

locals {
  forgeproxy_asg_names = {
    blue  = "${var.name_prefix}-forgeproxy-blue"
    green = "${var.name_prefix}-forgeproxy-green"
  }
  forgeproxy_current_live_slot = data.external.forgeproxy_rollout_slot.result.current_slot
  forgeproxy_default_live_slot = contains(
    ["blue", "green"],
    local.forgeproxy_current_live_slot
  ) ? local.forgeproxy_current_live_slot : "blue"
  forgeproxy_rollout_slots_needing_update = [
    for slot in ["blue", "green"] : slot
    if(
      data.external.forgeproxy_asg_launch_template_versions.result["${slot}_version"] == ""
      || data.external.forgeproxy_asg_launch_template_versions.result["${slot}_version"] != tostring(aws_launch_template.forgeproxy[slot].latest_version)
    )
  ]
  forgeproxy_auto_target_slot = (
    length(local.forgeproxy_rollout_slots_needing_update) == 0
    ? local.forgeproxy_default_live_slot
    : (
      length(local.forgeproxy_rollout_slots_needing_update) == 1
      ? local.forgeproxy_rollout_slots_needing_update[0]
      : data.external.forgeproxy_rollout_slot.result.target_slot
    )
  )
  forgeproxy_target_slot = (
    var.forgeproxy_active_slot != null
    ? var.forgeproxy_active_slot
    : local.forgeproxy_auto_target_slot
  )
  forgeproxy_current_asg_launch_template_versions = {
    blue  = data.external.forgeproxy_asg_launch_template_versions.result.blue_version
    green = data.external.forgeproxy_asg_launch_template_versions.result.green_version
  }
  forgeproxy_asg_launch_template_versions = {
    for slot in ["blue", "green"] : slot => (
      slot == local.forgeproxy_target_slot
      ? tostring(aws_launch_template.forgeproxy[slot].latest_version)
      : (
        local.forgeproxy_current_asg_launch_template_versions[slot] != ""
        ? local.forgeproxy_current_asg_launch_template_versions[slot]
        : tostring(aws_launch_template.forgeproxy[slot].latest_version)
      )
    )
  }
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
