# Get current AWS partition and region information
data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

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
