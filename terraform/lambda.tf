# ── Lambda Health Decoupler ────────────────────────────────────────────────
locals {
  asg_health_check_lambda_name = "${var.name_prefix}-hc"
  asg_health_check_schedule_expression = (
    var.asg_health_check_lambda_interval_minutes == 1
    ? "rate(1 minute)"
    : "rate(${var.asg_health_check_lambda_interval_minutes} minutes)"
  )
}

resource "aws_dynamodb_table" "forgeproxy_health_check_state" {
  name         = "${var.name_prefix}-forgeproxy-health-check-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "instance_id"

  attribute {
    name = "instance_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Name = "${var.name_prefix}-forgeproxy-health-check-state"
  }
}

resource "aws_cloudwatch_log_group" "forgeproxy_health_check" {
  name              = "/aws/lambda/${local.asg_health_check_lambda_name}"
  retention_in_days = 14

  tags = {
    Name = local.asg_health_check_lambda_name
  }
}

resource "aws_iam_role" "forgeproxy_health_check_lambda" {
  name_prefix = "${var.name_prefix}-hc-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.name_prefix}-hc-role"
  }
}

resource "aws_iam_role_policy" "forgeproxy_health_check_lambda" {
  name_prefix = "${var.name_prefix}-hc-"
  role        = aws_iam_role.forgeproxy_health_check_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:DescribeTargetHealth",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingInstances",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:AssignPrivateIpAddresses",
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:UnassignPrivateIpAddresses",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "autoscaling:SetInstanceHealth",
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:autoscaling:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:autoScalingGroup:*:autoScalingGroupName/${var.name_prefix}-forgeproxy-*",
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:DeleteItem",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
        ]
        Resource = aws_dynamodb_table.forgeproxy_health_check_state.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.forgeproxy_health_check.arn}:*"
      }
    ]
  })
}

data "archive_file" "forgeproxy_health_check_lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/health_check.py"
  output_path = "${path.module}/lambda/health_check.zip"
}

resource "aws_lambda_function" "forgeproxy_health_check" {
  function_name    = local.asg_health_check_lambda_name
  role             = aws_iam_role.forgeproxy_health_check_lambda.arn
  handler          = "health_check.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.forgeproxy_health_check_lambda.output_path
  source_code_hash = data.archive_file.forgeproxy_health_check_lambda.output_base64sha256
  timeout          = 30

  vpc_config {
    subnet_ids         = [local.private_subnet_id]
    security_group_ids = [aws_security_group.forgeproxy_health_check_lambda.id]
  }

  environment {
    variables = {
      ASG_NAME_PREFIX           = "${var.name_prefix}-forgeproxy-"
      HEALTH_CHECK_STATE_TABLE  = aws_dynamodb_table.forgeproxy_health_check_state.name
      OBSERVATION_INTERVAL_SECS = tostring(var.asg_health_check_lambda_interval_minutes * 60)
      READYZ_HOST               = local.default_proxy_hostname
      READYZ_TIMEOUT_SECS       = tostring(var.health_check_timeout_secs)
      TARGET_GROUP_ARNS = jsonencode({
        https = aws_lb_target_group.https[local.forgeproxy_target_slot].arn
        ssh   = aws_lb_target_group.ssh[local.forgeproxy_target_slot].arn
      })
      TARGET_INSTANCE_PRIVATE_IPS = jsonencode(zipmap(
        local.forgeproxy_target_slot == "blue" ? data.aws_instances.forgeproxy_blue.ids : data.aws_instances.forgeproxy_green.ids,
        local.forgeproxy_target_slot == "blue" ? data.aws_instances.forgeproxy_blue.private_ips : data.aws_instances.forgeproxy_green.private_ips,
      ))
      TERMINATION_THRESHOLD = tostring(var.asg_unhealthy_termination_threshold)
    }
  }

  tags = {
    Name = local.asg_health_check_lambda_name
  }

  depends_on = [
    aws_cloudwatch_log_group.forgeproxy_health_check,
    aws_iam_role_policy.forgeproxy_health_check_lambda,
  ]
}

resource "aws_cloudwatch_event_rule" "forgeproxy_health_check_lambda" {
  name                = local.asg_health_check_lambda_name
  description         = "Observe active forgeproxy target health and mark persistently unhealthy ASG instances for replacement."
  schedule_expression = local.asg_health_check_schedule_expression

  tags = {
    Name = local.asg_health_check_lambda_name
  }
}

resource "aws_cloudwatch_event_target" "forgeproxy_health_check_lambda" {
  rule      = aws_cloudwatch_event_rule.forgeproxy_health_check_lambda.name
  target_id = "forgeproxy-health-check"
  arn       = aws_lambda_function.forgeproxy_health_check.arn
}

resource "aws_lambda_permission" "forgeproxy_health_check_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.forgeproxy_health_check.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.forgeproxy_health_check_lambda.arn
}
