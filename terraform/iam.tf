# ── IAM Role for vmimport (EC2 Image Builder) ───────────────────────────────
resource "aws_iam_role" "vmimport" {
  name_prefix = "${var.name_prefix}-vmimport-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "vmie.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.name_prefix}-vmimport-role"
  }
}

resource "aws_iam_role_policy" "vmimport" {
  name_prefix = "${var.name_prefix}-vmimport-"
  role        = aws_iam_role.vmimport.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
        ]
        Resource = "${aws_s3_bucket.ami_staging.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot",
          "ec2:DescribeSnapshots",
          "ec2:DescribeSnapshotAttribute",
          "ec2:ModifySnapshotAttribute",
          "ec2:CopySnapshot",
          "ec2:RegisterImage",
          "ec2:DescribeImages",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── IAM Role for forgeproxy instances ───────────────────────────────────────
resource "aws_iam_role" "forgeproxy" {
  name_prefix = "${var.name_prefix}-forgeproxy-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.name_prefix}-forgeproxy-role"
  }
}

resource "aws_iam_instance_profile" "forgeproxy" {
  name_prefix = "${var.name_prefix}-forgeproxy-"
  role        = aws_iam_role.forgeproxy.name
}

# Allow forgeproxy instances to:
# - Read secrets from Secrets Manager
# - List/read from S3 bundle bucket
# - Use SSM Session Manager for access
# - Write CloudWatch logs
resource "aws_iam_role_policy" "forgeproxy" {
  name_prefix = "${var.name_prefix}-forgeproxy-"
  role        = aws_iam_role.forgeproxy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Effect = "Allow"
          Action = [
            "secretsmanager:GetSecretValue",
          ]
          Resource = "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.name_prefix}/*"
        },
        {
          Effect   = "Allow"
          Action   = ["secretsmanager:ListSecrets"]
          Resource = "*"
        },
        {
          Effect   = "Allow"
          Action   = ["s3:ListBucket"]
          Resource = aws_s3_bucket.bundle.arn
        },
        {
          Effect = "Allow"
          Action = [
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteObject",
          ]
          Resource = "${aws_s3_bucket.bundle.arn}/*"
        },
        {
          Effect = "Allow"
          Action = [
            "ssm:UpdateInstanceInformation",
            "ssmmessages:CreateControlChannel",
            "ssmmessages:CreateDataChannel",
            "ssmmessages:OpenControlChannel",
            "ssmmessages:OpenDataChannel",
            "ssmmessages:AcknowledgeMessage",
            "ssmmessages:GetEndpoint",
            "ssmmessages:GetMessages",
            "ec2messages:AcknowledgeMessage",
            "ec2messages:DeleteMessage",
            "ec2messages:FailMessage",
            "ec2messages:GetMessages",
            "ec2messages:SendReply",
          ]
          Resource = "*"
        },
        {
          Effect = "Allow"
          Action = [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
          ]
          Resource = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ec2/forgeproxy-*"
        },
      ],
      var.forgeproxy_ssh_host_key_secret_arn == null ? [] : [
        {
          Effect = "Allow"
          Action = [
            "secretsmanager:GetSecretValue",
          ]
          Resource = var.forgeproxy_ssh_host_key_secret_arn
        },
      ],
      var.forgeproxy_ssh_host_key_kms_key_arn == null ? [] : [
        {
          Effect = "Allow"
          Action = [
            "kms:Decrypt",
          ]
          Resource = var.forgeproxy_ssh_host_key_kms_key_arn
        },
      ]
    )
  })
}

# ── IAM Role for Valkey instance ─────────────────────────────────────────────
resource "aws_iam_role" "valkey" {
  name_prefix = "${var.name_prefix}-valkey-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.name_prefix}-valkey-role"
  }
}

resource "aws_iam_instance_profile" "valkey" {
  name_prefix = "${var.name_prefix}-valkey-"
  role        = aws_iam_role.valkey.name
}

# Allow Valkey instance to:
# - Read secrets from Secrets Manager (TLS certs)
# - Use SSM Session Manager for access
# - Write CloudWatch logs
resource "aws_iam_role_policy" "valkey" {
  name_prefix = "${var.name_prefix}-valkey-"
  role        = aws_iam_role.valkey.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
        ]
        Resource = "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.name_prefix}/valkey-*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:ListSecrets"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:UpdateInstanceInformation",
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel",
          "ssmmessages:AcknowledgeMessage",
          "ssmmessages:GetEndpoint",
          "ssmmessages:GetMessages",
          "ec2messages:AcknowledgeMessage",
          "ec2messages:DeleteMessage",
          "ec2messages:FailMessage",
          "ec2messages:GetMessages",
          "ec2messages:SendReply",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ec2/valkey-*"
      },
    ]
  })
}

# ── IAM Role for ghe-key-lookup instances ───────────────────────────────────
resource "aws_iam_role" "ghe_key_lookup" {
  count = local.ghe_key_lookup_enabled ? 1 : 0

  name_prefix = "${var.name_prefix}-ghe-key-lookup-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.name_prefix}-ghe-key-lookup-role"
  }
}

resource "aws_iam_instance_profile" "ghe_key_lookup" {
  count = local.ghe_key_lookup_enabled ? 1 : 0

  name_prefix = "${var.name_prefix}-ghe-key-lookup-"
  role        = aws_iam_role.ghe_key_lookup[0].name
}

resource "aws_iam_role_policy" "ghe_key_lookup" {
  count = local.ghe_key_lookup_enabled ? 1 : 0

  name_prefix = "${var.name_prefix}-ghe-key-lookup-"
  role        = aws_iam_role.ghe_key_lookup[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
        ]
        Resource = "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.name_prefix}/ghe-key-lookup-*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:ListSecrets"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:UpdateInstanceInformation",
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel",
          "ssmmessages:AcknowledgeMessage",
          "ssmmessages:GetEndpoint",
          "ssmmessages:GetMessages",
          "ec2messages:AcknowledgeMessage",
          "ec2messages:DeleteMessage",
          "ec2messages:FailMessage",
          "ec2messages:GetMessages",
          "ec2messages:SendReply",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ec2/ghe-key-lookup-*"
      },
    ]
  })
}
