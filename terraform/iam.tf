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
    Statement = [
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
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.bundle.arn,
          "${aws_s3_bucket.bundle.arn}/*",
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:UpdateInstanceInformation",
          "ssmmessages:AcknowledgeMessage",
          "ssmmessages:GetEndpoint",
          "ssmmessages:GetMessages",
          "ec2messages:GetMessages",
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
    ]
  })
}

# ── IAM Role for KeyDB instance ─────────────────────────────────────────────
resource "aws_iam_role" "keydb" {
  name_prefix = "${var.name_prefix}-keydb-"

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
    Name = "${var.name_prefix}-keydb-role"
  }
}

resource "aws_iam_instance_profile" "keydb" {
  name_prefix = "${var.name_prefix}-keydb-"
  role        = aws_iam_role.keydb.name
}

# Allow KeyDB instance to:
# - Read secrets from Secrets Manager (TLS certs)
# - Use SSM Session Manager for access
# - Write CloudWatch logs
resource "aws_iam_role_policy" "keydb" {
  name_prefix = "${var.name_prefix}-keydb-"
  role        = aws_iam_role.keydb.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
        ]
        Resource = "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.name_prefix}/keydb-*"
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
          "ssmmessages:AcknowledgeMessage",
          "ssmmessages:GetEndpoint",
          "ssmmessages:GetMessages",
          "ec2messages:GetMessages",
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
        Resource = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ec2/keydb-*"
      },
    ]
  })
}
