# ── S3 Bucket: AMI Staging ──────────────────────────────────────────────────
# Used to upload the NixOS AMI before importing into EC2
resource "aws_s3_bucket" "ami_staging" {
  bucket_prefix = "${var.name_prefix}-ami-staging-"

  tags = {
    Name = "${var.name_prefix}-ami-staging"
  }
}

resource "aws_s3_bucket_versioning" "ami_staging" {
  bucket = aws_s3_bucket.ami_staging.id

  versioning_configuration {
    status = "Disabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ami_staging" {
  bucket = aws_s3_bucket.ami_staging.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "ami_staging" {
  bucket = aws_s3_bucket.ami_staging.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "ami_staging" {
  bucket = aws_s3_bucket.ami_staging.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.vmimport.arn
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.ami_staging.arn,
          "${aws_s3_bucket.ami_staging.arn}/*"
        ]
      }
    ]
  })
}

# Lifecycle rule: delete old AMI uploads after 30 days
resource "aws_s3_bucket_lifecycle_configuration" "ami_staging" {
  bucket = aws_s3_bucket.ami_staging.id

  rule {
    id     = "delete-old-amis"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }
  }
}

# ── S3 Bucket: Bundle Storage ──────────────────────────────────────────────
# Long-term storage for git bundle archives
resource "aws_s3_bucket" "bundle" {
  bucket = var.bundle_bucket_name

  tags = {
    Name = var.bundle_bucket_name
  }
}

resource "aws_s3_bucket_versioning" "bundle" {
  bucket = aws_s3_bucket.bundle.id

  versioning_configuration {
    status = "Suspended"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bundle" {
  bucket = aws_s3_bucket.bundle.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "bundle" {
  bucket = aws_s3_bucket.bundle.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle rule: transition to GLACIER after 90 days for cost optimization
resource "aws_s3_bucket_lifecycle_configuration" "bundle" {
  bucket = aws_s3_bucket.bundle.id

  rule {
    id     = "archive-bundles"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}
