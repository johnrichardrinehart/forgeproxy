# ── Map closure_variant to nixosConfiguration names ───────────────────────────
locals {
  forgecache_config = var.closure_variant == "dev" ? "forgecache-dev" : "forgecache"
  keydb_config      = var.closure_variant == "dev" ? "keydb-dev" : "keydb"
  variant_suffix    = var.closure_variant == "dev" ? "-dev" : ""
}

# ── Evaluate Nix outPaths at plan time (fast, no build) ──────────────────────
data "external" "forgecache_image_hash" {
  program = ["bash", "-c", <<-EOT
    OUTPATH=$(nix eval --tarball-ttl 0 --raw '${var.flake_ref}#nixosConfigurations.${local.forgecache_config}.config.system.build.images.amazon.outPath')
    HASH=$(basename "$OUTPATH" | cut -d- -f1)
    printf '{"hash":"%s"}\n' "$HASH"
  EOT
  ]
}

data "external" "keydb_image_hash" {
  program = ["bash", "-c", <<-EOT
    OUTPATH=$(nix eval --tarball-ttl 0 --raw '${var.flake_ref}#nixosConfigurations.${local.keydb_config}.config.system.build.images.amazon.outPath')
    HASH=$(basename "$OUTPATH" | cut -d- -f1)
    printf '{"hash":"%s"}\n' "$HASH"
  EOT
  ]
}

# ── Build forgecache AMI ──────────────────────────────────────────────────
resource "null_resource" "build_forgecache_ami" {
  triggers = {
    image_hash = data.external.forgecache_image_hash.result.hash
  }

  provisioner "local-exec" {
    command = <<-EOT
      set -euo pipefail

      HASH="${data.external.forgecache_image_hash.result.hash}"
      AMI_NAME="${var.name_prefix}-forgecache${local.variant_suffix}-$HASH"
      S3_KEY="forgecache${local.variant_suffix}-$HASH.vhd"

      # If an AMI with this hash already exists, nothing to do
      EXISTING_AMI=$(aws ec2 describe-images \
        --owners self \
        --filters "Name=name,Values=$AMI_NAME" \
        --query 'Images[0].ImageId' --output text \
        --region "${var.aws_region}")
      if [ "$EXISTING_AMI" != "None" ]; then
        exit 0
      fi

      # Build the NixOS image (only reached when AMI doesn't exist yet)
      nix build --tarball-ttl 0 '${var.flake_ref}#nixosConfigurations.${local.forgecache_config}.config.system.build.images.amazon'

      # Upload only if this exact image isn't already in the bucket
      if ! aws s3api head-object --bucket "${aws_s3_bucket.ami_staging.id}" --key "$S3_KEY" 2>/dev/null; then
        OUT_PATH=$(readlink -f result)
        aws s3 cp "$OUT_PATH"/*.vhd \
          "s3://${aws_s3_bucket.ami_staging.id}/$S3_KEY"
      fi

      # Import snapshot from S3
      SNAPSHOT_ID=$(aws ec2 import-snapshot \
        --description "forgecache NixOS image ($HASH)" \
        --disk-container "Format=VHD,UserBucket={S3Bucket=${aws_s3_bucket.ami_staging.id},S3Key=$S3_KEY}" \
        --role-name "${aws_iam_role.vmimport.name}" \
        --region "${var.aws_region}" \
        --query 'ImportTaskId' --output text)

      # Poll for completion
      while true; do
        STATUS=$(aws ec2 describe-import-snapshot-tasks \
          --import-task-ids $SNAPSHOT_ID \
          --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.Status' \
          --output text)
        if [ "$STATUS" = "completed" ]; then
          break
        elif [ "$STATUS" = "failed" ]; then
          exit 1
        fi
        sleep 10
      done

      # Get snapshot ID
      SNAP_ID=$(aws ec2 describe-import-snapshot-tasks \
        --import-task-ids $SNAPSHOT_ID \
        --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.SnapshotId' \
        --output text)

      # Register AMI
      aws ec2 register-image \
        --name "$AMI_NAME" \
        --description "forgecache NixOS AMI (Terraform-managed)" \
        --architecture x86_64 \
        --root-device-name /dev/xvda \
        --virtualization-type hvm \
        --ena-support \
        --block-device-mappings \
          "DeviceName=/dev/xvda,Ebs={SnapshotId=$SNAP_ID,VolumeSize=${var.forgeproxy_root_volume_gb},VolumeType=gp3,DeleteOnTermination=true}" \
        --query 'ImageId' --output text
    EOT
  }

  depends_on = [
    aws_s3_bucket.ami_staging,
    aws_iam_role.vmimport,
    aws_iam_role_policy.vmimport,
  ]
}

# Look up the forgecache AMI by its deterministic name
data "aws_ami" "forgecache" {
  most_recent = true
  owners      = ["self"]

  filter {
    name   = "name"
    values = ["${var.name_prefix}-forgecache${local.variant_suffix}-${data.external.forgecache_image_hash.result.hash}"]
  }

  depends_on = [null_resource.build_forgecache_ami]
}

# ── Build keydb AMI ────────────────────────────────────────────────────────
resource "null_resource" "build_keydb_ami" {
  triggers = {
    image_hash = data.external.keydb_image_hash.result.hash
  }

  provisioner "local-exec" {
    command = <<-EOT
      set -euo pipefail

      HASH="${data.external.keydb_image_hash.result.hash}"
      AMI_NAME="${var.name_prefix}-keydb${local.variant_suffix}-$HASH"
      S3_KEY="keydb${local.variant_suffix}-$HASH.vhd"

      # If an AMI with this hash already exists, nothing to do
      EXISTING_AMI=$(aws ec2 describe-images \
        --owners self \
        --filters "Name=name,Values=$AMI_NAME" \
        --query 'Images[0].ImageId' --output text \
        --region "${var.aws_region}")
      if [ "$EXISTING_AMI" != "None" ]; then
        exit 0
      fi

      # Build the NixOS image (only reached when AMI doesn't exist yet)
      nix build --tarball-ttl 0 '${var.flake_ref}#nixosConfigurations.${local.keydb_config}.config.system.build.images.amazon'

      # Upload only if this exact image isn't already in the bucket
      if ! aws s3api head-object --bucket "${aws_s3_bucket.ami_staging.id}" --key "$S3_KEY" 2>/dev/null; then
        OUT_PATH=$(readlink -f result)
        aws s3 cp "$OUT_PATH"/*.vhd \
          "s3://${aws_s3_bucket.ami_staging.id}/$S3_KEY"
      fi

      # Import snapshot from S3
      SNAPSHOT_ID=$(aws ec2 import-snapshot \
        --description "keydb NixOS image ($HASH)" \
        --disk-container "Format=VHD,UserBucket={S3Bucket=${aws_s3_bucket.ami_staging.id},S3Key=$S3_KEY}" \
        --role-name "${aws_iam_role.vmimport.name}" \
        --region "${var.aws_region}" \
        --query 'ImportTaskId' --output text)

      # Poll for completion
      while true; do
        STATUS=$(aws ec2 describe-import-snapshot-tasks \
          --import-task-ids $SNAPSHOT_ID \
          --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.Status' \
          --output text)
        if [ "$STATUS" = "completed" ]; then
          break
        elif [ "$STATUS" = "failed" ]; then
          exit 1
        fi
        sleep 10
      done

      # Get snapshot ID
      SNAP_ID=$(aws ec2 describe-import-snapshot-tasks \
        --import-task-ids $SNAPSHOT_ID \
        --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.SnapshotId' \
        --output text)

      # Register AMI
      aws ec2 register-image \
        --name "$AMI_NAME" \
        --description "keydb NixOS AMI (Terraform-managed)" \
        --architecture x86_64 \
        --root-device-name /dev/xvda \
        --virtualization-type hvm \
        --ena-support \
        --block-device-mappings \
          "DeviceName=/dev/xvda,Ebs={SnapshotId=$SNAP_ID,VolumeSize=${var.keydb_root_volume_gb},VolumeType=gp3,DeleteOnTermination=true}" \
        --query 'ImageId' --output text
    EOT
  }

  depends_on = [
    aws_s3_bucket.ami_staging,
    aws_iam_role.vmimport,
    aws_iam_role_policy.vmimport,
  ]
}

# Look up the keydb AMI by its deterministic name
data "aws_ami" "keydb" {
  most_recent = true
  owners      = ["self"]

  filter {
    name   = "name"
    values = ["${var.name_prefix}-keydb${local.variant_suffix}-${data.external.keydb_image_hash.result.hash}"]
  }

  depends_on = [null_resource.build_keydb_ami]
}
