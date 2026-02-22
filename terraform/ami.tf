# ── Map closure_variant to nixosConfiguration names ───────────────────────────
locals {
  forgeproxy_config = var.closure_variant == "dev" ? "forgeproxy-dev" : "forgeproxy"
  keydb_config      = var.closure_variant == "dev" ? "keydb-dev" : "keydb"
  variant_suffix    = var.closure_variant == "dev" ? "-dev" : ""

  # ── Values derived from the Nix configuration (single source of truth) ──
  keydb_tls_enable = data.external.nix_config.result.keydb_tls_enable == "true"
  backend_port     = tonumber(data.external.nix_config.result.backend_port)
  keydb_max_memory = data.external.nix_config.result.keydb_max_memory
}

# ── Evaluate Nix outPaths at plan time (fast, no build) ──────────────────────
data "external" "forgeproxy_image_hash" {
  program = ["bash", "-c", <<-EOT
    set -euo pipefail
    OUTPATH=$(nix eval --tarball-ttl 0 --raw '${var.flake_ref}#nixosConfigurations.${local.forgeproxy_config}.config.system.build.images.amazon.outPath')
    HASH=$(basename "$OUTPATH" | cut -d- -f1)
    printf '{"hash":"%s"}\n' "$HASH"
  EOT
  ]
}

data "external" "keydb_image_hash" {
  program = ["bash", "-c", <<-EOT
    set -euo pipefail
    OUTPATH=$(nix eval --tarball-ttl 0 --raw '${var.flake_ref}#nixosConfigurations.${local.keydb_config}.config.system.build.images.amazon.outPath')
    HASH=$(basename "$OUTPATH" | cut -d- -f1)
    printf '{"hash":"%s"}\n' "$HASH"
  EOT
  ]
}

# ── Extract configuration values from Nix (single source of truth) ────────────
# These values are baked into the AMIs. Terraform must use the same values for
# infrastructure (SG rules, NLB target groups) and runtime config (Secrets Manager).
data "external" "nix_config" {
  program = ["bash", "-c", <<-EOT
    set -euo pipefail
    KEYDB_TLS=$(nix eval --tarball-ttl 0 '${var.flake_ref}#nixosConfigurations.${local.keydb_config}.config.services.keydb.tls.enable')
    BACKEND_PORT=$(nix eval --tarball-ttl 0 '${var.flake_ref}#nixosConfigurations.${local.forgeproxy_config}.config.services.forgeproxy-nginx.backendPort')
    KEYDB_MAX_MEM=$(nix eval --tarball-ttl 0 --raw '${var.flake_ref}#nixosConfigurations.${local.keydb_config}.config.services.keydb.maxMemory')
    printf '{"keydb_tls_enable":"%s","backend_port":"%s","keydb_max_memory":"%s"}\n' \
      "$KEYDB_TLS" "$BACKEND_PORT" "$KEYDB_MAX_MEM"
  EOT
  ]
}

# ── Build forgeproxy AMI ──────────────────────────────────────────────────
resource "null_resource" "build_forgeproxy_ami" {
  triggers = {
    image_hash  = data.external.forgeproxy_image_hash.result.hash
    name_prefix = var.name_prefix
  }

  provisioner "local-exec" {
    command = <<-EOT
      set -euo pipefail

      HASH="${data.external.forgeproxy_image_hash.result.hash}"
      AMI_NAME="${var.name_prefix}-forgeproxy${local.variant_suffix}-$HASH"
      S3_KEY="forgeproxy${local.variant_suffix}-$HASH.vhd"

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
      nix build --tarball-ttl 0 '${var.flake_ref}#nixosConfigurations.${local.forgeproxy_config}.config.system.build.images.amazon'

      # Upload only if this exact image isn't already in the bucket.
      # Uses aggressive retry/timeout settings for large uploads over
      # slow or unstable home connections: adaptive retry, 64 MiB chunks
      # (fewer parts = fewer failure points), and a retry loop around
      # the entire upload.
      if ! aws s3api head-object --bucket "${aws_s3_bucket.ami_staging.id}" --key "$S3_KEY" 2>/dev/null; then
        OUT_PATH=$(readlink -f result)
        export AWS_MAX_ATTEMPTS=10
        export AWS_RETRY_MODE=adaptive
        # Configure S3 multipart settings in a temp copy of the user's config
        S3_CFG=$(mktemp)
        trap 'rm -f "$S3_CFG"' EXIT
        cp "$HOME/.aws/config" "$S3_CFG"
        AWS_CONFIG_FILE="$S3_CFG" aws configure set default.s3.multipart_chunksize 64MB
        AWS_CONFIG_FILE="$S3_CFG" aws configure set default.s3.max_concurrent_requests 2
        for attempt in 1 2 3; do
          echo "S3 upload attempt $attempt/3 ..."
          if AWS_CONFIG_FILE="$S3_CFG" aws s3 cp \
            --cli-read-timeout 600 \
            --cli-connect-timeout 120 \
            "$OUT_PATH"/*.vhd \
            "s3://${aws_s3_bucket.ami_staging.id}/$S3_KEY"; then
            break
          fi
          if [ "$attempt" -eq 3 ]; then
            echo "S3 upload failed after 3 attempts" >&2; exit 1
          fi
          echo "Upload failed, retrying in 10s ..."
          sleep 10
        done
      fi

      # Import snapshot from S3
      SNAPSHOT_ID=$(aws ec2 import-snapshot \
        --description "forgeproxy NixOS image ($HASH)" \
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
        --description "forgeproxy NixOS AMI (Terraform-managed)" \
        --architecture x86_64 \
        --root-device-name /dev/xvda \
        --virtualization-type hvm \
        --boot-mode uefi \
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

# Look up the forgeproxy AMI by its deterministic name
data "aws_ami" "forgeproxy" {
  most_recent = true
  owners      = ["self"]

  filter {
    name   = "name"
    values = ["${var.name_prefix}-forgeproxy${local.variant_suffix}-${data.external.forgeproxy_image_hash.result.hash}"]
  }

  depends_on = [null_resource.build_forgeproxy_ami]
}

# ── Build keydb AMI ────────────────────────────────────────────────────────
resource "null_resource" "build_keydb_ami" {
  triggers = {
    image_hash  = data.external.keydb_image_hash.result.hash
    name_prefix = var.name_prefix
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

      # Upload only if this exact image isn't already in the bucket.
      # Uses aggressive retry/timeout settings for large uploads over
      # slow or unstable home connections: adaptive retry, 64 MiB chunks
      # (fewer parts = fewer failure points), and a retry loop around
      # the entire upload.
      if ! aws s3api head-object --bucket "${aws_s3_bucket.ami_staging.id}" --key "$S3_KEY" 2>/dev/null; then
        OUT_PATH=$(readlink -f result)
        export AWS_MAX_ATTEMPTS=10
        export AWS_RETRY_MODE=adaptive
        # Configure S3 multipart settings in a temp copy of the user's config
        S3_CFG=$(mktemp)
        trap 'rm -f "$S3_CFG"' EXIT
        cp "$HOME/.aws/config" "$S3_CFG"
        AWS_CONFIG_FILE="$S3_CFG" aws configure set default.s3.multipart_chunksize 64MB
        AWS_CONFIG_FILE="$S3_CFG" aws configure set default.s3.max_concurrent_requests 2
        for attempt in 1 2 3; do
          echo "S3 upload attempt $attempt/3 ..."
          if AWS_CONFIG_FILE="$S3_CFG" aws s3 cp \
            --cli-read-timeout 600 \
            --cli-connect-timeout 120 \
            "$OUT_PATH"/*.vhd \
            "s3://${aws_s3_bucket.ami_staging.id}/$S3_KEY"; then
            break
          fi
          if [ "$attempt" -eq 3 ]; then
            echo "S3 upload failed after 3 attempts" >&2; exit 1
          fi
          echo "Upload failed, retrying in 10s ..."
          sleep 10
        done
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
        --boot-mode uefi \
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
