# ── Map closure_variant to nixosConfiguration names ───────────────────────────
locals {
  forgeproxy_config     = var.closure_variant == "dev" ? "forgeproxy" : "forgeproxy-hardened"
  valkey_config         = var.closure_variant == "dev" ? "valkey" : "valkey-hardened"
  ghe_key_lookup_config = var.closure_variant == "dev" ? "ghe-key-lookup" : "ghe-key-lookup-hardened"
  variant_suffix        = var.closure_variant == "dev" ? "" : "-hardened"

  # ── Values derived from the Nix configuration (single source of truth) ──
  valkey_tls_enable = data.external.nix_config.result.valkey_tls_enable == "true"
  backend_port      = tonumber(data.external.nix_config.result.backend_port)
  valkey_max_memory = data.external.nix_config.result.valkey_max_memory
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

data "external" "valkey_image_hash" {
  program = ["bash", "-c", <<-EOT
    set -euo pipefail
    OUTPATH=$(nix eval --tarball-ttl 0 --raw '${var.flake_ref}#nixosConfigurations.${local.valkey_config}.config.system.build.images.amazon.outPath')
    HASH=$(basename "$OUTPATH" | cut -d- -f1)
    printf '{"hash":"%s"}\n' "$HASH"
  EOT
  ]
}

data "external" "ghe_key_lookup_image_hash" {
  program = ["bash", "-c", <<-EOT
    set -euo pipefail
    OUTPATH=$(nix eval --tarball-ttl 0 --raw '${var.flake_ref}#nixosConfigurations."${local.ghe_key_lookup_config}".config.system.build.images.amazon.outPath')
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
    VALKEY_TLS=$(nix eval --tarball-ttl 0 '${var.flake_ref}#nixosConfigurations.${local.valkey_config}.config.services.valkey.tls.enable')
    BACKEND_PORT=$(nix eval --tarball-ttl 0 '${var.flake_ref}#nixosConfigurations.${local.forgeproxy_config}.config.services.forgeproxy-nginx.backendPort')
    VALKEY_MAX_MEM=$(nix eval --tarball-ttl 0 --raw '${var.flake_ref}#nixosConfigurations.${local.valkey_config}.config.services.valkey.maxMemory')
    printf '{"valkey_tls_enable":"%s","backend_port":"%s","valkey_max_memory":"%s"}\n' \
      "$VALKEY_TLS" "$BACKEND_PORT" "$VALKEY_MAX_MEM"
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

      if [ -z "$${AWS_PROFILE:-}" ] && [ -n "${var.aws_profile}" ]; then
        export AWS_PROFILE="${var.aws_profile}"
      fi
      if [ -z "$${AWS_REGION:-}" ]; then
        export AWS_REGION="${var.aws_region}"
      fi
      if [ -z "$${AWS_DEFAULT_REGION:-}" ]; then
        export AWS_DEFAULT_REGION="${var.aws_region}"
      fi

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

      # Build the NixOS image (only reached when AMI doesn't exist yet).
      # Use --no-link to avoid races on the shared ./result symlink when
      # multiple AMI builds run concurrently.
      OUT_PATH=$(nix build --tarball-ttl 0 --no-link --print-out-paths \
        '${var.flake_ref}#nixosConfigurations.${local.forgeproxy_config}.config.system.build.images.amazon' \
        | tail -n1)

      # Upload only if this exact image isn't already in the bucket.
      # Uses aggressive retry/timeout settings for large uploads over
      # slow or unstable home connections: adaptive retry, 64 MiB chunks
      # (fewer parts = fewer failure points), and a retry loop around
      # the entire upload.
      if ! aws s3api head-object --bucket "${aws_s3_bucket.ami_staging.id}" --key "$S3_KEY" 2>/dev/null; then
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

# ── Build valkey AMI ────────────────────────────────────────────────────────
resource "null_resource" "build_valkey_ami" {
  triggers = {
    image_hash  = data.external.valkey_image_hash.result.hash
    name_prefix = var.name_prefix
  }

  provisioner "local-exec" {
    command = <<-EOT
      set -euo pipefail

      if [ -z "$${AWS_PROFILE:-}" ] && [ -n "${var.aws_profile}" ]; then
        export AWS_PROFILE="${var.aws_profile}"
      fi
      if [ -z "$${AWS_REGION:-}" ]; then
        export AWS_REGION="${var.aws_region}"
      fi
      if [ -z "$${AWS_DEFAULT_REGION:-}" ]; then
        export AWS_DEFAULT_REGION="${var.aws_region}"
      fi

      HASH="${data.external.valkey_image_hash.result.hash}"
      AMI_NAME="${var.name_prefix}-valkey${local.variant_suffix}-$HASH"
      S3_KEY="valkey${local.variant_suffix}-$HASH.vhd"

      # If an AMI with this hash already exists, nothing to do
      EXISTING_AMI=$(aws ec2 describe-images \
        --owners self \
        --filters "Name=name,Values=$AMI_NAME" \
        --query 'Images[0].ImageId' --output text \
        --region "${var.aws_region}")
      if [ "$EXISTING_AMI" != "None" ]; then
        exit 0
      fi

      # Build the NixOS image (only reached when AMI doesn't exist yet).
      # Use --no-link to avoid races on the shared ./result symlink when
      # multiple AMI builds run concurrently.
      OUT_PATH=$(nix build --tarball-ttl 0 --no-link --print-out-paths \
        '${var.flake_ref}#nixosConfigurations.${local.valkey_config}.config.system.build.images.amazon' \
        | tail -n1)

      # Upload only if this exact image isn't already in the bucket.
      # Uses aggressive retry/timeout settings for large uploads over
      # slow or unstable home connections: adaptive retry, 64 MiB chunks
      # (fewer parts = fewer failure points), and a retry loop around
      # the entire upload.
      if ! aws s3api head-object --bucket "${aws_s3_bucket.ami_staging.id}" --key "$S3_KEY" 2>/dev/null; then
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
        --description "valkey NixOS image ($HASH)" \
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
        --description "valkey NixOS AMI (Terraform-managed)" \
        --architecture x86_64 \
        --root-device-name /dev/xvda \
        --virtualization-type hvm \
        --boot-mode uefi \
        --ena-support \
        --block-device-mappings \
          "DeviceName=/dev/xvda,Ebs={SnapshotId=$SNAP_ID,VolumeSize=${var.valkey_root_volume_gb},VolumeType=gp3,DeleteOnTermination=true}" \
        --query 'ImageId' --output text
    EOT
  }

  depends_on = [
    aws_s3_bucket.ami_staging,
    aws_iam_role.vmimport,
    aws_iam_role_policy.vmimport,
  ]
}

# Look up the valkey AMI by its deterministic name
data "aws_ami" "valkey" {
  most_recent = true
  owners      = ["self"]

  filter {
    name   = "name"
    values = ["${var.name_prefix}-valkey${local.variant_suffix}-${data.external.valkey_image_hash.result.hash}"]
  }

  depends_on = [null_resource.build_valkey_ami]
}

# ── Build ghe-key-lookup AMI ──────────────────────────────────────────────────
resource "null_resource" "build_ghe_key_lookup_ami" {
  count = var.enable_ghe_key_lookup ? 1 : 0

  triggers = {
    image_hash  = data.external.ghe_key_lookup_image_hash.result.hash
    name_prefix = var.name_prefix
  }

  provisioner "local-exec" {
    command = <<-EOT
      set -euo pipefail

      if [ -z "$${AWS_PROFILE:-}" ] && [ -n "${var.aws_profile}" ]; then
        export AWS_PROFILE="${var.aws_profile}"
      fi
      if [ -z "$${AWS_REGION:-}" ]; then
        export AWS_REGION="${var.aws_region}"
      fi
      if [ -z "$${AWS_DEFAULT_REGION:-}" ]; then
        export AWS_DEFAULT_REGION="${var.aws_region}"
      fi

      HASH="${data.external.ghe_key_lookup_image_hash.result.hash}"
      AMI_NAME="${var.name_prefix}-ghe-key-lookup${local.variant_suffix}-$HASH"
      S3_KEY="ghe-key-lookup${local.variant_suffix}-$HASH.vhd"

      # If an AMI with this hash already exists, nothing to do
      EXISTING_AMI=$(aws ec2 describe-images \
        --owners self \
        --filters "Name=name,Values=$AMI_NAME" \
        --query 'Images[0].ImageId' --output text \
        --region "${var.aws_region}")
      if [ "$EXISTING_AMI" != "None" ]; then
        exit 0
      fi

      # Build the NixOS image (only reached when AMI doesn't exist yet).
      # Use --no-link to avoid races on the shared ./result symlink when
      # multiple AMI builds run concurrently.
      OUT_PATH=$(nix build --tarball-ttl 0 --no-link --print-out-paths \
        '${var.flake_ref}#nixosConfigurations."${local.ghe_key_lookup_config}".config.system.build.images.amazon' \
        | tail -n1)

      # Upload only if this exact image isn't already in the bucket.
      if ! aws s3api head-object --bucket "${aws_s3_bucket.ami_staging.id}" --key "$S3_KEY" 2>/dev/null; then
        export AWS_MAX_ATTEMPTS=10
        export AWS_RETRY_MODE=adaptive
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
        --description "ghe-key-lookup NixOS image ($HASH)" \
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
        --description "ghe-key-lookup NixOS AMI (Terraform-managed)" \
        --architecture x86_64 \
        --root-device-name /dev/xvda \
        --virtualization-type hvm \
        --boot-mode uefi \
        --ena-support \
        --block-device-mappings \
          "DeviceName=/dev/xvda,Ebs={SnapshotId=$SNAP_ID,VolumeSize=${var.ghe_key_lookup_root_volume_gb},VolumeType=gp3,DeleteOnTermination=true}" \
        --query 'ImageId' --output text
    EOT
  }

  depends_on = [
    aws_s3_bucket.ami_staging,
    aws_iam_role.vmimport,
    aws_iam_role_policy.vmimport,
  ]
}

# Look up the ghe-key-lookup AMI by its deterministic name
data "aws_ami" "ghe_key_lookup" {
  count = var.enable_ghe_key_lookup ? 1 : 0

  most_recent = true
  owners      = ["self"]

  filter {
    name   = "name"
    values = ["${var.name_prefix}-ghe-key-lookup${local.variant_suffix}-${data.external.ghe_key_lookup_image_hash.result.hash}"]
  }

  depends_on = [null_resource.build_ghe_key_lookup_ami]
}
