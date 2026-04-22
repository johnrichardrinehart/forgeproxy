# ── Resolve instance architectures ──────────────────────────────────────────
data "aws_ec2_instance_type" "forgeproxy" {
  instance_type = var.forgeproxy_instance_type
}

data "aws_ec2_instance_type" "valkey" {
  instance_type = var.valkey_instance_type
}

data "aws_ec2_instance_type" "ghe_key_lookup" {
  count         = var.enable_ghe_key_lookup ? 1 : 0
  instance_type = var.ghe_key_lookup_instance_type
}

# ── Map closure_variant and instance architecture to nixosConfiguration names ─
locals {
  # EC2 reports "x86_64" or "arm64"; map to the Nix system and AMI arch strings.
  # supported_architectures is a list; all instance types have exactly one entry.
  forgeproxy_ec2_arch     = data.aws_ec2_instance_type.forgeproxy.supported_architectures[0]
  valkey_ec2_arch         = data.aws_ec2_instance_type.valkey.supported_architectures[0]
  ghe_key_lookup_ec2_arch = var.enable_ghe_key_lookup ? data.aws_ec2_instance_type.ghe_key_lookup[0].supported_architectures[0] : "x86_64"

  # AMI architecture strings accepted by ec2 register-image
  forgeproxy_ami_arch     = local.forgeproxy_ec2_arch == "arm64" ? "arm64" : "x86_64"
  valkey_ami_arch         = local.valkey_ec2_arch == "arm64" ? "arm64" : "x86_64"
  ghe_key_lookup_ami_arch = local.ghe_key_lookup_ec2_arch == "arm64" ? "arm64" : "x86_64"

  # Nix system strings used to select nixosConfigurations
  forgeproxy_nix_system     = local.forgeproxy_ec2_arch == "arm64" ? "aarch64-linux" : "x86_64-linux"
  valkey_nix_system         = local.valkey_ec2_arch == "arm64" ? "aarch64-linux" : "x86_64-linux"
  ghe_key_lookup_nix_system = local.ghe_key_lookup_ec2_arch == "arm64" ? "aarch64-linux" : "x86_64-linux"

  variant_suffix = var.closure_variant == "dev" ? "" : "-hardened"

  forgeproxy_config     = var.closure_variant == "dev" ? "forgeproxy-${local.forgeproxy_nix_system}" : "forgeproxy-hardened-${local.forgeproxy_nix_system}"
  valkey_config         = var.closure_variant == "dev" ? "valkey-${local.valkey_nix_system}" : "valkey-hardened-${local.valkey_nix_system}"
  ghe_key_lookup_config = var.closure_variant == "dev" ? "ghe-key-lookup-${local.ghe_key_lookup_nix_system}" : "ghe-key-lookup-hardened-${local.ghe_key_lookup_nix_system}"

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
    image_hash   = data.external.forgeproxy_image_hash.result.hash
    name_prefix  = var.name_prefix
    architecture = local.forgeproxy_ami_arch
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
        --architecture ${local.forgeproxy_ami_arch} \
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
    image_hash   = data.external.valkey_image_hash.result.hash
    name_prefix  = var.name_prefix
    architecture = local.valkey_ami_arch
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
        --architecture ${local.valkey_ami_arch} \
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
    image_hash   = data.external.ghe_key_lookup_image_hash.result.hash
    name_prefix  = var.name_prefix
    architecture = local.ghe_key_lookup_ami_arch
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
        --architecture ${local.ghe_key_lookup_ami_arch} \
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
