{
  config,
  pkgs,
  lib,
  ...
}:

let
  cacheVolumeAttach = pkgs.writeShellScript "forgeproxy-cache-volume-attach" ''
    set -euo pipefail

    log() {
      echo "forgeproxy-cache-volume: $*" >&2
    }

    metadata() {
      ${pkgs.curl}/bin/curl -sf -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" "http://169.254.169.254/latest/$1"
    }

    user_data_value() {
      printf '%s\n' "$USER_DATA" \
        | ${pkgs.gnused}/bin/sed -n "s/^# $1=//p" \
        | ${pkgs.coreutils}/bin/head -n1
    }

    IMDS_TOKEN=$(${pkgs.curl}/bin/curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
    USER_DATA=$(metadata "user-data" || true)

    enabled=$(user_data_value FORGEPROXY_CACHE_EBS_ENABLED)
    mount_dir=$(user_data_value FORGEPROXY_CACHE_MOUNT_DIR)
    mount_dir=''${mount_dir:-/var/cache/forgeproxy}
    ${pkgs.coreutils}/bin/mkdir -p "$mount_dir"

    if [ "$enabled" != "true" ]; then
      log "dedicated cache EBS disabled; using root filesystem cache directory"
      exit 0
    fi

    name_prefix=$(user_data_value SM_PREFIX)
    slot=$(user_data_value FORGEPROXY_DEPLOYMENT_SLOT)
    volume_type=$(user_data_value FORGEPROXY_CACHE_VOLUME_TYPE)
    volume_type=''${volume_type:-gp3}
    volume_size_gb=$(user_data_value FORGEPROXY_CACHE_VOLUME_GB)
    volume_size_gb=''${volume_size_gb:-1024}
    volume_iops=$(user_data_value FORGEPROXY_CACHE_VOLUME_IOPS)
    volume_iops=''${volume_iops:-3000}
    volume_throughput=$(user_data_value FORGEPROXY_CACHE_VOLUME_THROUGHPUT_MBPS)
    volume_throughput=''${volume_throughput:-125}
    attach_device=$(user_data_value FORGEPROXY_CACHE_VOLUME_DEVICE_NAME)
    attach_device=''${attach_device:-/dev/sdf}
    fs_type=$(user_data_value FORGEPROXY_CACHE_VOLUME_FS_TYPE)
    fs_type=''${fs_type:-xfs}
    fs_label=$(user_data_value FORGEPROXY_CACHE_VOLUME_LABEL)
    fs_label=''${fs_label:-forgeproxy}
    mount_options=$(user_data_value FORGEPROXY_CACHE_MOUNT_OPTIONS)
    mount_options=''${mount_options:-noatime}
    xfs_label_max_bytes=12

    if [ -z "$name_prefix" ] || [ -z "$slot" ]; then
      log "FATAL: missing SM_PREFIX or FORGEPROXY_DEPLOYMENT_SLOT in EC2 user-data"
      exit 1
    fi

    identity=$(metadata "dynamic/instance-identity/document")
    region=$(printf '%s\n' "$identity" | ${pkgs.jq}/bin/jq -r '.region')
    instance_id=$(printf '%s\n' "$identity" | ${pkgs.jq}/bin/jq -r '.instanceId')
    az=$(metadata "meta-data/placement/availability-zone")
    aws=(${pkgs.awscli2}/bin/aws --region "$region")

    describe_current_attachment() {
      "''${aws[@]}" ec2 describe-volumes \
        --filters \
          "Name=attachment.instance-id,Values=$instance_id" \
          "Name=tag:Role,Values=forgeproxy-cache" \
          "Name=tag:ForgeproxyNamePrefix,Values=$name_prefix" \
          "Name=tag:DeploymentSlot,Values=$slot" \
        --query 'Volumes[0].VolumeId' \
        --output text
    }

    available_current_seed_volumes() {
      "''${aws[@]}" ec2 describe-volumes \
        --filters \
          "Name=status,Values=available" \
          "Name=availability-zone,Values=$az" \
          "Name=tag:Role,Values=forgeproxy-cache" \
          "Name=tag:ForgeproxyNamePrefix,Values=$name_prefix" \
          "Name=tag:DeploymentSlot,Values=$slot" \
          "Name=tag:CurrentSeed,Values=true" \
        --query 'Volumes[].[VolumeId, Tags[?Key==`CacheSlot`].Value | [0]]' \
        --output text \
        | ${pkgs.coreutils}/bin/sort -k2,2n \
        | ${pkgs.gawk}/bin/awk '{print $1}'
    }

    current_seed_snapshots() {
      "''${aws[@]}" ec2 describe-snapshots \
        --owner-ids self \
        --filters \
          "Name=status,Values=completed" \
          "Name=tag:Role,Values=forgeproxy-cache-seed" \
          "Name=tag:ForgeproxyNamePrefix,Values=$name_prefix" \
          "Name=tag:DeploymentSlot,Values=$slot" \
          "Name=tag:CurrentSeed,Values=true" \
        --query 'Snapshots[].[SnapshotId, Tags[?Key==`SourceCacheSlot`].Value | [0]]' \
        --output text \
        | ${pkgs.coreutils}/bin/sort -k2,2n \
        | ${pkgs.gawk}/bin/awk '{print $1}'
    }

    existing_current_seed_volume_count() {
      "''${aws[@]}" ec2 describe-volumes \
        --filters \
          "Name=availability-zone,Values=$az" \
          "Name=tag:Role,Values=forgeproxy-cache" \
          "Name=tag:ForgeproxyNamePrefix,Values=$name_prefix" \
          "Name=tag:DeploymentSlot,Values=$slot" \
          "Name=tag:CurrentSeed,Values=true" \
        --query 'length(Volumes)' \
        --output text
    }

    snapshot_volume_size_gb() {
      local snapshot_id="$1"

      "''${aws[@]}" ec2 describe-snapshots \
        --snapshot-ids "$snapshot_id" \
        --query 'Snapshots[0].VolumeSize' \
        --output text
    }

    create_volume_from_seed() {
      local snapshots snapshot_count existing_count snapshot_id snapshot_size_gb tag_spec

      mapfile -t snapshots < <(current_seed_snapshots)
      snapshot_count=''${#snapshots[@]}
      existing_count=$(existing_current_seed_volume_count)
      snapshot_id=""
      if [ "$snapshot_count" -gt 0 ]; then
        snapshot_id=''${snapshots[$(( existing_count % snapshot_count ))]}
        log "creating cache volume from seed snapshot $snapshot_id"
      else
        log "creating blank cache volume; no current seed snapshots are available"
      fi

      tag_spec="ResourceType=volume,Tags=[{Key=Name,Value=$name_prefix-forgeproxy-$slot-cache-dynamic},{Key=Role,Value=forgeproxy-cache},{Key=ForgeproxyNamePrefix,Value=$name_prefix},{Key=DeploymentSlot,Value=$slot},{Key=CacheSlot,Value=dynamic},{Key=CurrentSeed,Value=true},{Key=AttachmentState,Value=available},{Key=AvailabilityZone,Value=$az},{Key=CreatedBy,Value=forgeproxy-cache-volume-attach}]"

      local args=(
        ec2 create-volume
        --availability-zone "$az"
        --volume-type "$volume_type"
        --encrypted
        --tag-specifications "$tag_spec"
        --query VolumeId
        --output text
      )
      if [ "$volume_type" = "gp3" ]; then
        args+=(--iops "$volume_iops" --throughput "$volume_throughput")
      fi
      if [ -n "$snapshot_id" ]; then
        args+=(--snapshot-id "$snapshot_id")
        snapshot_size_gb=$(snapshot_volume_size_gb "$snapshot_id")
        if [ "$volume_size_gb" -gt "$snapshot_size_gb" ]; then
          args+=(--size "$volume_size_gb")
        fi
      else
        args+=(--size "$volume_size_gb")
      fi

      "''${aws[@]}" "''${args[@]}"
    }

    attach_volume() {
      local volume_id="$1"

      log "attaching cache volume $volume_id to $instance_id as $attach_device"
      if ! "''${aws[@]}" ec2 attach-volume \
        --volume-id "$volume_id" \
        --instance-id "$instance_id" \
        --device "$attach_device" >/dev/null; then
        return 1
      fi
      "''${aws[@]}" ec2 wait volume-in-use --volume-ids "$volume_id"
      "''${aws[@]}" ec2 create-tags \
        --resources "$volume_id" \
        --tags \
          Key=AttachmentState,Value=attached \
          Key=AttachedInstance,Value="$instance_id" \
          Key=AvailabilityZone,Value="$az" >/dev/null
    }

    choose_or_create_volume() {
      local volume_id

      volume_id=$(describe_current_attachment)
      if [ -n "$volume_id" ] && [ "$volume_id" != "None" ]; then
        log "cache volume $volume_id is already attached to this instance"
        printf '%s\n' "$volume_id"
        return 0
      fi

      while read -r volume_id; do
        [ -n "$volume_id" ] || continue
        if attach_volume "$volume_id"; then
          printf '%s\n' "$volume_id"
          return 0
        fi
        log "volume $volume_id could not be attached; trying another candidate"
      done < <(available_current_seed_volumes)

      volume_id=$(create_volume_from_seed)
      "''${aws[@]}" ec2 wait volume-available --volume-ids "$volume_id"
      attach_volume "$volume_id"
      printf '%s\n' "$volume_id"
    }

    find_block_device() {
      local volume_id="$1"
      local volume_serial
      volume_serial=''${volume_id//-/}

      for _ in $(${pkgs.coreutils}/bin/seq 1 120); do
        for candidate in \
          "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_$volume_serial" \
          "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_$volume_id" \
          "$attach_device" \
          "/dev/xvdf"
        do
          if [ -e "$candidate" ]; then
            ${pkgs.coreutils}/bin/readlink -f "$candidate"
            return 0
          fi
        done
        sleep 1
      done

      log "FATAL: attached cache volume $volume_id did not appear as a block device"
      exit 1
    }

    ensure_filesystem() {
      local block_device="$1"
      local xfs_label

      if ${pkgs.util-linux}/bin/blkid "$block_device" >/dev/null 2>&1; then
        log "cache volume $block_device already has a filesystem"
        return 0
      fi

      log "formatting blank cache volume $block_device as $fs_type"
      case "$fs_type" in
        xfs)
          # XFS stores filesystem labels in a fixed 12-byte on-disk field.
          xfs_label=$(printf '%s' "$fs_label" | ${pkgs.coreutils}/bin/head -c "$xfs_label_max_bytes")
          if [ "$xfs_label" != "$fs_label" ]; then
            log "truncating XFS cache filesystem label '$fs_label' to '$xfs_label'"
          fi
          ${pkgs.xfsprogs}/bin/mkfs.xfs -f -L "$xfs_label" "$block_device"
          ;;
        ext4)
          ${pkgs.e2fsprogs}/bin/mkfs.ext4 -F -L "$fs_label" "$block_device"
          ;;
        *)
          log "FATAL: unsupported cache filesystem type: $fs_type"
          exit 1
          ;;
      esac
    }

    volume_id=$(choose_or_create_volume)
    block_device=$(find_block_device "$volume_id")
    ensure_filesystem "$block_device"

    if ${pkgs.util-linux}/bin/mountpoint -q "$mount_dir"; then
      log "$mount_dir is already mounted"
    else
      log "mounting $block_device at $mount_dir"
      ${pkgs.util-linux}/bin/mount -o "$mount_options" "$block_device" "$mount_dir"
    fi

    ${pkgs.coreutils}/bin/chgrp forgeproxy-cache "$mount_dir" || true
    ${pkgs.coreutils}/bin/chmod 2775 "$mount_dir" || true
    log "cache volume $volume_id is ready at $mount_dir"
  '';
in
{
  config = lib.mkIf (config.services.forgeproxy.enable or false) {
    boot.kernelModules = [ "xfs" ];
    boot.supportedFilesystems = [ "xfs" ];

    systemd.services.forgeproxy-cache-volume = {
      description = "Attach and mount the forgeproxy dedicated cache EBS volume";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      before = [
        "forgeproxy.service"
        "forgeproxy-cache-scrub.service"
      ];
      requiredBy = [ "forgeproxy.service" ];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };

      script = ''
        exec ${cacheVolumeAttach}
      '';
    };

    systemd.services.forgeproxy = {
      requires = [ "forgeproxy-cache-volume.service" ];
      after = [ "forgeproxy-cache-volume.service" ];
    };

    systemd.services.forgeproxy-cache-scrub =
      lib.mkIf (config.services.forgeproxy.validation.periodicFullFsckIntervalSec != null)
        {
          after = [ "forgeproxy-cache-volume.service" ];
        };
  };
}
