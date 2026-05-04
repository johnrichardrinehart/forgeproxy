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

  cacheVolumeSnapshot = pkgs.writeShellScript "forgeproxy-cache-volume-snapshot" ''
    set -euo pipefail

    log() {
      echo "forgeproxy-cache-snapshot: $*" >&2
    }

    log_event() {
      local event="$1"
      shift

      echo "forgeproxy-cache-snapshot-event event=$event $*" >&2
    }

    validate_nonnegative_integer() {
      local name="$1"
      local value="$2"

      case "$value" in
        ""|None|*[!0-9]*)
          log "FATAL: $name must be a non-negative integer, got $value"
          exit 1
          ;;
      esac
    }

    validate_positive_integer() {
      local name="$1"
      local value="$2"

      validate_nonnegative_integer "$name" "$value"
      if [ "$value" -lt 1 ]; then
        log "FATAL: $name must be a positive integer, got $value"
        exit 1
      fi
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
    snapshot_enabled=$(user_data_value FORGEPROXY_CACHE_PERIODIC_SNAPSHOT_ENABLED)
    if [ "$enabled" != "true" ] || [ "$snapshot_enabled" != "true" ]; then
      log "periodic cache snapshots disabled"
      exit 0
    fi

    name_prefix=$(user_data_value SM_PREFIX)
    slot=$(user_data_value FORGEPROXY_DEPLOYMENT_SLOT)
    interval_secs=$(user_data_value FORGEPROXY_CACHE_PERIODIC_SNAPSHOT_INTERVAL_SECS)
    interval_secs=''${interval_secs:-86400}
    wait_timeout_secs=$(user_data_value FORGEPROXY_CACHE_PERIODIC_SNAPSHOT_WAIT_TIMEOUT_SECS)
    wait_timeout_secs=''${wait_timeout_secs:-86400}
    poll_secs=$(user_data_value FORGEPROXY_CACHE_PERIODIC_SNAPSHOT_POLL_SECS)
    poll_secs=''${poll_secs:-60}
    retention_count=$(user_data_value FORGEPROXY_CACHE_SEED_SNAPSHOT_RETENTION_COUNT)
    retention_count=''${retention_count:-1}

    validate_positive_integer FORGEPROXY_CACHE_PERIODIC_SNAPSHOT_INTERVAL_SECS "$interval_secs"
    validate_nonnegative_integer FORGEPROXY_CACHE_PERIODIC_SNAPSHOT_WAIT_TIMEOUT_SECS "$wait_timeout_secs"
    validate_positive_integer FORGEPROXY_CACHE_PERIODIC_SNAPSHOT_POLL_SECS "$poll_secs"
    validate_positive_integer FORGEPROXY_CACHE_SEED_SNAPSHOT_RETENTION_COUNT "$retention_count"

    if [ "$wait_timeout_secs" -gt "$interval_secs" ]; then
      log "warning: FORGEPROXY_CACHE_PERIODIC_SNAPSHOT_WAIT_TIMEOUT_SECS=$wait_timeout_secs exceeds FORGEPROXY_CACHE_PERIODIC_SNAPSHOT_INTERVAL_SECS=$interval_secs"
      log_event config_warning \
        "warning=wait_timeout_exceeds_interval" \
        "wait_timeout_secs=$wait_timeout_secs" \
        "interval_secs=$interval_secs"
    fi

    if [ -z "$name_prefix" ] || [ -z "$slot" ]; then
      log "FATAL: missing SM_PREFIX or FORGEPROXY_DEPLOYMENT_SLOT in EC2 user-data"
      exit 1
    fi

    case "$slot" in
      blue)
        target_slot=green
        ;;
      green)
        target_slot=blue
        ;;
      *)
        log "FATAL: unknown deployment slot $slot"
        exit 1
        ;;
    esac

    identity=$(metadata "dynamic/instance-identity/document")
    region=$(printf '%s\n' "$identity" | ${pkgs.jq}/bin/jq -r '.region')
    instance_id=$(printf '%s\n' "$identity" | ${pkgs.jq}/bin/jq -r '.instanceId')
    aws=(${pkgs.awscli2}/bin/aws --region "$region")

    attached_cache_volume_row() {
      "''${aws[@]}" ec2 describe-volumes \
        --filters \
          "Name=attachment.instance-id,Values=$instance_id" \
          "Name=tag:Role,Values=forgeproxy-cache" \
          "Name=tag:ForgeproxyNamePrefix,Values=$name_prefix" \
          "Name=tag:DeploymentSlot,Values=$slot" \
        --query 'Volumes[0].[VolumeId, Tags[?Key==`CacheSlot`].Value | [0]]' \
        --output text
    }

    current_seed_snapshots_for_volume() {
      local source_volume_id="$1"

      "''${aws[@]}" ec2 describe-snapshots \
        --owner-ids self \
        --filters \
          "Name=status,Values=completed" \
          "Name=tag:Role,Values=forgeproxy-cache-seed" \
          "Name=tag:ForgeproxyNamePrefix,Values=$name_prefix" \
          "Name=tag:DeploymentSlot,Values=$target_slot" \
          "Name=tag:SourceSlot,Values=$slot" \
          "Name=tag:SourceVolumeId,Values=$source_volume_id" \
          "Name=tag:CurrentSeed,Values=true" \
        --query 'Snapshots[].[SnapshotId, Tags[?Key==`CreatedAtUnix`].Value | [0]]' \
        --output text
    }

    pending_seed_snapshot_rows() {
      local volume_id="$1"

      "''${aws[@]}" ec2 describe-snapshots \
        --owner-ids self \
        --filters \
          "Name=tag:Role,Values=forgeproxy-cache-seed" \
          "Name=tag:ForgeproxyNamePrefix,Values=$name_prefix" \
          "Name=tag:DeploymentSlot,Values=$target_slot" \
          "Name=tag:SourceSlot,Values=$slot" \
          "Name=tag:SourceVolumeId,Values=$volume_id" \
          "Name=tag:PendingSeed,Values=true" \
        --query 'Snapshots[].[SnapshotId, State, Tags[?Key==`SourceCacheSlot`].Value | [0]]' \
        --output text
    }

    completed_seed_snapshot_rows() {
      "''${aws[@]}" ec2 describe-snapshots \
        --owner-ids self \
        --filters \
          "Name=status,Values=completed" \
          "Name=tag:Role,Values=forgeproxy-cache-seed" \
          "Name=tag:ForgeproxyNamePrefix,Values=$name_prefix" \
          "Name=tag:DeploymentSlot,Values=$target_slot" \
          "Name=tag:SourceSlot,Values=$slot" \
        --query 'Snapshots[].[SnapshotId, Tags[?Key==`SourceVolumeId`].Value | [0], Tags[?Key==`SourceCacheSlot`].Value | [0], Tags[?Key==`CreatedAtUnix`].Value | [0]]' \
        --output text
    }

    snapshot_state() {
      local snapshot_id="$1"

      "''${aws[@]}" ec2 describe-snapshots \
        --snapshot-ids "$snapshot_id" \
        --query 'Snapshots[0].State' \
        --output text
    }

    snapshot_created_at_unix() {
      local snapshot_id="$1"
      local created_at

      created_at=$("''${aws[@]}" ec2 describe-snapshots \
        --snapshot-ids "$snapshot_id" \
        --query 'Snapshots[0].Tags[?Key==`CreatedAtUnix`].Value | [0]' \
        --output text)
      case "$created_at" in
        ""|None|*[!0-9]*)
          created_at=0
          ;;
      esac

      printf '%s\n' "$created_at"
    }

    mark_current_snapshots_inactive() {
      local source_volume_id="$1"
      local snapshot_ids

      snapshot_ids=$("''${aws[@]}" ec2 describe-snapshots \
        --owner-ids self \
        --filters \
          "Name=tag:Role,Values=forgeproxy-cache-seed" \
          "Name=tag:ForgeproxyNamePrefix,Values=$name_prefix" \
          "Name=tag:DeploymentSlot,Values=$target_slot" \
          "Name=tag:SourceSlot,Values=$slot" \
          "Name=tag:SourceVolumeId,Values=$source_volume_id" \
          "Name=tag:CurrentSeed,Values=true" \
        --query 'Snapshots[].SnapshotId' \
        --output text)

      if [ -z "$snapshot_ids" ] || [ "$snapshot_ids" = "None" ]; then
        return 0
      fi

      log "marking old $target_slot seed snapshots inactive: $snapshot_ids"
      "''${aws[@]}" ec2 create-tags \
        --resources $snapshot_ids \
        --tags Key=CurrentSeed,Value=false >/dev/null
    }

    delete_old_seed_snapshots() {
      local snapshot_ids snapshot_id

      case "$retention_count" in
        ""|None|*[!0-9]*)
          log "FATAL: invalid FORGEPROXY_CACHE_SEED_SNAPSHOT_RETENTION_COUNT=$retention_count"
          return 1
          ;;
      esac
      if [ "$retention_count" -lt 1 ]; then
        return 0
      fi

      snapshot_ids=$(completed_seed_snapshot_rows | ${pkgs.gawk}/bin/awk -v keep="$retention_count" '
        NF >= 1 {
          snapshot_id = $1
          source_volume_id = $2
          cache_slot = $3
          created_at = $4
          if (source_volume_id == "" || source_volume_id == "None") {
            source_volume_id = ""
          }
          if (cache_slot == "" || cache_slot == "None") {
            cache_slot = "dynamic"
          }
          if (created_at !~ /^[0-9]+$/) {
            created_at = 0
          }
          group_key = source_volume_id
          if (group_key == "") {
            group_key = "cache:" cache_slot
          }
          print group_key, created_at, snapshot_id
        }
      ' | ${pkgs.coreutils}/bin/sort -k1,1 -k2,2nr | ${pkgs.gawk}/bin/awk -v keep="$retention_count" '
        {
          group_key = $1
          seen[group_key] += 1
          if (seen[group_key] > keep) {
            print $3
          }
        }
      ')

      if [ -z "$snapshot_ids" ] || [ "$snapshot_ids" = "None" ]; then
        return 0
      fi

      while read -r snapshot_id; do
        [ -n "$snapshot_id" ] || continue
        log "deleting old $target_slot cache seed snapshot $snapshot_id"
        "''${aws[@]}" ec2 delete-snapshot --snapshot-id "$snapshot_id" >/dev/null
      done <<<"$snapshot_ids"
    }

    promote_snapshot() {
      local snapshot_id="$1"
      local cache_slot="$2"
      local source_volume_id="$3"
      local completed_at_unix newest_created_at snapshot_created_at

      snapshot_created_at=$(snapshot_created_at_unix "$snapshot_id")
      newest_created_at=$(latest_current_seed_created_at "$source_volume_id")
      if [ "$snapshot_created_at" -lt "$newest_created_at" ]; then
        "''${aws[@]}" ec2 create-tags \
          --resources "$snapshot_id" \
          --tags \
            Key=CurrentSeed,Value=false \
            Key=PendingSeed,Value=false \
            Key=StaleSeed,Value=true >/dev/null
        log "skipped stale periodic cache seed snapshot $snapshot_id for $target_slot cache slot $cache_slot"
        return 0
      fi

      completed_at_unix=$(${pkgs.coreutils}/bin/date -u +%s)
      mark_current_snapshots_inactive "$source_volume_id"
      "''${aws[@]}" ec2 create-tags \
        --resources "$snapshot_id" \
        --tags \
          Key=CurrentSeed,Value=true \
          Key=PendingSeed,Value=false \
          Key=CompletedAtUnix,Value="$completed_at_unix" >/dev/null
      delete_old_seed_snapshots
      log "promoted completed cache seed snapshot $snapshot_id for $target_slot cache slot $cache_slot"
    }

    complete_pending_snapshot_if_ready() {
      local row snapshot_id state cache_slot

      while read -r row; do
        [ -n "$row" ] || continue
        snapshot_id=$(printf '%s\n' "$row" | ${pkgs.gawk}/bin/awk '{print $1}')
        state=$(printf '%s\n' "$row" | ${pkgs.gawk}/bin/awk '{print $2}')
        cache_slot=$(printf '%s\n' "$row" | ${pkgs.gawk}/bin/awk '{print $3}')
        [ -n "$snapshot_id" ] && [ "$snapshot_id" != "None" ] || continue
        case "$state" in
          completed)
            promote_snapshot "$snapshot_id" "$cache_slot" "$volume_id"
            return 0
            ;;
          error)
            log "periodic cache seed snapshot $snapshot_id failed"
            log_event snapshot_error \
              "snapshot_id=$snapshot_id" \
              "state=$state" \
              "volume_id=$volume_id" \
              "source_slot=$slot" \
              "target_slot=$target_slot" \
              "cache_slot=$cache_slot"
            "''${aws[@]}" ec2 create-tags \
              --resources "$snapshot_id" \
              --tags \
                Key=CurrentSeed,Value=false \
                Key=PendingSeed,Value=false \
                Key=StaleSeed,Value=true >/dev/null
            return 1
            ;;
          *)
            log "periodic cache seed snapshot $snapshot_id is still $state"
            return 0
            ;;
        esac
      done < <(pending_seed_snapshot_rows "$volume_id")
      return 1
    }

    latest_current_seed_created_at() {
      local source_volume_id="$1"
      local row snapshot_id created_at newest

      newest=0
      while read -r row; do
        [ -n "$row" ] || continue
        snapshot_id=$(printf '%s\n' "$row" | ${pkgs.gawk}/bin/awk '{print $1}')
        created_at=$(printf '%s\n' "$row" | ${pkgs.gawk}/bin/awk '{print $2}')
        [ -n "$snapshot_id" ] && [ "$snapshot_id" != "None" ] || continue
        case "$created_at" in
          ""|None|*[!0-9]*)
            created_at=0
            ;;
        esac
        if [ "$created_at" -gt "$newest" ]; then
          newest="$created_at"
        fi
      done < <(current_seed_snapshots_for_volume "$source_volume_id")

      printf '%s\n' "$newest"
    }

    wait_for_snapshot_completion() {
      local snapshot_id="$1"
      local cache_slot="$2"
      local start now state

      if [ "$wait_timeout_secs" -eq 0 ]; then
        return 0
      fi

      start=$(${pkgs.coreutils}/bin/date -u +%s)
      while true; do
        state=$(snapshot_state "$snapshot_id")
        case "$state" in
          completed)
            promote_snapshot "$snapshot_id" "$cache_slot" "$volume_id"
            return 0
            ;;
          error)
            log "periodic cache seed snapshot $snapshot_id failed"
            log_event snapshot_error \
              "snapshot_id=$snapshot_id" \
              "state=$state" \
              "volume_id=$volume_id" \
              "source_slot=$slot" \
              "target_slot=$target_slot" \
              "cache_slot=$cache_slot"
            return 1
            ;;
        esac

        now=$(${pkgs.coreutils}/bin/date -u +%s)
        if [ $(( now - start )) -ge "$wait_timeout_secs" ]; then
          log "periodic cache seed snapshot $snapshot_id is still $state after ''${wait_timeout_secs}s; a later timer run will promote it"
          log_event snapshot_pending_after_wait_timeout \
            "snapshot_id=$snapshot_id" \
            "state=$state" \
            "wait_timeout_secs=$wait_timeout_secs" \
            "poll_secs=$poll_secs" \
            "volume_id=$volume_id" \
            "source_slot=$slot" \
            "target_slot=$target_slot" \
            "cache_slot=$cache_slot"
          return 0
        fi
        ${pkgs.coreutils}/bin/sleep "$poll_secs"
      done
    }

    row=$(attached_cache_volume_row)
    volume_id=$(printf '%s\n' "$row" | ${pkgs.gawk}/bin/awk '{print $1}')
    cache_slot=$(printf '%s\n' "$row" | ${pkgs.gawk}/bin/awk '{print $2}')
    if [ -z "$volume_id" ] || [ "$volume_id" = "None" ]; then
      log "no attached dedicated cache volume found"
      exit 0
    fi
    [ -n "$cache_slot" ] && [ "$cache_slot" != "None" ] || cache_slot=dynamic

    if complete_pending_snapshot_if_ready; then
      exit 0
    fi

    now=$(${pkgs.coreutils}/bin/date -u +%s)
    latest_created_at=$(latest_current_seed_created_at "$volume_id")
    if [ "$latest_created_at" -gt 0 ] && [ $(( now - latest_created_at )) -lt "$interval_secs" ]; then
      log "latest current cache seed snapshot for $target_slot cache slot $cache_slot is younger than ''${interval_secs}s"
      exit 0
    fi

    log "creating periodic cache seed snapshot from $slot volume $volume_id for $target_slot cache slot $cache_slot"
    snapshot_id=$("''${aws[@]}" ec2 create-snapshot \
      --volume-id "$volume_id" \
      --description "$name_prefix forgeproxy $slot cache slot $cache_slot periodic seed for $target_slot" \
      --tag-specifications "ResourceType=snapshot,Tags=[{Key=Name,Value=$name_prefix-forgeproxy-$target_slot-cache-seed-$cache_slot-periodic},{Key=Role,Value=forgeproxy-cache-seed},{Key=ForgeproxyNamePrefix,Value=$name_prefix},{Key=DeploymentSlot,Value=$target_slot},{Key=SourceSlot,Value=$slot},{Key=SourceCacheSlot,Value=$cache_slot},{Key=SourceVolumeId,Value=$volume_id},{Key=CurrentSeed,Value=false},{Key=PendingSeed,Value=true},{Key=CreatedAtUnix,Value=$now},{Key=CreatedBy,Value=forgeproxy-cache-volume-snapshot}]" \
      --query SnapshotId \
      --output text)
    log "created periodic cache seed snapshot $snapshot_id"
    wait_for_snapshot_completion "$snapshot_id" "$cache_slot"
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

    systemd.services.forgeproxy-cache-snapshot = {
      description = "Create periodic forgeproxy dedicated cache EBS seed snapshots";
      after = [
        "network-online.target"
        "forgeproxy-cache-volume.service"
      ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        Type = "oneshot";
      };

      script = ''
        exec ${cacheVolumeSnapshot}
      '';
    };

    systemd.timers.forgeproxy-cache-snapshot = {
      description = "Run periodic forgeproxy dedicated cache EBS seed snapshots";
      wantedBy = [ "timers.target" ];

      timerConfig = {
        OnBootSec = "15min";
        OnUnitActiveSec = "1h";
        Persistent = true;
      };
    };
  };
}
