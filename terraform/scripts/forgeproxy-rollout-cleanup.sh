#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${AWS_PROFILE:-}" && -n "${AWS_PROFILE_FALLBACK:-}" ]]; then
  export AWS_PROFILE="${AWS_PROFILE_FALLBACK}"
fi

active_slot="${ACTIVE_SLOT:?ACTIVE_SLOT is required}"
desired_count="${DESIRED_COUNT:?DESIRED_COUNT is required}"
max_count="${MAX_COUNT:-${desired_count}}"
blue_asg="${BLUE_ASG_NAME:?BLUE_ASG_NAME is required}"
green_asg="${GREEN_ASG_NAME:?GREEN_ASG_NAME is required}"
aws_region="${AWS_REGION:?AWS_REGION is required}"
nlb_dns_name="${NLB_DNS_NAME:?NLB_DNS_NAME is required}"
client_facing_hostnames="${CLIENT_FACING_HOSTNAMES:?CLIENT_FACING_HOSTNAMES is required}"
cutover_check_interval_seconds="${CUTOVER_CHECK_INTERVAL_SECONDS:?CUTOVER_CHECK_INTERVAL_SECONDS is required}"
cutover_required_consecutive_successes="${CUTOVER_REQUIRED_CONSECUTIVE_SUCCESSES:?CUTOVER_REQUIRED_CONSECUTIVE_SUCCESSES is required}"
cutover_timeout_seconds="${CUTOVER_TIMEOUT_SECONDS:?CUTOVER_TIMEOUT_SECONDS is required}"
forgeproxy_config_secret_arn="${FORGEPROXY_CONFIG_SECRET_ARN:-}"

case "${active_slot}" in
  blue)
    active_asg="${blue_asg}"
    inactive_asg="${green_asg}"
    ;;
  green)
    active_asg="${green_asg}"
    inactive_asg="${blue_asg}"
    ;;
  *)
    echo "unknown ACTIVE_SLOT: ${active_slot}" >&2
    exit 1
    ;;
esac

aws_args=(--region "${aws_region}")

IFS=',' read -r -a rollout_hostnames <<< "${client_facing_hostnames}"

probe_https_endpoint() {
  local hostname="$1"
  local path="$2"
  local body_file
  local status
  local curl_exit=0

  body_file="$(mktemp)"

  status="$(curl \
    --silent \
    --show-error \
    --output "${body_file}" \
    --write-out "%{http_code}" \
    --connect-timeout 10 \
    --max-time 30 \
    --connect-to "${hostname}:443:${nlb_dns_name}:443" \
    "https://${hostname}${path}")" || curl_exit=$?

  if (( curl_exit != 0 )); then
    echo "Probe curl failed for https://${hostname}${path}: exit ${curl_exit}" >&2
    if [[ -s "${body_file}" ]]; then
      echo "Probe response body (first 4096 bytes):" >&2
      head -c 4096 "${body_file}" >&2 || true
      echo >&2
    fi
    rm -f "${body_file}"
    return 1
  fi

  if [[ ! "${status}" =~ ^2[0-9][0-9]$ ]]; then
    echo "Probe returned HTTP ${status} for https://${hostname}${path}" >&2
    if [[ -s "${body_file}" ]]; then
      echo "Probe response body (first 4096 bytes):" >&2
      head -c 4096 "${body_file}" >&2 || true
      echo >&2
    fi
    rm -f "${body_file}"
    return 1
  fi

  rm -f "${body_file}"
}

wait_for_cutover_soak() {
  local consecutive_successes=0
  local deadline
  deadline="$(( $(date +%s) + cutover_timeout_seconds ))"

  echo "Waiting for post-cutover HTTPS soak across ${#rollout_hostnames[@]} hostnames"
  echo "Require ${cutover_required_consecutive_successes} consecutive successful rounds at ${cutover_check_interval_seconds}s intervals"

  while true; do
    local now
    local round_failed=0
    now="$(date +%s)"
    if (( now >= deadline )); then
      echo "Timed out waiting for post-cutover HTTPS soak" >&2
      return 1
    fi

    for hostname in "${rollout_hostnames[@]}"; do
      if ! probe_https_endpoint "${hostname}" "/readyz"; then
        echo "Post-cutover probe failed for https://${hostname}/readyz" >&2
        round_failed=1
        break
      fi
      if ! probe_https_endpoint "${hostname}" "/healthz"; then
        echo "Post-cutover probe failed for https://${hostname}/healthz" >&2
        round_failed=1
        break
      fi
    done

    if (( round_failed == 0 )); then
      consecutive_successes="$(( consecutive_successes + 1 ))"
      echo "Post-cutover soak round ${consecutive_successes}/${cutover_required_consecutive_successes} passed"
      if (( consecutive_successes >= cutover_required_consecutive_successes )); then
        break
      fi
    else
      echo "Resetting soak counter after failed probe round"
      consecutive_successes=0
    fi

    sleep "${cutover_check_interval_seconds}"
  done
}

retry_update_asg() {
  local asg_name="$1"
  local min_size="$2"
  local desired_capacity="$3"
  local max_size="$4"
  local attempts=0
  local max_attempts=5

  while (( attempts < max_attempts )); do
    if aws "${aws_args[@]}" autoscaling update-auto-scaling-group \
      --auto-scaling-group-name "${asg_name}" \
      --min-size "${min_size}" \
      --desired-capacity "${desired_capacity}" \
      --max-size "${max_size}"; then
      return 0
    fi

    attempts="$((attempts + 1))"
    if (( attempts >= max_attempts )); then
      echo "Failed updating ASG ${asg_name} after ${max_attempts} attempts" >&2
      return 1
    fi

    local sleep_seconds
    sleep_seconds="$(( attempts * 5 ))"
    echo "Retrying ASG update for ${asg_name} in ${sleep_seconds}s (attempt $((attempts + 1))/${max_attempts})" >&2
    sleep "${sleep_seconds}"
  done
}

best_effort_cleanup_secret_labels() {
  local secret_arn="$1"
  local label="AWSPREVIOUS"

  if [[ -z "${secret_arn}" ]]; then
    return 0
  fi

  echo "Best-effort secret cleanup: removing stale ${label} labels from ${secret_arn}"
  local versions
  versions="$(aws "${aws_args[@]}" secretsmanager list-secret-version-ids \
    --secret-id "${secret_arn}" \
    --include-deprecated \
    --query "Versions[?contains(VersionStages, '${label}')].VersionId" \
    --output text 2>/dev/null || true)"

  if [[ -z "${versions}" || "${versions}" == "None" ]]; then
    echo "Best-effort secret cleanup: no ${label} versions found"
    return 0
  fi

  local version_id
  for version_id in ${versions}; do
    local attempt=1
    local max_attempts=5
    while (( attempt <= max_attempts )); do
      if aws "${aws_args[@]}" secretsmanager update-secret-version-stage \
        --secret-id "${secret_arn}" \
        --version-stage "${label}" \
        --remove-from-version-id "${version_id}" >/dev/null 2>&1; then
        echo "Best-effort secret cleanup: removed ${label} from ${version_id}"
        break
      fi

      if (( attempt == max_attempts )); then
        echo "Best-effort secret cleanup: unable to remove ${label} from ${version_id} after ${max_attempts} attempts" >&2
        break
      fi

      local sleep_seconds
      sleep_seconds="$(( attempt * 2 ))"
      echo "Best-effort secret cleanup: retry ${attempt}/${max_attempts} for ${version_id} in ${sleep_seconds}s" >&2
      sleep "${sleep_seconds}"
      attempt="$((attempt + 1))"
    done
  done
}

if ! wait_for_cutover_soak; then
  echo "Post-cutover soak did not stabilize; skipping inactive slot scale-down in this pass" >&2
  exit 1
fi

echo "Reconciling active slot (${active_asg}) to ${desired_count} instances"
retry_update_asg "${active_asg}" "${desired_count}" "${desired_count}" "${max_count}"

echo "Scaling inactive slot (${inactive_asg}) down to zero"
retry_update_asg "${inactive_asg}" "0" "0" "${max_count}"

best_effort_cleanup_secret_labels "${forgeproxy_config_secret_arn}"

echo "Inactive slot ${inactive_asg} requested to scale down"
