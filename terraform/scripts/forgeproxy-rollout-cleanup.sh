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
      exit 1
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

wait_for_cutover_soak

echo "Reconciling active slot (${active_asg}) to ${desired_count} instances"
aws "${aws_args[@]}" autoscaling update-auto-scaling-group \
  --auto-scaling-group-name "${active_asg}" \
  --min-size "${desired_count}" \
  --desired-capacity "${desired_count}" \
  --max-size "${max_count}"

echo "Scaling inactive slot (${inactive_asg}) down to zero"
aws "${aws_args[@]}" autoscaling update-auto-scaling-group \
  --auto-scaling-group-name "${inactive_asg}" \
  --min-size 0 \
  --desired-capacity 0

echo "Inactive slot ${inactive_asg} requested to scale down"
