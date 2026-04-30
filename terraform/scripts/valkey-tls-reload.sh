#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${AWS_PROFILE:-}" && -n "${AWS_PROFILE_FALLBACK:-}" ]]; then
  export AWS_PROFILE="${AWS_PROFILE_FALLBACK}"
fi

valkey_tls_enable="${VALKEY_TLS_ENABLE:-false}"
if [[ "${valkey_tls_enable}" != "true" ]]; then
  echo "Valkey TLS disabled; skipping valkey service restart"
  exit 0
fi

aws_region="${AWS_REGION:?AWS_REGION is required}"
valkey_instance_id="${VALKEY_INSTANCE_ID:?VALKEY_INSTANCE_ID is required}"
valkey_service_name="${VALKEY_SERVICE_NAME:-valkey}"
wait_timeout_seconds="${WAIT_TIMEOUT_SECONDS:-600}"

aws_args=(--region "${aws_region}")

require_managed_instance_online() {
  local deadline now ping_status
  deadline="$(( $(date +%s) + wait_timeout_seconds ))"

  echo "Waiting for SSM managed instance status: ${valkey_instance_id}"
  while true; do
    ping_status="$(aws "${aws_args[@]}" ssm describe-instance-information \
      --filters "Key=InstanceIds,Values=${valkey_instance_id}" \
      --query 'InstanceInformationList[0].PingStatus' \
      --output text 2>/dev/null || true)"

    if [[ "${ping_status}" == "Online" ]]; then
      echo "SSM managed instance is online: ${valkey_instance_id}"
      return 0
    fi

    now="$(date +%s)"
    if (( now >= deadline )); then
      echo "Timed out waiting for SSM online status for ${valkey_instance_id}" >&2
      return 1
    fi

    sleep 5
  done
}

wait_for_command() {
  local command_id="$1"
  local deadline now status
  deadline="$(( $(date +%s) + wait_timeout_seconds ))"

  while true; do
    status="$(aws "${aws_args[@]}" ssm get-command-invocation \
      --command-id "${command_id}" \
      --instance-id "${valkey_instance_id}" \
      --query 'Status' \
      --output text 2>/dev/null || true)"

    case "${status}" in
      Success)
        return 0
        ;;
      Pending|InProgress|Delayed|"")
        ;;
      *)
        aws "${aws_args[@]}" ssm get-command-invocation \
          --command-id "${command_id}" \
          --instance-id "${valkey_instance_id}" \
          --query '{Status:Status,ResponseCode:ResponseCode,StandardOutputContent:StandardOutputContent,StandardErrorContent:StandardErrorContent}' \
          --output json || true
        return 1
        ;;
    esac

    now="$(date +%s)"
    if (( now >= deadline )); then
      echo "Timed out waiting for SSM command ${command_id} on ${valkey_instance_id}" >&2
      return 1
    fi

    sleep 3
  done
}

require_managed_instance_online

echo "Restarting systemd service ${valkey_service_name} on valkey instance ${valkey_instance_id}"
command_id="$(
  aws "${aws_args[@]}" ssm send-command \
    --document-name "AWS-RunShellScript" \
    --instance-ids "${valkey_instance_id}" \
    --parameters "commands=[\"systemctl restart ${valkey_service_name}\",\"systemctl is-active ${valkey_service_name}\"]" \
    --query 'Command.CommandId' \
    --output text
)"

if [[ -z "${command_id}" || "${command_id}" == "None" ]]; then
  echo "Failed to start SSM command for valkey service reload" >&2
  exit 1
fi

wait_for_command "${command_id}"
echo "Valkey service ${valkey_service_name} restarted successfully on ${valkey_instance_id}"
