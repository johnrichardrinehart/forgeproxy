#!/usr/bin/env bash
set -euo pipefail

retries="${CLEANUP_RETRIES:-3}"
base_delay_secs="${CLEANUP_BASE_DELAY_SECS:-10}"

if ! command -v terraform >/dev/null 2>&1; then
  echo "terraform is required" >&2
  exit 1
fi

state_addresses="$(terraform state list 2>/dev/null || true)"
if [[ -z "${state_addresses}" ]]; then
  echo "No Terraform state found in current directory; nothing to clean up"
  exit 0
fi

target_addresses="$(printf '%s\n' "${state_addresses}" | rg '(null_resource\.forgeproxy_rollout_cleanup|aws_secretsmanager_secret_version\.forgeproxy_config)$' || true)"
if [[ -z "${target_addresses}" ]]; then
  echo "No forgeproxy cleanup targets found in state"
  exit 0
fi

target_args=()
while IFS= read -r addr; do
  [[ -z "${addr}" ]] && continue
  target_args+=("-target=${addr}")
done <<<"${target_addresses}"

attempt=1
while (( attempt <= retries )); do
  echo "Follow-up cleanup apply attempt ${attempt}/${retries}"
  if terraform apply -auto-approve "${target_args[@]}"; then
    echo "Follow-up cleanup succeeded"
    exit 0
  fi

  if (( attempt == retries )); then
    echo "Follow-up cleanup failed after ${retries} attempts" >&2
    exit 1
  fi

  sleep_secs="$(( base_delay_secs * attempt ))"
  echo "Follow-up cleanup failed; retrying in ${sleep_secs}s" >&2
  sleep "${sleep_secs}"
  attempt="$(( attempt + 1 ))"
done
