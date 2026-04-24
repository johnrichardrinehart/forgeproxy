#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${AWS_PROFILE:-}" && -n "${AWS_PROFILE_FALLBACK:-}" ]]; then
  export AWS_PROFILE="${AWS_PROFILE_FALLBACK}"
fi

aws_region="${AWS_REGION:?AWS_REGION is required}"
secret_name="${SECRET_NAME:?SECRET_NAME is required}"
local_file_path="${LOCAL_FILE_PATH:?LOCAL_FILE_PATH is required}"

if [[ ! -f "${local_file_path}" ]]; then
  exit 0
fi

aws_args=(--region "${aws_region}")
current_secret="$(aws "${aws_args[@]}" secretsmanager get-secret-value \
  --secret-id "${secret_name}" \
  --query 'SecretString' \
  --output text 2>/dev/null || true)"

if [[ -z "${current_secret}" || "${current_secret}" == "None" ]]; then
  exit 0
fi

canonicalize_json_file() {
  local path="$1"

  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json, sys; print(json.dumps(json.load(open(sys.argv[1])), sort_keys=True, separators=(",", ":")))' "${path}"
    return 0
  fi

  tr -d '[:space:]' <"${path}"
}

canonicalize_json_stdin() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json, sys; print(json.dumps(json.load(sys.stdin), sort_keys=True, separators=(",", ":")))' 
    return 0
  fi

  tr -d '[:space:]'
}

local_canonical="$(canonicalize_json_file "${local_file_path}")"
remote_canonical="$(printf '%s' "${current_secret}" | canonicalize_json_stdin)"

if [[ "${local_canonical}" == "${remote_canonical}" ]]; then
  exit 0
fi

cat >&2 <<EOF
WARNING: local bootstrap secrets file conflicts with the existing Secrets Manager secret.
  Local file: ${local_file_path}
  Secret:     ${secret_name}

Continuing will overwrite the existing bootstrap secret value in AWS with the local file contents.
EOF

if [[ ! -t 0 ]]; then
  cat >&2 <<'EOF'
Conflict detected in a non-interactive session.
Rerun terraform apply interactively and confirm the overwrite, or remove ./forgeproxy-bootstrap-secrets.json to keep the existing Secrets Manager value.
EOF
  exit 1
fi

printf 'Continue and overwrite the existing bootstrap secret? [y/N] ' >&2
read -r response

case "${response}" in
  y|Y|yes|YES|Yes)
    exit 0
    ;;
  *)
    echo "Aborting without overwriting the existing bootstrap secret." >&2
    exit 1
    ;;
esac
