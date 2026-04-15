upstream:
  hostname: "${upstream_hostname}"
  api_url: "${upstream_api_url}"
  git_url_base: "${upstream_git_url_base}"
  admin_token_env: "FORGE_ADMIN_TOKEN"
%{ if ghe_key_lookup_enabled ~}
  key_lookup_url: "${ghe_key_lookup_url}"
%{ endif ~}

backend_type: "${backend_type}"

upstream_credentials:
  default_mode: "pat"
  orgs:
%{ for org in org_creds ~}
    "${org.name}":
      mode: "${org.mode}"
      keyring_key_name: "${name_prefix}-creds-${replace(org.name, "/", "-")}"
%{ endfor ~}
  # To add an org without a Terraform re-apply: update this secret directly and
  # create a forgeproxy/creds/<keyring-key> secret; then restart forgeproxy.

proxy:
  ssh_listen: "0.0.0.0:2222"
  http_listen: "127.0.0.1:${backend_port}"

valkey:
  endpoint: "${valkey_private_ip}:${valkey_enable_tls ? "6380" : "6379"}"
  tls: ${valkey_enable_tls}
%{ if valkey_enable_tls ~}
  ca_cert_file: "/run/forgeproxy/valkey-ca.pem"
%{ endif ~}
  auth_token_env: "VALKEY_AUTH_TOKEN"

auth:
  webhook_secret_env: "FORGE_WEBHOOK_SECRET"

clone:
  prepare_published_generation_indexes: ${prepare_published_generation_indexes}
  generation_coalescing_window_secs: ${generation_coalescing_window_secs}
  max_concurrent_local_upload_packs: ${max_concurrent_local_upload_packs}
  max_concurrent_local_upload_packs_per_repo: ${max_concurrent_local_upload_packs_per_repo}

pack_cache:
  enabled: ${pack_cache_enabled}
  max_percent: ${pack_cache_max_percent}
  ttl_secs: ${pack_cache_ttl_secs}
  wait_for_inflight_secs: ${pack_cache_wait_for_inflight_secs}
  min_response_bytes: ${pack_cache_min_response_bytes}

storage:
  local:
    path: "/var/cache/forgeproxy"
    max_bytes: ${local_cache_max_bytes}
    eviction_policy: "${eviction_policy}"
  s3:
    bucket: "${bundle_bucket}"
    prefix: "${s3_bundle_prefix}"
    region: "${aws_region}"
    use_fips: ${s3_use_fips}
    presigned_url_ttl: ${s3_presigned_url_ttl}

bundles:
  pack_threads: ${bundle_pack_threads}
  max_incremental_bundles: ${bundle_max_incremental_bundles}

observability:
  metrics:
    prometheus:
      enabled: ${metrics_enabled}
      refresh_interval_secs: ${metrics_refresh_interval_secs}
  logs:
    journald:
      enabled: ${logs_enabled}
  traces:
    enabled: ${traces_enabled}
    sample_ratio: ${traces_sample_ratio}

logging:
  level: "${log_level}"
