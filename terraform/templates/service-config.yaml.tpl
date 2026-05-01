config_reload:
  enabled: ${config_reload_enabled}
  interval_secs: ${config_reload_interval_secs}

background_work:
  enabled: ${background_work_enabled}
  defer_when_active_clones: ${background_work_defer_when_active_clones}
  cpu_busy_100ms_high_watermark: ${background_work_cpu_busy_100ms_high_watermark}
  load_1m_per_cpu_high_watermark: ${background_work_load_1m_per_cpu_high_watermark}
  retry_interval_secs: ${background_work_retry_interval_secs}
  max_defer_retries: ${background_work_max_defer_retries}
  max_defer_secs: ${background_work_max_defer_secs}

upstream:
  hostname: "${upstream_hostname}"
  api_url: "${upstream_api_url}"
  git_url_base: "${upstream_git_url_base}"
  admin_token_env: "FORGE_ADMIN_TOKEN"
%{ if ghe_key_lookup_enabled ~}
  key_lookup_url: "${ghe_key_lookup_url}"
%{ endif ~}

backend_type: "${backend_type}"

delegated_repositories: ${jsonencode(delegated_repositories)}

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
  ssh_listen: "127.0.0.1:2223"
  http_listen: "127.0.0.1:${backend_port}"

valkey:
  endpoint: "${valkey_private_ip}:${valkey_enable_tls ? "6380" : "6379"}"
  tls: ${valkey_enable_tls}
%{ if valkey_enable_tls ~}
  ca_cert_file: "/run/forgeproxy/valkey-ca.pem"
%{ endif ~}
  auth_token_env: "VALKEY_AUTH_TOKEN"

auth:
  ssh_user_lookup_cache_ttl: ${auth_ssh_user_lookup_cache_ttl}
  ssh_repo_access_cache_ttl: ${auth_ssh_repo_access_cache_ttl}
  webhook_secret_env: "FORGE_WEBHOOK_SECRET"

clone:
  prepare_published_generation_indexes: ${prepare_published_generation_indexes}
  generation_coalescing_window_secs: ${generation_coalescing_window_secs}
  global_short_circuit_upstream_secs: ${global_short_circuit_upstream_secs}
  request_wait_for_local_catch_up_secs: ${request_wait_for_local_catch_up_secs}
  request_wait_for_active_local_catch_up_secs: ${request_wait_for_active_local_catch_up_secs}
  request_time_s3_restore_secs: ${request_time_s3_restore_secs}
  generation_publish_secs: ${generation_publish_secs}
  local_upload_pack_first_byte_secs: ${local_upload_pack_first_byte_secs}
  # Request path: every local disk serve acquires these before spawning git upload-pack.
  # Higher values improve parallel clone/fetch throughput but allow more concurrent pack-objects CPU.
  max_concurrent_upstream_clones: ${max_concurrent_upstream_clones}
  max_concurrent_local_upload_packs: ${max_concurrent_local_upload_packs}
  max_concurrent_local_upload_packs_per_repo: ${max_concurrent_local_upload_packs_per_repo}
  max_concurrent_deep_validations: ${max_concurrent_deep_validations}
  # Request path: local git upload-pack inherits this as pack.threads for pack generation.
  local_upload_pack_threads: ${local_upload_pack_threads}
  # Request-adjacent CPU: tee imports and pack-cache indexing use this git index-pack thread cap.
  index_pack_threads: ${index_pack_threads}

pack_cache:
  enabled: ${pack_cache_enabled}
  max_percent: ${pack_cache_max_percent}
  high_water_mark: ${pack_cache_high_water_mark}
  low_water_mark: ${pack_cache_low_water_mark}
  eviction_policy: "${pack_cache_eviction_policy}"
  wait_for_inflight_secs: ${pack_cache_wait_for_inflight_secs}
  on_demand_composite_total_secs: ${pack_cache_on_demand_composite_total_secs}
  request_delta_pack_secs: ${pack_cache_request_delta_pack_secs}
  max_concurrent_request_deltas: ${pack_cache_max_concurrent_request_deltas}
  max_concurrent_background_warmings: ${pack_cache_max_concurrent_background_warmings}
  min_response_bytes: ${pack_cache_min_response_bytes}
  recent_entry_max_age_secs: ${pack_cache_recent_entry_max_age_secs}
  max_recent_repos: ${pack_cache_max_recent_repos}

prewarm:
  enabled: ${prewarm_enabled}
  repos: ${jsonencode(prewarm_repos)}
  max_concurrent: ${prewarm_max_concurrent}
  force_open_secs: ${prewarm_force_open_secs}

health:
  check_timeout_secs: ${health_check_timeout_secs}
  disk_min_available_percent: ${health_disk_min_available_percent}

storage:
  local:
    path: "/var/cache/forgeproxy"
    max_percent: ${local_cache_max_percent}
    eviction_policy: "${eviction_policy}"
  s3:
    bucket: "${bundle_bucket}"
    prefix: "${s3_bundle_prefix}"
    region: "${aws_region}"
    use_fips: ${s3_use_fips}
    presigned_url_ttl: ${s3_presigned_url_ttl}

repo_update:
  mode: "${repo_update_mode}"
  large_repo_size_bytes_threshold: ${repo_update_large_repo_size_bytes_threshold}
  large_repo_ref_count_threshold: ${repo_update_large_repo_ref_count_threshold}
  failure_score_threshold: ${repo_update_failure_score_threshold}
  delta_workspace_max_physical_ratio: ${repo_update_delta_workspace_max_physical_ratio}

%{ if length(repo_update_overrides) > 0 ~}
repo_overrides:
%{ for repo, override in repo_update_overrides ~}
  "${repo}":
    repo_update:
%{ if override.mode != null ~}
      mode: "${override.mode}"
%{ endif ~}
%{ if override.large_repo_size_bytes_threshold != null ~}
      large_repo_size_bytes_threshold: ${override.large_repo_size_bytes_threshold}
%{ endif ~}
%{ if override.large_repo_ref_count_threshold != null ~}
      large_repo_ref_count_threshold: ${override.large_repo_ref_count_threshold}
%{ endif ~}
%{ if override.failure_score_threshold != null ~}
      failure_score_threshold: ${override.failure_score_threshold}
%{ endif ~}
%{ if override.delta_workspace_max_physical_ratio != null ~}
      delta_workspace_max_physical_ratio: ${override.delta_workspace_max_physical_ratio}
%{ endif ~}
%{ endfor ~}
%{ endif ~}

bundles:
  # Used for bundle generation, background bitmap/MIDX preparation, and request-time pack-cache deltas.
  max_concurrent_generations: ${bundle_max_concurrent_generations}
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
