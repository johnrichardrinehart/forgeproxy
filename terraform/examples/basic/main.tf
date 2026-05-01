# To consume from git instead of a local path, use:
#   source = "git::https://github.com/johnrichardrinehart/forgeproxy.git//terraform?ref=main"
module "forgeproxy" {
  source = "../../"

  flake_ref                 = var.flake_ref
  closure_variant           = var.closure_variant
  disallow_local_nix_builds = var.disallow_local_nix_builds

  aws_region  = var.aws_region
  aws_profile = var.aws_profile
  name_prefix = var.name_prefix

  upstream_hostname     = var.upstream_hostname
  upstream_port         = var.upstream_port
  upstream_ssh_port     = var.upstream_ssh_port
  upstream_api_url      = var.upstream_api_url
  upstream_git_url_base = var.upstream_git_url_base
  backend_type          = var.backend_type

  bundle_bucket_name = var.bundle_bucket_name
  force_destroy      = var.force_destroy

  forgeproxy_instance_type                          = var.forgeproxy_instance_type
  forgeproxy_count                                  = var.forgeproxy_count
  forgeproxy_max_count                              = var.forgeproxy_max_count
  forgeproxy_health_check_grace_period_secs         = var.forgeproxy_health_check_grace_period_secs
  forgeproxy_active_slot                            = var.forgeproxy_active_slot
  forgeproxy_cutover_check_interval_secs            = var.forgeproxy_cutover_check_interval_secs
  forgeproxy_cutover_required_consecutive_successes = var.forgeproxy_cutover_required_consecutive_successes
  forgeproxy_cutover_timeout_secs                   = var.forgeproxy_cutover_timeout_secs
  forgeproxy_root_volume_gb                         = var.forgeproxy_root_volume_gb
  forgeproxy_root_volume_iops                       = var.forgeproxy_root_volume_iops
  forgeproxy_root_volume_throughput_mbps            = var.forgeproxy_root_volume_throughput_mbps
  forgeproxy_cache_volume_enabled                   = var.forgeproxy_cache_volume_enabled
  forgeproxy_cache_volume_gb                        = var.forgeproxy_cache_volume_gb
  forgeproxy_cache_volume_iops                      = var.forgeproxy_cache_volume_iops
  forgeproxy_cache_volume_throughput_mbps           = var.forgeproxy_cache_volume_throughput_mbps
  forgeproxy_ssh_host_key_secret_arn                = var.forgeproxy_ssh_host_key_secret_arn
  forgeproxy_ssh_host_key_kms_key_arn               = var.forgeproxy_ssh_host_key_kms_key_arn

  valkey_instance_type  = var.valkey_instance_type
  valkey_root_volume_gb = var.valkey_root_volume_gb

  enable_ghe_key_lookup              = var.enable_ghe_key_lookup
  ghe_key_lookup_instance_type       = var.ghe_key_lookup_instance_type
  ghe_key_lookup_count               = var.ghe_key_lookup_count
  ghe_key_lookup_root_volume_gb      = var.ghe_key_lookup_root_volume_gb
  ghe_key_lookup_vpc_id              = var.ghe_key_lookup_vpc_id
  ghe_key_lookup_subnet_ids          = var.ghe_key_lookup_subnet_ids
  ghe_key_lookup_security_group_ids  = var.ghe_key_lookup_security_group_ids
  ghe_key_lookup_listen_ports        = var.ghe_key_lookup_listen_ports
  ghe_key_lookup_allowed_cidrs       = var.ghe_key_lookup_allowed_cidrs
  ghe_key_lookup_ssh_target_endpoint = var.ghe_key_lookup_ssh_target_endpoint
  ghe_key_lookup_ghe_url             = var.ghe_key_lookup_ghe_url
  ghe_key_lookup_ssh_user            = var.ghe_key_lookup_ssh_user
  ghe_key_lookup_ssh_port            = var.ghe_key_lookup_ssh_port

  vpc_cidr            = var.vpc_cidr
  public_subnet_cidr  = var.public_subnet_cidr
  private_subnet_cidr = var.private_subnet_cidr

  allowed_client_cidrs          = var.allowed_client_cidrs
  nlb_internal                  = var.nlb_internal
  nlb_tls_cert_arns_by_hostname = var.nlb_tls_cert_arns_by_hostname
  nlb_tls_ssl_policy            = var.nlb_tls_ssl_policy
  metrics_scrape_cidrs          = var.metrics_scrape_cidrs
  ec2_key_pair_name             = var.ec2_key_pair_name

  local_cache_max_percent                       = var.local_cache_max_percent
  eviction_policy                               = var.eviction_policy
  auth_ssh_user_lookup_cache_ttl                = var.auth_ssh_user_lookup_cache_ttl
  auth_ssh_repo_access_cache_ttl                = var.auth_ssh_repo_access_cache_ttl
  config_reload_enabled                         = var.config_reload_enabled
  config_reload_interval_secs                   = var.config_reload_interval_secs
  background_work_enabled                       = var.background_work_enabled
  background_work_defer_when_active_clones      = var.background_work_defer_when_active_clones
  background_work_cpu_busy_100ms_high_watermark = var.background_work_cpu_busy_100ms_high_watermark
  background_work_load_1m_per_cpu_high_watermark = (
    var.background_work_load_1m_per_cpu_high_watermark
  )
  background_work_retry_interval_secs           = var.background_work_retry_interval_secs
  background_work_max_defer_retries             = var.background_work_max_defer_retries
  background_work_max_defer_secs                = var.background_work_max_defer_secs
  generation_coalescing_window_secs             = var.generation_coalescing_window_secs
  global_short_circuit_upstream_secs            = var.global_short_circuit_upstream_secs
  request_wait_for_local_catch_up_secs          = var.request_wait_for_local_catch_up_secs
  request_wait_for_active_local_catch_up_secs   = var.request_wait_for_active_local_catch_up_secs
  request_time_s3_restore_secs                  = var.request_time_s3_restore_secs
  generation_publish_secs                       = var.generation_publish_secs
  local_upload_pack_first_byte_secs             = var.local_upload_pack_first_byte_secs
  delegated_repositories                        = var.delegated_repositories
  max_concurrent_local_upload_packs             = var.max_concurrent_local_upload_packs
  max_concurrent_local_upload_packs_per_repo    = var.max_concurrent_local_upload_packs_per_repo
  local_upload_pack_threads                     = var.local_upload_pack_threads
  index_pack_threads                            = var.index_pack_threads
  pack_cache_enabled                            = var.pack_cache_enabled
  pack_cache_max_percent                        = var.pack_cache_max_percent
  pack_cache_high_water_mark                    = var.pack_cache_high_water_mark
  pack_cache_low_water_mark                     = var.pack_cache_low_water_mark
  pack_cache_eviction_policy                    = var.pack_cache_eviction_policy
  pack_cache_wait_for_inflight_secs             = var.pack_cache_wait_for_inflight_secs
  pack_cache_on_demand_composite_total_secs     = var.pack_cache_on_demand_composite_total_secs
  pack_cache_request_delta_pack_secs            = var.pack_cache_request_delta_pack_secs
  pack_cache_max_concurrent_request_deltas      = var.pack_cache_max_concurrent_request_deltas
  pack_cache_max_concurrent_background_warmings = var.pack_cache_max_concurrent_background_warmings
  pack_cache_min_response_bytes                 = var.pack_cache_min_response_bytes
  pack_cache_recent_entry_max_age_secs          = var.pack_cache_recent_entry_max_age_secs
  pack_cache_max_recent_repos                   = var.pack_cache_max_recent_repos
  prewarm_enabled                               = var.prewarm_enabled
  prewarm_repos                                 = var.prewarm_repos
  prewarm_max_concurrent                        = var.prewarm_max_concurrent
  prewarm_force_open_secs                       = var.prewarm_force_open_secs
  health_check_timeout_secs                     = var.health_check_timeout_secs
  health_disk_min_available_percent             = var.health_disk_min_available_percent

  s3_bundle_prefix     = var.s3_bundle_prefix
  s3_use_fips          = var.s3_use_fips
  s3_presigned_url_ttl = var.s3_presigned_url_ttl

  metrics_enabled                      = var.metrics_enabled
  metrics_refresh_interval_secs        = var.metrics_refresh_interval_secs
  prepare_published_generation_indexes = var.prepare_published_generation_indexes
  bundle_pack_threads                  = var.bundle_pack_threads
  bundle_max_incremental_bundles       = var.bundle_max_incremental_bundles
  logs_enabled                         = var.logs_enabled
  traces_enabled                       = var.traces_enabled
  traces_sample_ratio                  = var.traces_sample_ratio
  log_level                            = var.log_level
  org_creds                            = var.org_creds
  otlp_metrics                         = var.otlp_metrics
  host_metrics_enabled                 = var.host_metrics_enabled
  otlp_logs                            = var.otlp_logs
  otlp_traces                          = var.otlp_traces
}
