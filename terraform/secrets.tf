# Random password for Valkey authentication
resource "random_password" "valkey_auth" {
  length  = 32
  special = true
}

# ── Service Configuration Secret ───────────────────────────────────────────
# The complete forgeproxy config.yaml
resource "aws_secretsmanager_secret" "forgeproxy_config" {
  name_prefix = "${var.name_prefix}/service-config-"
  description = "Forgeproxy service configuration (config.yaml)"

  tags = {
    Name = "${var.name_prefix}-service-config"
  }
}

resource "aws_secretsmanager_secret_version" "forgeproxy_config" {
  secret_id = aws_secretsmanager_secret.forgeproxy_config.id

  secret_string = templatefile("${path.module}/templates/service-config.yaml.tpl", {
    config_reload_enabled                         = var.config_reload_enabled
    config_reload_interval_secs                   = var.config_reload_interval_secs
    background_work_enabled                       = var.background_work_enabled
    background_work_defer_when_active_clones      = var.background_work_defer_when_active_clones
    background_work_cpu_busy_100ms_high_watermark = var.background_work_cpu_busy_100ms_high_watermark
    background_work_load_1m_per_cpu_high_watermark = (
      var.background_work_load_1m_per_cpu_high_watermark
    )
    background_work_retry_interval_secs            = var.background_work_retry_interval_secs
    background_work_max_defer_retries              = var.background_work_max_defer_retries
    background_work_max_defer_secs                 = var.background_work_max_defer_secs
    upstream_hostname                              = var.upstream_hostname
    upstream_api_url                               = var.upstream_api_url
    upstream_git_url_base                          = coalesce(var.upstream_git_url_base, "https://${var.upstream_hostname}")
    backend_type                                   = var.backend_type
    delegated_repositories                         = var.delegated_repositories
    valkey_private_ip                              = aws_instance.valkey.private_ip
    valkey_enable_tls                              = local.valkey_tls_enable
    backend_port                                   = local.backend_port
    bundle_bucket                                  = aws_s3_bucket.bundle.id
    s3_bundle_prefix                               = var.s3_bundle_prefix
    aws_region                                     = var.aws_region
    s3_use_fips                                    = var.s3_use_fips
    s3_presigned_url_ttl                           = var.s3_presigned_url_ttl
    local_cache_max_percent                        = var.local_cache_max_percent
    eviction_policy                                = var.eviction_policy
    auth_ssh_user_lookup_cache_ttl                 = var.auth_ssh_user_lookup_cache_ttl
    auth_ssh_repo_access_cache_ttl                 = var.auth_ssh_repo_access_cache_ttl
    prepare_published_generation_indexes           = var.prepare_published_generation_indexes
    generation_coalescing_window_secs              = var.generation_coalescing_window_secs
    global_short_circuit_upstream_secs             = var.global_short_circuit_upstream_secs
    request_wait_for_local_catch_up_secs           = var.request_wait_for_local_catch_up_secs
    request_wait_for_active_local_catch_up_secs    = var.request_wait_for_active_local_catch_up_secs
    request_time_s3_restore_secs                   = var.request_time_s3_restore_secs
    generation_publish_secs                        = var.generation_publish_secs
    local_upload_pack_first_byte_secs              = var.local_upload_pack_first_byte_secs
    repo_update_mode                               = var.repo_update_mode
    repo_update_large_repo_size_bytes_threshold    = var.repo_update_large_repo_size_bytes_threshold
    repo_update_large_repo_ref_count_threshold     = var.repo_update_large_repo_ref_count_threshold
    repo_update_failure_score_threshold            = var.repo_update_failure_score_threshold
    repo_update_delta_workspace_max_physical_ratio = var.repo_update_delta_workspace_max_physical_ratio
    repo_update_overrides                          = var.repo_update_overrides
    max_concurrent_upstream_clones                 = var.max_concurrent_upstream_clones
    max_concurrent_local_upload_packs              = var.max_concurrent_local_upload_packs
    max_concurrent_local_upload_packs_per_repo     = var.max_concurrent_local_upload_packs_per_repo
    max_concurrent_deep_validations                = var.max_concurrent_deep_validations
    local_upload_pack_threads                      = var.local_upload_pack_threads
    index_pack_threads                             = var.index_pack_threads
    pack_cache_enabled                             = var.pack_cache_enabled
    pack_cache_max_percent                         = var.pack_cache_max_percent
    pack_cache_high_water_mark                     = var.pack_cache_high_water_mark
    pack_cache_low_water_mark                      = var.pack_cache_low_water_mark
    pack_cache_eviction_policy                     = var.pack_cache_eviction_policy
    pack_cache_wait_for_inflight_secs              = var.pack_cache_wait_for_inflight_secs
    pack_cache_on_demand_composite_total_secs      = var.pack_cache_on_demand_composite_total_secs
    pack_cache_request_delta_pack_secs             = var.pack_cache_request_delta_pack_secs
    pack_cache_max_concurrent_request_deltas       = var.pack_cache_max_concurrent_request_deltas
    pack_cache_max_concurrent_background_warmings  = var.pack_cache_max_concurrent_background_warmings
    pack_cache_min_response_bytes                  = var.pack_cache_min_response_bytes
    pack_cache_recent_entry_max_age_secs           = var.pack_cache_recent_entry_max_age_secs
    pack_cache_max_recent_repos                    = var.pack_cache_max_recent_repos
    prewarm_enabled                                = var.prewarm_enabled
    prewarm_repos                                  = var.prewarm_repos
    prewarm_max_concurrent                         = var.prewarm_max_concurrent
    prewarm_force_open_secs                        = var.prewarm_force_open_secs
    health_check_timeout_secs                      = var.health_check_timeout_secs
    health_disk_min_available_percent              = var.health_disk_min_available_percent
    bundle_max_concurrent_generations              = var.bundle_max_concurrent_generations
    bundle_pack_threads                            = var.bundle_pack_threads
    bundle_max_incremental_bundles                 = var.bundle_max_incremental_bundles
    metrics_enabled                                = var.metrics_enabled
    metrics_refresh_interval_secs                  = var.metrics_refresh_interval_secs
    logs_enabled                                   = var.logs_enabled
    traces_enabled                                 = var.traces_enabled
    traces_sample_ratio                            = var.traces_sample_ratio
    log_level                                      = var.log_level
    name_prefix                                    = var.name_prefix
    org_creds                                      = var.org_creds
    ghe_key_lookup_enabled                         = local.ghe_key_lookup_enabled
    ghe_key_lookup_url                             = local.ghe_key_lookup_enabled ? "http://${aws_lb.ghe_key_lookup[0].dns_name}:${local.ghe_key_lookup_listen_port}" : ""
  })

  lifecycle {
    # Forgeproxy instances and launch templates consume this version directly.
    # Replacing the secret version must publish the new value before Terraform
    # tries to destroy legacy instance/attachment edges still present in state.
    create_before_destroy = true
  }

  depends_on = [aws_secretsmanager_secret_version.bootstrap_secrets]
}

resource "aws_secretsmanager_secret" "forgeproxy_otel_collector_config" {
  name_prefix = "${var.name_prefix}/otel-collector-config-"
  description = "Forgeproxy OTEL collector configuration"

  tags = {
    Name = "${var.name_prefix}-otel-collector-config"
  }
}

resource "aws_secretsmanager_secret_version" "forgeproxy_otel_collector_config" {
  secret_id = aws_secretsmanager_secret.forgeproxy_otel_collector_config.id

  secret_string = templatefile("${path.module}/templates/otel-collector-config.yaml.tpl", {
    host_metrics_enabled  = var.host_metrics_enabled
    otlp_metrics_enabled  = var.otlp_metrics.endpoint != "" ? true : false
    otlp_metrics_endpoint = var.otlp_metrics.endpoint
    otlp_metrics_protocol = var.otlp_metrics.protocol
    otlp_metrics_interval = var.otlp_metrics.export_interval_secs
    otlp_metrics_username = var.otlp_metrics.basic_auth_username
    otlp_metrics_password = var.otlp_metrics.basic_auth_password
    otlp_logs_enabled     = var.otlp_logs.endpoint != "" ? true : false
    otlp_logs_endpoint    = var.otlp_logs.endpoint
    otlp_logs_protocol    = var.otlp_logs.protocol
    otlp_logs_interval    = var.otlp_logs.export_interval_secs
    otlp_logs_username    = var.otlp_logs.basic_auth_username
    otlp_logs_password    = var.otlp_logs.basic_auth_password
    otlp_traces_enabled   = var.otlp_traces.endpoint != "" ? true : false
    otlp_traces_endpoint  = var.otlp_traces.endpoint
    otlp_traces_protocol  = var.otlp_traces.protocol
    otlp_traces_interval  = var.otlp_traces.export_interval_secs
    otlp_traces_username  = var.otlp_traces.basic_auth_username
    otlp_traces_password  = var.otlp_traces.basic_auth_password
  })
}

# ── Forge Admin Token Secret ──────────────────────────────────────────────
resource "aws_secretsmanager_secret" "forge_admin_token" {
  name_prefix = "${var.name_prefix}/forge-admin-token-"
  description = "Admin token for upstream forge authentication"

  tags = {
    Name = "${var.name_prefix}-forge-admin-token"
  }
}

resource "aws_secretsmanager_secret_version" "forge_admin_token" {
  secret_id = aws_secretsmanager_secret.forge_admin_token.id

  secret_string = trimspace(local.bootstrap_secrets.forge_admin_token)

  depends_on = [aws_secretsmanager_secret_version.bootstrap_secrets]
}

# ── Valkey Auth Token Secret ───────────────────────────────────────────────
resource "aws_secretsmanager_secret" "valkey_auth_token" {
  name_prefix = "${var.name_prefix}/valkey-auth-token-"
  description = "Authentication token for Valkey"

  tags = {
    Name = "${var.name_prefix}-valkey-auth-token"
  }
}

resource "aws_secretsmanager_secret_version" "valkey_auth_token" {
  secret_id = aws_secretsmanager_secret.valkey_auth_token.id

  secret_string = random_password.valkey_auth.result

  depends_on = [aws_secretsmanager_secret_version.bootstrap_secrets]
}

# ── Webhook Secret ────────────────────────────────────────────────────────
resource "aws_secretsmanager_secret" "webhook_secret" {
  name_prefix = "${var.name_prefix}/webhook-secret-"
  description = "Webhook HMAC secret for forge webhook validation"

  tags = {
    Name = "${var.name_prefix}-webhook-secret"
  }
}

resource "aws_secretsmanager_secret_version" "webhook_secret" {
  secret_id = aws_secretsmanager_secret.webhook_secret.id

  secret_string = trimspace(local.bootstrap_secrets.webhook_secret)

  depends_on = [aws_secretsmanager_secret_version.bootstrap_secrets]
}

# ── nginx upstream hostname secret ────────────────────────────────────────
resource "aws_secretsmanager_secret" "nginx_upstream_hostname" {
  name_prefix = "${var.name_prefix}/nginx-upstream-hostname-"
  description = "nginx upstream hostname (written to runtime config)"

  tags = {
    Name = "${var.name_prefix}-nginx-upstream-hostname"
  }
}

resource "aws_secretsmanager_secret_version" "nginx_upstream_hostname" {
  secret_id = aws_secretsmanager_secret.nginx_upstream_hostname.id

  secret_string = var.upstream_hostname
}

# ── nginx upstream port secret ────────────────────────────────────────────
resource "aws_secretsmanager_secret" "nginx_upstream_port" {
  name_prefix = "${var.name_prefix}/nginx-upstream-port-"
  description = "nginx upstream port (written to runtime config)"

  tags = {
    Name = "${var.name_prefix}-nginx-upstream-port"
  }
}

resource "aws_secretsmanager_secret_version" "nginx_upstream_port" {
  secret_id = aws_secretsmanager_secret.nginx_upstream_port.id

  secret_string = tostring(var.upstream_port)
}

# ── nginx upstream SSH port secret ────────────────────────────────────────
resource "aws_secretsmanager_secret" "nginx_upstream_ssh_port" {
  name_prefix = "${var.name_prefix}/nginx-upstream-ssh-port-"
  description = "nginx upstream SSH port for emergency bypass (written to runtime config)"

  tags = {
    Name = "${var.name_prefix}-nginx-upstream-ssh-port"
  }
}

resource "aws_secretsmanager_secret_version" "nginx_upstream_ssh_port" {
  secret_id = aws_secretsmanager_secret.nginx_upstream_ssh_port.id

  secret_string = tostring(var.upstream_ssh_port)
}

# ── nginx TLS Certificate Secret ──────────────────────────────────────────
resource "aws_secretsmanager_secret" "nginx_tls_cert" {
  name_prefix = "${var.name_prefix}/nginx-tls-cert-"
  description = "nginx TLS certificate (public part)"

  tags = {
    Name = "${var.name_prefix}-nginx-tls-cert"
  }
}

resource "aws_secretsmanager_secret_version" "nginx_tls_cert" {
  secret_id = aws_secretsmanager_secret.nginx_tls_cert.id

  secret_string = tls_self_signed_cert.nginx.cert_pem
}

# ── nginx TLS Key Secret ──────────────────────────────────────────────────
resource "aws_secretsmanager_secret" "nginx_tls_key" {
  name_prefix = "${var.name_prefix}/nginx-tls-key-"
  description = "nginx TLS private key"

  tags = {
    Name = "${var.name_prefix}-nginx-tls-key"
  }
}

resource "aws_secretsmanager_secret_version" "nginx_tls_key" {
  secret_id = aws_secretsmanager_secret.nginx_tls_key.id

  secret_string = tls_private_key.nginx.private_key_pem
}

# ── Valkey TLS Certificate Secret ──────────────────────────────────────────
resource "aws_secretsmanager_secret" "valkey_tls_cert" {
  count = local.valkey_tls_enable ? 1 : 0

  name_prefix = "${var.name_prefix}/valkey-tls-cert-"
  description = "Valkey TLS certificate (public part)"

  tags = {
    Name = "${var.name_prefix}-valkey-tls-cert"
  }
}

resource "aws_secretsmanager_secret_version" "valkey_tls_cert" {
  count = local.valkey_tls_enable ? 1 : 0

  secret_id = aws_secretsmanager_secret.valkey_tls_cert[0].id

  secret_string = tls_locally_signed_cert.valkey[0].cert_pem
}

# ── Valkey TLS Key Secret ──────────────────────────────────────────────────
resource "aws_secretsmanager_secret" "valkey_tls_key" {
  count = local.valkey_tls_enable ? 1 : 0

  name_prefix = "${var.name_prefix}/valkey-tls-key-"
  description = "Valkey TLS private key"

  tags = {
    Name = "${var.name_prefix}-valkey-tls-key"
  }
}

resource "aws_secretsmanager_secret_version" "valkey_tls_key" {
  count = local.valkey_tls_enable ? 1 : 0

  secret_id = aws_secretsmanager_secret.valkey_tls_key[0].id

  secret_string = tls_private_key.valkey[0].private_key_pem
}

# ── Valkey TLS CA Certificate Secret ───────────────────────────────────────
resource "aws_secretsmanager_secret" "valkey_tls_ca" {
  count = local.valkey_tls_enable ? 1 : 0

  name_prefix = "${var.name_prefix}/valkey-tls-ca-"
  description = "Valkey TLS CA certificate"

  tags = {
    Name = "${var.name_prefix}-valkey-tls-ca"
  }
}

resource "aws_secretsmanager_secret_version" "valkey_tls_ca" {
  count = local.valkey_tls_enable ? 1 : 0

  secret_id = aws_secretsmanager_secret.valkey_tls_ca[0].id

  secret_string = tls_self_signed_cert.ca.cert_pem
}

# ── Organization Credential Secrets ──────────────────────────────────────
# One secret per organization in var.org_creds
resource "aws_secretsmanager_secret" "org_creds" {
  for_each = {
    for org in var.org_creds : org.name => org
  }

  name_prefix = "${var.name_prefix}/creds-${each.value.name}-"
  description = "Credentials for organization: ${each.value.name}"

  tags = {
    Name = "${var.name_prefix}-creds-${each.value.name}"
  }
}

resource "aws_secretsmanager_secret_version" "org_creds" {
  for_each = {
    for org in var.org_creds : org.name => org
  }

  secret_id = aws_secretsmanager_secret.org_creds[each.key].id

  secret_string = trimspace(local.bootstrap_org_credentials[each.key])

  depends_on = [aws_secretsmanager_secret_version.bootstrap_secrets]
}

# ── ghe-key-lookup Runtime Config Secret ───────────────────────────────────
resource "aws_secretsmanager_secret" "ghe_key_lookup_config" {
  count = local.ghe_key_lookup_enabled ? 1 : 0

  name_prefix = "${var.name_prefix}/ghe-key-lookup-config-"
  description = "Runtime TOML config for ghe-key-lookup sidecar"

  tags = {
    Name = "${var.name_prefix}-ghe-key-lookup-config"
  }
}

resource "aws_secretsmanager_secret_version" "ghe_key_lookup_config" {
  count = local.ghe_key_lookup_enabled ? 1 : 0

  secret_id = aws_secretsmanager_secret.ghe_key_lookup_config[0].id
  secret_string = templatefile("${path.module}/templates/ghe-key-lookup-config.toml.tpl", {
    listen               = "0.0.0.0:${local.ghe_key_lookup_listen_port}"
    identity_keyring_key = "GHE_KEY_LOOKUP_IDENTITY"
    identity_env_var     = var.closure_variant == "dev" ? "GHE_KEY_LOOKUP_IDENTITY_PEM" : ""
    identity_file        = var.closure_variant == "dev" ? "/run/ghe-key-lookup/admin-key" : ""
    ssh_user             = var.ghe_key_lookup_ssh_user
    ssh_target_endpoint  = var.ghe_key_lookup_ssh_target_endpoint
    ssh_port             = var.ghe_key_lookup_ssh_port
    ghe_url              = trimspace(var.ghe_key_lookup_ghe_url)
  })

  depends_on = [aws_secretsmanager_secret_version.bootstrap_secrets]
}

# ── ghe-key-lookup Admin Key Secret ────────────────────────────────────────
resource "aws_secretsmanager_secret" "ghe_key_lookup_admin_key" {
  count = local.ghe_key_lookup_enabled ? 1 : 0

  name_prefix = "${var.name_prefix}/ghe-key-lookup-admin-key-"
  description = "SSH private key used by ghe-key-lookup to reach the GHE admin console"

  tags = {
    Name = "${var.name_prefix}-ghe-key-lookup-admin-key"
  }
}

resource "aws_secretsmanager_secret_version" "ghe_key_lookup_admin_key" {
  count = local.ghe_key_lookup_enabled ? 1 : 0

  secret_id     = aws_secretsmanager_secret.ghe_key_lookup_admin_key[0].id
  secret_string = trimspace(local.bootstrap_secrets.ghe_key_lookup_admin_key)

  depends_on = [aws_secretsmanager_secret_version.bootstrap_secrets]
}
