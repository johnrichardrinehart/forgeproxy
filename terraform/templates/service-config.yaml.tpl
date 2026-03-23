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
  bundle_uri_base_url: "https://${proxy_fqdn}/bundles"

valkey:
  endpoint: "${valkey_private_ip}:${valkey_enable_tls ? "6380" : "6379"}"
  tls: ${valkey_enable_tls}
%{ if valkey_enable_tls ~}
  ca_cert_file: "/run/forgeproxy/valkey-ca.pem"
%{ endif ~}
  auth_token_env: "VALKEY_AUTH_TOKEN"

auth:
  webhook_secret_env: "FORGE_WEBHOOK_SECRET"

storage:
  local:
    path: "/var/cache/forgeproxy/repos"
    max_bytes: ${local_cache_max_bytes}
    eviction_policy: "${eviction_policy}"
  s3:
    bucket: "${bundle_bucket}"
    prefix: "${s3_bundle_prefix}"
    region: "${aws_region}"
    use_fips: ${s3_use_fips}
    presigned_url_ttl: ${s3_presigned_url_ttl}

observability:
  metrics:
    prometheus:
      enabled: true
  logs:
    journald:
      enabled: true
  traces:
    enabled: ${otlp_traces_enabled}
    sample_ratio: 1.0
  exporters:
    otlp:
      metrics:
        enabled: ${otlp_metrics_enabled}
        endpoint: "${otlp_metrics_endpoint}"
        protocol: "${otlp_metrics_protocol}"
        export_interval_secs: ${otlp_metrics_interval}
        auth:
          basic:
            username: "${otlp_metrics_username}"
            password: "${otlp_metrics_password}"
      logs:
        enabled: ${otlp_logs_enabled}
        endpoint: "${otlp_logs_endpoint}"
        protocol: "${otlp_logs_protocol}"
        export_interval_secs: ${otlp_logs_interval}
        auth:
          basic:
            username: "${otlp_logs_username}"
            password: "${otlp_logs_password}"
      traces:
        enabled: ${otlp_traces_enabled}
        endpoint: "${otlp_traces_endpoint}"
        protocol: "${otlp_traces_protocol}"
        export_interval_secs: ${otlp_traces_interval}
        auth:
          basic:
            username: "${otlp_traces_username}"
            password: "${otlp_traces_password}"

logging:
  level: "${log_level}"
