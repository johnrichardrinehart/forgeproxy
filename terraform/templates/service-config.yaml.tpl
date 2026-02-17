upstream:
  hostname: "${upstream_hostname}"
  api_url: "${upstream_api_url}"
  admin_token_env: "FORGE_ADMIN_TOKEN"

backend_type: "${backend_type}"

upstream_credentials:
  default_mode: "pat"
  orgs:
%{ for org in org_creds ~}
    "${org.name}":
      mode: "${org.mode}"
      keyring_key_name: "forgecache-creds-${replace(org.name, "/", "-")}"
%{ endfor ~}
  # To add an org without a Terraform re-apply: update this secret directly and
  # create a forgecache/creds/<keyring-key> secret; then restart forgecache.

proxy:
  ssh_listen: "0.0.0.0:2222"
  http_listen: "127.0.0.1:8080"
  bundle_uri_base_url: "https://${proxy_fqdn}/bundles"

keydb:
  endpoint: "${keydb_private_ip}:6380"
  tls: true
  auth_token_env: "KEYDB_AUTH_TOKEN"

auth:
  webhook_secret_env: "FORGE_WEBHOOK_SECRET"

storage:
  local:
    path: "/var/cache/forgecache/repos"
    max_bytes: ${local_cache_max_bytes}
    eviction_policy: "${eviction_policy}"
  s3:
    bucket: "${bundle_bucket}"
    prefix: "${s3_bundle_prefix}"
    region: "${aws_region}"
    use_fips: ${s3_use_fips}
    presigned_url_ttl: ${s3_presigned_url_ttl}

metrics:
  prometheus:
    enabled: true
  otlp:
    enabled: ${otlp_enabled}
    endpoint: "${otlp_endpoint}"
    protocol: "grpc"
    export_interval_secs: 60

logging:
  level: "${log_level}"
