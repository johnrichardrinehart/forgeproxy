# Random password for KeyDB authentication
resource "random_password" "keydb_auth" {
  length  = 32
  special = true
}

# ── Service Configuration Secret ───────────────────────────────────────────
# The complete forgecache config.yaml
resource "aws_secretsmanager_secret" "forgecache_config" {
  name_prefix = "${var.name_prefix}/service-config-"
  description = "Forgecache service configuration (config.yaml)"

  tags = {
    Name = "${var.name_prefix}-service-config"
  }
}

resource "aws_secretsmanager_secret_version" "forgecache_config" {
  secret_id = aws_secretsmanager_secret.forgecache_config.id

  secret_string = templatefile("${path.module}/templates/service-config.yaml.tpl", {
    upstream_hostname     = var.upstream_hostname
    upstream_api_url      = var.upstream_api_url
    backend_type          = var.backend_type
    proxy_fqdn            = var.proxy_fqdn
    keydb_private_ip      = aws_instance.keydb.private_ip
    keydb_enable_tls      = local.keydb_tls_enable
    bundle_bucket         = aws_s3_bucket.bundle.id
    s3_bundle_prefix      = var.s3_bundle_prefix
    aws_region            = var.aws_region
    s3_use_fips           = var.s3_use_fips
    s3_presigned_url_ttl  = var.s3_presigned_url_ttl
    local_cache_max_bytes = var.local_cache_max_bytes
    eviction_policy       = var.eviction_policy
    otlp_enabled          = var.otlp_endpoint != "" ? true : false
    otlp_endpoint         = var.otlp_endpoint != "" ? var.otlp_endpoint : ""
    log_level             = var.log_level
    org_creds             = var.org_creds
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

  secret_string = "REPLACE_ME_WITH_ACTUAL_FORGE_ADMIN_TOKEN"

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ── KeyDB Auth Token Secret ───────────────────────────────────────────────
resource "aws_secretsmanager_secret" "keydb_auth_token" {
  name_prefix = "${var.name_prefix}/keydb-auth-token-"
  description = "Authentication token for KeyDB"

  tags = {
    Name = "${var.name_prefix}-keydb-auth-token"
  }
}

resource "aws_secretsmanager_secret_version" "keydb_auth_token" {
  secret_id = aws_secretsmanager_secret.keydb_auth_token.id

  secret_string = random_password.keydb_auth.result
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

  secret_string = "REPLACE_ME_WITH_ACTUAL_WEBHOOK_SECRET"

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ── OTLP Config Secret ────────────────────────────────────────────────────
resource "aws_secretsmanager_secret" "otlp_config" {
  name_prefix = "${var.name_prefix}/otlp-config-"
  description = "OpenTelemetry configuration and credentials"

  tags = {
    Name = "${var.name_prefix}-otlp-config"
  }
}

resource "aws_secretsmanager_secret_version" "otlp_config" {
  secret_id = aws_secretsmanager_secret.otlp_config.id

  secret_string = var.otlp_endpoint != "" ? var.otlp_endpoint : "REPLACE_ME_OR_LEAVE_EMPTY"

  lifecycle {
    ignore_changes = [secret_string]
  }
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

# ── KeyDB TLS Certificate Secret ──────────────────────────────────────────
resource "aws_secretsmanager_secret" "keydb_tls_cert" {
  count = local.keydb_tls_enable ? 1 : 0

  name_prefix = "${var.name_prefix}/keydb-tls-cert-"
  description = "KeyDB TLS certificate (public part)"

  tags = {
    Name = "${var.name_prefix}-keydb-tls-cert"
  }
}

resource "aws_secretsmanager_secret_version" "keydb_tls_cert" {
  count = local.keydb_tls_enable ? 1 : 0

  secret_id = aws_secretsmanager_secret.keydb_tls_cert[0].id

  secret_string = tls_locally_signed_cert.keydb[0].cert_pem
}

# ── KeyDB TLS Key Secret ──────────────────────────────────────────────────
resource "aws_secretsmanager_secret" "keydb_tls_key" {
  count = local.keydb_tls_enable ? 1 : 0

  name_prefix = "${var.name_prefix}/keydb-tls-key-"
  description = "KeyDB TLS private key"

  tags = {
    Name = "${var.name_prefix}-keydb-tls-key"
  }
}

resource "aws_secretsmanager_secret_version" "keydb_tls_key" {
  count = local.keydb_tls_enable ? 1 : 0

  secret_id = aws_secretsmanager_secret.keydb_tls_key[0].id

  secret_string = tls_private_key.keydb[0].private_key_pem
}

# ── KeyDB TLS CA Certificate Secret ───────────────────────────────────────
resource "aws_secretsmanager_secret" "keydb_tls_ca" {
  count = local.keydb_tls_enable ? 1 : 0

  name_prefix = "${var.name_prefix}/keydb-tls-ca-"
  description = "KeyDB TLS CA certificate"

  tags = {
    Name = "${var.name_prefix}-keydb-tls-ca"
  }
}

resource "aws_secretsmanager_secret_version" "keydb_tls_ca" {
  count = local.keydb_tls_enable ? 1 : 0

  secret_id = aws_secretsmanager_secret.keydb_tls_ca[0].id

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

  secret_string = "REPLACE_ME_WITH_${upper(replace(each.value.name, "-", "_"))}_CREDENTIALS"

  lifecycle {
    ignore_changes = [secret_string]
  }
}
