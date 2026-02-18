# ── TLS: Self-signed CA ─────────────────────────────────────────────────────
resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem = tls_private_key.ca.private_key_pem

  subject {
    common_name         = "forgecache-ca"
    organization        = "Forgecache Internal CA"
    organizational_unit = "Engineering"
    country             = "US"
  }

  validity_period_hours = 8760 * 10 # 10 years

  is_ca_certificate = true

  allowed_uses = [
    "cert_signing",
    "crl_signing",
  ]
}

# ── TLS: KeyDB Server Certificate ───────────────────────────────────────────
resource "tls_private_key" "keydb" {
  count = var.keydb_enable_tls ? 1 : 0

  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "keydb" {
  count = var.keydb_enable_tls ? 1 : 0

  private_key_pem = tls_private_key.keydb[0].private_key_pem

  subject {
    common_name         = "keydb"
    organization        = "Forgecache"
    organizational_unit = "Engineering"
    country             = "US"
  }

  # Use KeyDB instance's private IP as SAN
  dns_names = [
    aws_instance.keydb.private_ip,
    "keydb",
    "keydb.internal",
  ]

  ip_addresses = [
    aws_instance.keydb.private_ip,
  ]
}

resource "tls_locally_signed_cert" "keydb" {
  count = var.keydb_enable_tls ? 1 : 0

  cert_request_pem   = tls_cert_request.keydb[0].cert_request_pem
  ca_private_key_pem = tls_private_key.ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca.cert_pem

  validity_period_hours = 8760 * 5 # 5 years

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
  ]
}

# ── TLS: nginx Certificate ──────────────────────────────────────────────────
resource "tls_private_key" "nginx" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "nginx" {
  private_key_pem = tls_private_key.nginx.private_key_pem

  subject {
    common_name         = var.proxy_fqdn
    organization        = "Forgecache"
    organizational_unit = "Engineering"
    country             = "US"
  }

  validity_period_hours = 8760 * 5 # 5 years

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
  ]

  # Include the proxy FQDN and NLB DNS name as SANs
  dns_names = [
    var.proxy_fqdn,
    aws_lb.nlb.dns_name,
    "localhost",
  ]
}
