# ── TLS: Self-signed CA ─────────────────────────────────────────────────────
resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem = tls_private_key.ca.private_key_pem

  subject {
    common_name         = "forgeproxy-ca"
    organization        = "Forgeproxy Internal CA"
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

# ── TLS: Valkey Server Certificate ───────────────────────────────────────────
resource "tls_private_key" "valkey" {
  count = local.valkey_tls_enable ? 1 : 0

  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "valkey" {
  count = local.valkey_tls_enable ? 1 : 0

  private_key_pem = tls_private_key.valkey[0].private_key_pem

  subject {
    common_name         = "valkey"
    organization        = "Forgeproxy"
    organizational_unit = "Engineering"
    country             = "US"
  }

  # Use Valkey instance's private IP as SAN
  dns_names = [
    aws_instance.valkey.private_ip,
    "valkey",
    "valkey.internal",
  ]

  ip_addresses = [
    aws_instance.valkey.private_ip,
  ]
}

resource "tls_locally_signed_cert" "valkey" {
  count = local.valkey_tls_enable ? 1 : 0

  cert_request_pem   = tls_cert_request.valkey[0].cert_request_pem
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
    common_name         = aws_lb.nlb.dns_name
    organization        = "Forgeproxy"
    organizational_unit = "Engineering"
    country             = "US"
  }

  validity_period_hours = 8760 * 5 # 5 years

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
  ]

  # This certificate is only for the internal NLB-to-nginx hop.
  dns_names = [
    aws_lb.nlb.dns_name,
    "localhost",
  ]
}
