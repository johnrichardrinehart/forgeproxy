{
  config,
  pkgs,
  lib,
  ...
}:

let
  awsValkeyAuthProvider = pkgs.writeShellScript "valkey-aws-auth-provider" ''
    set -euo pipefail

    # ── Read SM_PREFIX from EC2 user_data ─────────────────────────────
    _IMDS_TOKEN=$(${pkgs.curl}/bin/curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
    _USER_DATA=$(${pkgs.curl}/bin/curl -sf -H "X-aws-ec2-metadata-token: $_IMDS_TOKEN" "http://169.254.169.254/latest/user-data" || true)
    SM_PREFIX=$(printf '%s\n' "$_USER_DATA" | ${pkgs.gnused}/bin/sed -n 's/^# SM_PREFIX=//p' | ${pkgs.coreutils}/bin/head -n1)
    if [ -z "$SM_PREFIX" ]; then
      SM_PREFIX=$(printf '%s' "$_USER_DATA" | ${pkgs.coreutils}/bin/tr -d '\r\n')
    fi
    if [ -z "$SM_PREFIX" ] || [ "$SM_PREFIX" = "{ ... }: {}" ]; then
      echo "FATAL: Could not resolve SM_PREFIX from EC2 user_data" >&2
      exit 1
    fi

    # ── Resolve secret names under SM_PREFIX (handles name_prefix random suffix) ──
    ALL_SECRETS=$(${pkgs.awscli2}/bin/aws secretsmanager list-secrets \
      --filters "Key=name,Values=''${SM_PREFIX}/" \
      --query 'SecretList[].Name' --output json)

    resolve() {
      echo "$ALL_SECRETS" | ${pkgs.jq}/bin/jq -r --arg p "''${SM_PREFIX}/$1" \
        '[.[] | select(startswith($p))][0]'
    }

    fetch() {
      ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
        --secret-id "$(resolve "$1")" --query 'SecretString' --output text
    }

    AUTH_TOKEN=$(fetch valkey-auth-token)
    EXISTING_ID=$(${pkgs.keyutils}/bin/keyctl search @u user "VALKEY_AUTH_TOKEN" 2>/dev/null || true)
    if [ -n "$EXISTING_ID" ]; then
      printf %s "$AUTH_TOKEN" | ${pkgs.keyutils}/bin/keyctl pupdate "$EXISTING_ID"
    else
      printf %s "$AUTH_TOKEN" | ${pkgs.keyutils}/bin/keyctl padd user "VALKEY_AUTH_TOKEN" @u >/dev/null
    fi
  '';

  awsValkeyTlsProvider = pkgs.writeShellScript "valkey-aws-tls-provider" ''
    set -euo pipefail

    # ── Read SM_PREFIX from EC2 user_data ─────────────────────────────
    _IMDS_TOKEN=$(${pkgs.curl}/bin/curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
    _USER_DATA=$(${pkgs.curl}/bin/curl -sf -H "X-aws-ec2-metadata-token: $_IMDS_TOKEN" "http://169.254.169.254/latest/user-data" || true)
    SM_PREFIX=$(printf '%s\n' "$_USER_DATA" | ${pkgs.gnused}/bin/sed -n 's/^# SM_PREFIX=//p' | ${pkgs.coreutils}/bin/head -n1)
    if [ -z "$SM_PREFIX" ]; then
      SM_PREFIX=$(printf '%s' "$_USER_DATA" | ${pkgs.coreutils}/bin/tr -d '\r\n')
    fi
    if [ -z "$SM_PREFIX" ] || [ "$SM_PREFIX" = "{ ... }: {}" ]; then
      echo "FATAL: Could not resolve SM_PREFIX from EC2 user_data" >&2
      exit 1
    fi

    # ── Resolve secret names under SM_PREFIX (handles name_prefix random suffix) ──
    ALL_SECRETS=$(${pkgs.awscli2}/bin/aws secretsmanager list-secrets \
      --filters "Key=name,Values=''${SM_PREFIX}/" \
      --query 'SecretList[].Name' --output json)

    resolve() {
      echo "$ALL_SECRETS" | ${pkgs.jq}/bin/jq -r --arg p "''${SM_PREFIX}/$1" \
        '[.[] | select(startswith($p))][0]'
    }

    fetch() {
      ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
        --secret-id "$(resolve "$1")" --query 'SecretString' --output text
    }

    put_key() {
      local key_desc="$1"
      local secret_name="$2"
      local secret_value

      secret_value="$(fetch "$secret_name")"
      existing_id=$(${pkgs.keyutils}/bin/keyctl search @u user "$key_desc" 2>/dev/null || true)
      if [ -n "$existing_id" ]; then
        printf %s "$secret_value" | ${pkgs.keyutils}/bin/keyctl pupdate "$existing_id"
      else
        printf %s "$secret_value" | ${pkgs.keyutils}/bin/keyctl padd user "$key_desc" @u >/dev/null
      fi
    }

    put_key "VALKEY_TLS_CERT" "valkey-tls-cert"
    put_key "VALKEY_TLS_KEY" "valkey-tls-key"
    put_key "VALKEY_TLS_CA" "valkey-tls-ca"
  '';
in
{
  services.valkey.tls.enable = lib.mkDefault true;
  services.valkey.tls.certFile = lib.mkDefault "/run/valkey/tls/cert.pem";
  services.valkey.tls.keyFile = lib.mkDefault "/run/valkey/tls/key.pem";
  services.valkey.tls.caFile = lib.mkDefault "/run/valkey/tls/ca.pem";

  services.valkey-secrets = lib.mkDefault {
    enable = true;
    providerScript = awsValkeyAuthProvider;
  };

  services.valkey-tls = {
    enable = lib.mkDefault config.services.valkey.tls.enable;
    providerScript = awsValkeyTlsProvider;
  };

  systemd.services.valkey = {
    path = lib.mkAfter [ pkgs.keyutils ];
    serviceConfig.KeyringMode = lib.mkDefault "shared";
    serviceConfig.ExecStartPre = lib.mkAfter [
      (pkgs.writeShellScript "valkey-materialize-keyring-secrets" ''
        set -euo pipefail

        mkdir -p /run/valkey/tls
        AUTH_ID=$(keyctl search @u user VALKEY_AUTH_TOKEN)
        CERT_ID=$(keyctl search @u user VALKEY_TLS_CERT)
        KEY_ID=$(keyctl search @u user VALKEY_TLS_KEY)
        CA_ID=$(keyctl search @u user VALKEY_TLS_CA)

        printf 'requirepass %s\n' "$(keyctl pipe "$AUTH_ID")" > /run/valkey/runtime.conf
        keyctl pipe "$CERT_ID" > /run/valkey/tls/cert.pem
        keyctl pipe "$KEY_ID" > /run/valkey/tls/key.pem
        keyctl pipe "$CA_ID" > /run/valkey/tls/ca.pem

        chmod 600 /run/valkey/runtime.conf /run/valkey/tls/key.pem
      '')
    ];
  };
}
