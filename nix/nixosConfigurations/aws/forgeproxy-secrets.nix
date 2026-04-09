{
  config,
  pkgs,
  lib,
  ...
}:

let
  awsForgeProxyProvider = pkgs.writeShellScript "forgeproxy-aws-provider" ''
    set -euo pipefail

    # ── Read SM_PREFIX from EC2 user_data ─────────────────────────────
    _IMDS_TOKEN=$(${pkgs.curl}/bin/curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
    _USER_DATA=$(${pkgs.curl}/bin/curl -sf -H "X-aws-ec2-metadata-token: $_IMDS_TOKEN" "http://169.254.169.254/latest/user-data" || true)
    SM_PREFIX=$(printf '%s\n' "$_USER_DATA" | ${pkgs.gnused}/bin/sed -n 's/^# SM_PREFIX=//p' | ${pkgs.coreutils}/bin/head -n1)
    FORGEPROXY_SSH_HOST_KEY_SECRET_ARN=$(printf '%s\n' "$_USER_DATA" | ${pkgs.gnused}/bin/sed -n 's/^# FORGEPROXY_SSH_HOST_KEY_SECRET_ARN=//p' | ${pkgs.coreutils}/bin/head -n1)
    if [ -z "$SM_PREFIX" ]; then
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

    # ── Write config.yaml from Secrets Manager ────────────────────────
    # /run/forgeproxy is writable via RuntimeDirectory=forgeproxy;
    # /etc is read-only under ProtectSystem=strict.
    ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
      --secret-id "$(resolve service-config)" \
      --query 'SecretString' --output text > /run/forgeproxy/config.yaml

    OTEL_COLLECTOR_CONFIG_SECRET=$(resolve otel-collector-config)
    if [ "$OTEL_COLLECTOR_CONFIG_SECRET" = "null" ]; then
      rm -f /run/forgeproxy/otel-collector-config.yaml
    else
      ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
        --secret-id "$OTEL_COLLECTOR_CONFIG_SECRET" \
        --query 'SecretString' --output text > /run/forgeproxy/otel-collector-config.yaml
    fi

    # ── Write Valkey CA cert (for TLS verification) ─────────────────────
    VALKEY_CA_SECRET=$(resolve valkey-tls-ca)
    if [ "$VALKEY_CA_SECRET" != "null" ]; then
      VALKEY_CA_VALUE=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
        --secret-id "$VALKEY_CA_SECRET" \
        --query 'SecretString' --output text)
      EXISTING_ID=$(${pkgs.keyutils}/bin/keyctl search @u user FORGEPROXY_VALKEY_CA 2>/dev/null || true)
      if [ -n "$EXISTING_ID" ]; then
        printf %s "$VALKEY_CA_VALUE" | ${pkgs.keyutils}/bin/keyctl pupdate "$EXISTING_ID"
      else
        printf %s "$VALKEY_CA_VALUE" | ${pkgs.keyutils}/bin/keyctl padd user FORGEPROXY_VALKEY_CA @u >/dev/null
      fi
    fi

    # ── Load per-org credentials into the kernel keyring ──────────────
    # Discovers all secrets under ''${SM_PREFIX}/creds-<org> dynamically —
    # no hardcoded org list.  Adding an org requires creating a new SM
    # secret, not rebuilding the AMI.
    CRED_SECRETS=$(echo "$ALL_SECRETS" | ${pkgs.jq}/bin/jq -r \
      --arg p "''${SM_PREFIX}/creds-" '.[] | select(startswith($p))')
    for SECRET_NAME in $CRED_SECRETS; do
      SECRET_VALUE=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
        --secret-id "$SECRET_NAME" --query 'SecretString' --output text)
      # Extract org name: strip SM_PREFIX/creds- prefix and Terraform's
      # random suffix (26-char unique ID starting with a digit).
      REMAINDER="''${SECRET_NAME#''${SM_PREFIX}/creds-}"
      ORG_NAME="''${REMAINDER%-[0-9]*}"
      KEY_DESC="''${SM_PREFIX//\//-}-creds-''${ORG_NAME}"
      echo -n "$SECRET_VALUE" | keyctl padd user "$KEY_DESC" @u >/dev/null || true
    done

    # ── Load fixed secrets into keyring ───────────────────────────────
    # Stored under their env-var names so the Rust binary can look them
    # up from the user keyring (same pattern as org credentials).
    declare -A SUFFIX_TO_ENV=(
      [forge-admin-token]=FORGE_ADMIN_TOKEN
      [valkey-auth-token]=VALKEY_AUTH_TOKEN
      [webhook-secret]=FORGE_WEBHOOK_SECRET
    )

    for SUFFIX in "''${!SUFFIX_TO_ENV[@]}"; do
      SECRET_NAME=$(resolve "$SUFFIX")
      SECRET_VALUE=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
        --secret-id "$SECRET_NAME" --query 'SecretString' --output text) || true
      if [ -n "''${SECRET_VALUE}" ]; then
        echo -n "$SECRET_VALUE" | keyctl padd user "''${SUFFIX_TO_ENV[$SUFFIX]}" @u >/dev/null || true
      fi
    done

    if [ -n "$FORGEPROXY_SSH_HOST_KEY_SECRET_ARN" ]; then
      SSH_HOST_KEY=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
        --secret-id "$FORGEPROXY_SSH_HOST_KEY_SECRET_ARN" \
        --query 'SecretString' --output text)
      if [ -z "$SSH_HOST_KEY" ] || [ "$SSH_HOST_KEY" = "None" ]; then
        echo "FATAL: forgeproxy SSH host key secret is empty: $FORGEPROXY_SSH_HOST_KEY_SECRET_ARN" >&2
        exit 1
      fi
      EXISTING_ID=$(${pkgs.keyutils}/bin/keyctl search @u user forgeproxy:ssh_host_key 2>/dev/null || true)
      if [ -n "$EXISTING_ID" ]; then
        printf %s "$SSH_HOST_KEY" | ${pkgs.keyutils}/bin/keyctl pupdate "$EXISTING_ID"
      else
        printf %s "$SSH_HOST_KEY" | ${pkgs.keyutils}/bin/keyctl padd user forgeproxy:ssh_host_key @u >/dev/null
      fi
    fi
  '';

  awsNginxProvider = pkgs.writeShellScript "forgeproxy-nginx-provider" ''
                    set -euo pipefail

                    # ── Read SM_PREFIX from EC2 user_data ─────────────────────────
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

                    put_key() {
                      local key_desc="$1"
                      local secret_name="$2"
                      local secret_value

                      secret_value=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                        --secret-id "$(resolve "$secret_name")" \
                        --query 'SecretString' --output text)

                      existing_id=$(${pkgs.keyutils}/bin/keyctl search @u user "$key_desc" 2>/dev/null || true)
                      if [ -n "$existing_id" ]; then
                        printf %s "$secret_value" | ${pkgs.keyutils}/bin/keyctl pupdate "$existing_id"
                      else
                        printf %s "$secret_value" | ${pkgs.keyutils}/bin/keyctl padd user "$key_desc" @u >/dev/null
                      fi
                    }

                    UPSTREAM=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                      --secret-id "$(resolve nginx-upstream-hostname)" \
                      --query 'SecretString' --output text)
                    UPSTREAM_PORT=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                      --secret-id "$(resolve nginx-upstream-port)" \
                      --query 'SecretString' --output text)
                    # TLS material for nginx goes into the kernel keyring.
                    put_key "NGINX_TLS_CERT" "nginx-tls-cert"
                    put_key "NGINX_TLS_KEY" "nginx-tls-key"

                    # Upstream block (http-level include)
                    cat > /run/nginx/forgeproxy-upstream.conf <<EOF
    upstream forge-upstream {
      server $UPSTREAM:$UPSTREAM_PORT;
      keepalive 32;
    }
    EOF

                    # Server-level variable (server-level include)
                    cat > /run/nginx/forgeproxy-server.conf <<EOF
    set \$forge_upstream_host "$UPSTREAM";
    EOF
  '';
in
{
  services.forgeproxy-secrets = lib.mkDefault {
    enable = true;
    providerScript = awsForgeProxyProvider;
  };

  systemd.services.forgeproxy = {
    serviceConfig.ExecStartPre = lib.mkAfter [
      (pkgs.writeShellScript "forgeproxy-materialize-keyring-secrets" ''
        set -euo pipefail

        CA_ID=$(keyctl search @u user FORGEPROXY_VALKEY_CA 2>/dev/null || true)
        if [ -n "$CA_ID" ]; then
          keyctl pipe "$CA_ID" > /run/forgeproxy/valkey-ca.pem
        fi
      '')
    ];
  };

  services.forgeproxy-nginx-runtime = lib.mkDefault {
    enable = true;
    providerScript = awsNginxProvider;
  };
}
