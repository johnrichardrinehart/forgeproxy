{
  config,
  pkgs,
  lib,
  ...
}:

let
  nginxCfg = config.services.forgeproxy-nginx;
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

    write_secret_file_atomic() {
      local secret_id="$1"
      local destination="$2"
      local destination_base
      local destination_dir
      local tmp

      destination_base=$(${pkgs.coreutils}/bin/basename "$destination")
      destination_dir=$(${pkgs.coreutils}/bin/dirname "$destination")
      tmp=$(${pkgs.coreutils}/bin/mktemp "$destination_dir/.$destination_base.XXXXXX")

      if ! ${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
        --secret-id "$secret_id" \
        --query 'SecretString' --output text > "$tmp"; then
        ${pkgs.coreutils}/bin/rm -f "$tmp"
        return 1
      fi
      if ! ${pkgs.coreutils}/bin/chmod 0644 "$tmp"; then
        ${pkgs.coreutils}/bin/rm -f "$tmp"
        return 1
      fi
      if ! ${pkgs.coreutils}/bin/mv -f "$tmp" "$destination"; then
        ${pkgs.coreutils}/bin/rm -f "$tmp"
        return 1
      fi
    }

    # ── Write config.yaml from Secrets Manager ────────────────────────
    # /run/forgeproxy is writable via RuntimeDirectory=forgeproxy;
    # /etc is read-only under ProtectSystem=strict.
    write_secret_file_atomic "$(resolve service-config)" /run/forgeproxy/config.yaml

    OTEL_COLLECTOR_CONFIG_SECRET=$(resolve otel-collector-config)
    if [ "$OTEL_COLLECTOR_CONFIG_SECRET" = "null" ]; then
      rm -f /run/forgeproxy/otel-collector-config.yaml
    else
      write_secret_file_atomic "$OTEL_COLLECTOR_CONFIG_SECRET" /run/forgeproxy/otel-collector-config.yaml
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
                    _IDENTITY=$(${pkgs.curl}/bin/curl -sf -H "X-aws-ec2-metadata-token: $_IMDS_TOKEN" "http://169.254.169.254/latest/dynamic/instance-identity/document")
                    SM_PREFIX=$(printf '%s\n' "$_USER_DATA" | ${pkgs.gnused}/bin/sed -n 's/^# SM_PREFIX=//p' | ${pkgs.coreutils}/bin/head -n1)
                    INSTANCE_ID=$(printf '%s\n' "$_IDENTITY" | ${pkgs.jq}/bin/jq -r '.instanceId')
                    REGION=$(printf '%s\n' "$_IDENTITY" | ${pkgs.jq}/bin/jq -r '.region')
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
                    UPSTREAM_SSH_PORT_SECRET=$(resolve nginx-upstream-ssh-port)
                    if [ "$UPSTREAM_SSH_PORT_SECRET" = "null" ]; then
                      UPSTREAM_SSH_PORT=${toString nginxCfg.upstreamSshPort}
                    else
                      UPSTREAM_SSH_PORT=$(${pkgs.awscli2}/bin/aws secretsmanager get-secret-value \
                        --secret-id "$UPSTREAM_SSH_PORT_SECRET" \
                        --query 'SecretString' --output text)
                    fi
                    DISABLE_TAG_VALUE=$(${pkgs.awscli2}/bin/aws --region "$REGION" ec2 describe-tags \
                      --filters "Name=resource-id,Values=$INSTANCE_ID" "Name=key,Values=forgeproxy-disable" \
                      --query 'Tags[0].Value' --output text 2>/dev/null || true)
                    if [ "$DISABLE_TAG_VALUE" = "true" ]; then
                      FORGEPROXY_DISABLED=true
                      SSH_TARGET="$UPSTREAM:$UPSTREAM_SSH_PORT"
                    else
                      FORGEPROXY_DISABLED=false
                      SSH_TARGET="${nginxCfg.sshProxy.localAddress}:${toString nginxCfg.sshProxy.localPort}"
                    fi
                    echo "forgeproxy-nginx-provider: forgeproxy-disable tag value=''${DISABLE_TAG_VALUE:-missing}; disabled=$FORGEPROXY_DISABLED" >&2

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
    set \$forgeproxy_disabled "$FORGEPROXY_DISABLED";
    EOF

                    # Stream-level variables for SSH traffic.
                    cat > /run/nginx/forgeproxy-stream.conf <<EOF
    map \$time_iso8601 \$forgeproxy_disabled {
      default "$FORGEPROXY_DISABLED";
    }

    map \$time_iso8601 \$forgeproxy_ssh_target {
      default "$SSH_TARGET";
    }
    EOF
  '';

  awsCacheScrubSchedule = pkgs.writeShellScript "forgeproxy-cache-scrub-schedule" ''
        set -euo pipefail

        if ! systemctl cat forgeproxy-cache-scrub.timer >/dev/null 2>&1; then
          exit 0
        fi

        _IMDS_TOKEN=$(${pkgs.curl}/bin/curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
        _USER_DATA=$(${pkgs.curl}/bin/curl -sf -H "X-aws-ec2-metadata-token: $_IMDS_TOKEN" "http://169.254.169.254/latest/user-data" || true)
        CACHE_SCRUB_ON_CALENDAR=$(printf '%s\n' "$_USER_DATA" | ${pkgs.gnused}/bin/sed -n 's/^# FORGEPROXY_CACHE_SCRUB_ON_CALENDAR=//p' | ${pkgs.coreutils}/bin/head -n1)
        CACHE_SCRUB_INTERVAL_SECS=$(printf '%s\n' "$_USER_DATA" | ${pkgs.gnused}/bin/sed -n 's/^# FORGEPROXY_CACHE_SCRUB_INTERVAL_SECS=//p' | ${pkgs.coreutils}/bin/head -n1)

        if [ -z "''${CACHE_SCRUB_ON_CALENDAR:-}" ]; then
          CACHE_SCRUB_ON_CALENDAR="*-*-* 00:00:00 UTC"
        fi
        if [ -z "''${CACHE_SCRUB_INTERVAL_SECS:-}" ]; then
          CACHE_SCRUB_INTERVAL_SECS="86400"
        fi

        if ! [[ "$CACHE_SCRUB_INTERVAL_SECS" =~ ^[0-9]+$ ]]; then
          echo "forgeproxy-cache-scrub-schedule: invalid FORGEPROXY_CACHE_SCRUB_INTERVAL_SECS=$CACHE_SCRUB_INTERVAL_SECS" >&2
          exit 1
        fi

        mkdir -p /run/systemd/system/forgeproxy-cache-scrub.timer.d
        cat > /run/systemd/system/forgeproxy-cache-scrub.timer.d/override.conf <<EOF
    [Timer]
    OnBootSec=
    OnCalendar=$CACHE_SCRUB_ON_CALENDAR
    OnUnitActiveSec=''${CACHE_SCRUB_INTERVAL_SECS}s
    Persistent=true
    EOF

        systemctl daemon-reload
        systemctl restart forgeproxy-cache-scrub.timer
  '';
in
{
  services.forgeproxy-secrets = lib.mkDefault {
    enable = true;
    providerScript = awsForgeProxyProvider;
  };

  systemd.services.forgeproxy = {
    serviceConfig = {
      ExecStartPre = lib.mkAfter [
        (pkgs.writeShellScript "forgeproxy-materialize-keyring-secrets" ''
          set -euo pipefail

          CA_ID=$(keyctl search @u user FORGEPROXY_VALKEY_CA 2>/dev/null || true)
          if [ -n "$CA_ID" ]; then
            keyctl pipe "$CA_ID" > /run/forgeproxy/valkey-ca.pem
          fi
        '')
      ];
      ExecReload = lib.mkAfter [
        (pkgs.writeShellScript "forgeproxy-materialize-keyring-secrets" ''
          set -euo pipefail

          CA_ID=$(keyctl search @u user FORGEPROXY_VALKEY_CA 2>/dev/null || true)
          if [ -n "$CA_ID" ]; then
            keyctl pipe "$CA_ID" > /run/forgeproxy/valkey-ca.pem
          fi
        '')
      ];
    };
  };

  services.forgeproxy-nginx-runtime = lib.mkDefault {
    enable = true;
    providerScript = awsNginxProvider;
    refreshIntervalSec = 15;
  };

  services.forgeproxy-nginx.sshProxy.enable = lib.mkDefault true;

  systemd.services.forgeproxy-cache-scrub-schedule = {
    description = "Apply forgeproxy cache scrub timer schedule from EC2 user-data";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    before = [ "forgeproxy-cache-scrub.timer" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
    };
    script = ''
      exec ${awsCacheScrubSchedule}
    '';
  };
}
