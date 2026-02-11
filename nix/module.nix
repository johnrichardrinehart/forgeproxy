{ config, lib, pkgs, self, ... }:

let
  cfg = config.services.gheproxy;
in
{
  options.services.gheproxy = {
    enable = lib.mkEnableOption "GHE Caching Reverse Proxy service";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.system}.gheproxy;
      description = "The gheproxy package to use.";
    };

    configFile = lib.mkOption {
      type = lib.types.path;
      default = /etc/gheproxy/config.yaml;
      description = "Path to the gheproxy configuration file.";
    };

    secretNames = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      example = [ "gheproxy/ghe-admin-token" "gheproxy/keydb-auth-token" ];
      description = ''
        List of AWS Secrets Manager secret names to fetch at service
        start and load into the Linux kernel keyring.
      '';
    };

    awsRegion = lib.mkOption {
      type = lib.types.str;
      default = "us-east-1";
      description = "AWS region for Secrets Manager API calls.";
    };

    secretsManagerEndpoint = lib.mkOption {
      type = lib.types.str;
      default = "https://secretsmanager-fips.us-east-1.amazonaws.com";
      description = ''
        FIPS-compliant AWS Secrets Manager endpoint URL.
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "gheproxy";
      description = "System user to run the gheproxy service.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "gheproxy";
      description = "System group for the gheproxy service.";
    };

    cacheDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/cache/gheproxy";
      description = "Directory used for gheproxy cache data.";
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      default = "info";
      example = "debug";
      description = "Log verbosity level for the gheproxy binary.";
    };
  };

  config = lib.mkIf cfg.enable {
    # ── System user and group ──────────────────────────────────────────
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = cfg.cacheDir;
      createHome = true;
      description = "GHE Caching Reverse Proxy service user";
    };

    users.groups.${cfg.group} = { };

    # ── systemd service ────────────────────────────────────────────────
    systemd.services.gheproxy = {
      description = "GHE Caching Reverse Proxy";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        RUST_LOG = cfg.logLevel;
        AWS_DEFAULT_REGION = cfg.awsRegion;
      };

      path = with pkgs; [
        awscli2
        keyutils
        jq
        coreutils
      ];

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;

        ExecStartPre = let
          fetchSecretsScript = pkgs.writeShellScript "gheproxy-fetch-secrets" ''
            set -euo pipefail

            ENDPOINT="${cfg.secretsManagerEndpoint}"
            REGION="${cfg.awsRegion}"

            # Create a session keyring for the service if one does not exist.
            keyctl new_session >/dev/null 2>&1 || true

            for SECRET_NAME in ${lib.escapeShellArgs cfg.secretNames}; do
              echo "Fetching secret: $SECRET_NAME"

              SECRET_VALUE=$(aws secretsmanager get-secret-value \
                --secret-id "$SECRET_NAME" \
                --region "$REGION" \
                --endpoint-url "$ENDPOINT" \
                --query 'SecretString' \
                --output text)

              # Derive a keyring key description from the secret name.
              # e.g. "gheproxy/ghe-admin-token" -> "gheproxy-ghe-admin-token"
              KEY_DESC="''${SECRET_NAME//\//-}"

              # Store the secret in the session keyring.
              echo -n "$SECRET_VALUE" | keyctl padd user "$KEY_DESC" @s >/dev/null

              echo "Loaded secret $SECRET_NAME as keyring key '$KEY_DESC'"
            done
          '';
        in
          "+${fetchSecretsScript}";

        ExecStart = "${cfg.package}/bin/gheproxy --config ${cfg.configFile}";

        Restart = "on-failure";
        RestartSec = 5;

        # Directories managed by systemd (created automatically).
        StateDirectory = "gheproxy";
        CacheDirectory = "gheproxy";
        RuntimeDirectory = "gheproxy";

        # ── Hardening ────────────────────────────────────────────────
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        RestrictSUIDSGID = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;

        ReadWritePaths = [
          cfg.cacheDir
        ];
      };
    };

    # ── System packages required at runtime ────────────────────────────
    environment.systemPackages = with pkgs; [
      git
      keyutils
    ];

    # ── AWS Systems Manager agent ──────────────────────────────────────
    services.amazon-ssm-agent.enable = true;

    # ── SSH (temporary -- remove once SSM-only access is confirmed) ────
    services.openssh.enable = true;

    # ── Firewall ───────────────────────────────────────────────────────
    networking.firewall = {
      enable = true;
      allowedTCPPorts = [
        443    # HTTPS / TLS-terminated Git traffic
        2222   # SSH Git transport
        9090   # Prometheus metrics
      ];
    };

    # ── Shared memory sizing ───────────────────────────────────────────
    boot.devShmSize = "64m";
  };
}
