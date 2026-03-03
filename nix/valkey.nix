{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.valkey;

  valkeyConfig = pkgs.writeText "valkey.conf" ''
    # ── Network ────────────────────────────────────────────────────────
    bind 0.0.0.0
    port 6379
    protected-mode yes

    ${lib.optionalString cfg.tls.enable ''
      # ── TLS ────────────────────────────────────────────────────────────
      tls-port 6380
      tls-cert-file ${cfg.tls.certFile}
      tls-key-file ${cfg.tls.keyFile}
      tls-ca-cert-file ${cfg.tls.caFile}
      tls-protocols "TLSv1.2 TLSv1.3"
      tls-ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
      tls-ciphersuites "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
      tls-auth-clients no
      tls-prefer-server-ciphers yes
    ''}

    # ── Authentication ─────────────────────────────────────────────────
    requirepass ${cfg.requirePass}

    # ── Persistence (RDB snapshots) ────────────────────────────────────
    save 300 10
    save 60 10000
    dbfilename valkey-dump.rdb
    dir /var/lib/valkey

    # ── Memory management ──────────────────────────────────────────────
    maxmemory ${cfg.maxMemory}
    maxmemory-policy allkeys-lfu

    # ── Logging ────────────────────────────────────────────────────────
    loglevel notice
    logfile /var/log/valkey/valkey.log

    # ── Safety ─────────────────────────────────────────────────────────
    rename-command FLUSHALL ""
    rename-command FLUSHDB ""
    rename-command DEBUG ""

    ${lib.optionalString (cfg.extraConfFile != null) ''
      # ── Runtime overrides (e.g., requirepass from Secrets Manager) ──
      include ${cfg.extraConfFile}
    ''}
  '';
in
{
  options.services.valkey = {
    enable = lib.mkEnableOption "Valkey server (Redis-compatible)";

    tls = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Enable TLS for Valkey.";
      };

      certFile = lib.mkOption {
        type = lib.types.path;
        default = "/var/lib/valkey/tls/cert.pem";
        description = "Path to the TLS certificate for Valkey.";
      };

      keyFile = lib.mkOption {
        type = lib.types.path;
        default = "/var/lib/valkey/tls/key.pem";
        description = "Path to the TLS private key for Valkey.";
      };

      caFile = lib.mkOption {
        type = lib.types.path;
        default = "/var/lib/valkey/tls/ca.pem";
        description = "Path to the TLS CA certificate for Valkey.";
      };
    };

    requirePass = lib.mkOption {
      type = lib.types.str;
      default = "CHANGE_ME_USE_SOPS_OR_SECRETS_MANAGER";
      description = ''
        Password required to authenticate to Valkey.
        In production this MUST come from a secrets manager.
      '';
    };

    maxMemory = lib.mkOption {
      type = lib.types.str;
      default = "2gb";
      description = "Maximum memory Valkey is allowed to use.";
    };

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/valkey";
      description = "Directory for Valkey data files (RDB snapshots).";
    };

    extraConfFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Optional second configuration file to pass to valkey-server.
        This allows runtime configuration overrides (e.g., requirepass).
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "valkey";
      description = "System user to run the Valkey service.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "valkey";
      description = "System group for the Valkey service.";
    };
  };

  config = lib.mkIf cfg.enable {
    # ── System user and group ──────────────────────────────────────────
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = cfg.dataDir;
      createHome = true;
      description = "Valkey database server user";
    };

    users.groups.${cfg.group} = { };

    # ── Configuration file ─────────────────────────────────────────────
    environment.etc."valkey/valkey.conf" = {
      source = valkeyConfig;
      mode = "0640";
      user = cfg.user;
      group = cfg.group;
    };

    # ── systemd service ────────────────────────────────────────────────
    systemd.services.valkey = {
      description = "Valkey Server";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;

        ExecStart = "${pkgs.valkey}/bin/valkey-server /etc/valkey/valkey.conf";

        Restart = "on-failure";
        RestartSec = 5;

        StateDirectory = "valkey";
        RuntimeDirectory = "valkey";

        # ── Hardening ──────────────────────────────────────────────
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
        RestrictRealtime = true;

        ReadWritePaths = [
          cfg.dataDir
          "/var/log/valkey"
        ]
        ++ lib.optionals cfg.tls.enable [
          "/var/lib/valkey/tls"
        ];
      };
    };

    # ── Firewall ───────────────────────────────────────────────────────
    networking.firewall = {
      enable = true;
      allowedTCPPorts =
        if cfg.tls.enable then
          [ 6380 ] # TLS port
        else
          [ 6379 ] # plaintext port (use only in private subnets with SG protection)
      ;
    };

    # ── Log directory via tmpfiles ─────────────────────────────────────
    systemd.tmpfiles.rules = [
      "d /var/log/valkey 0750 ${cfg.user} ${cfg.group} -"
    ]
    ++ lib.optionals cfg.tls.enable [
      "d /var/lib/valkey/tls 0750 ${cfg.user} ${cfg.group} -"
    ];
  };
}
