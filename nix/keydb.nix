{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.keydb;

  keydbConfig = pkgs.writeText "keydb.conf" ''
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
    dbfilename keydb-dump.rdb
    dir /var/lib/keydb

    # ── Memory management ──────────────────────────────────────────────
    maxmemory ${cfg.maxMemory}
    maxmemory-policy allkeys-lfu

    # ── Logging ────────────────────────────────────────────────────────
    loglevel notice
    logfile /var/log/keydb/keydb.log

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
  options.services.keydb = {
    enable = lib.mkEnableOption "Valkey server (Redis-compatible)";

    tls = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Enable TLS for KeyDB.";
      };

      certFile = lib.mkOption {
        type = lib.types.path;
        default = "/var/lib/keydb/tls/cert.pem";
        description = "Path to the TLS certificate for KeyDB.";
      };

      keyFile = lib.mkOption {
        type = lib.types.path;
        default = "/var/lib/keydb/tls/key.pem";
        description = "Path to the TLS private key for KeyDB.";
      };

      caFile = lib.mkOption {
        type = lib.types.path;
        default = "/var/lib/keydb/tls/ca.pem";
        description = "Path to the TLS CA certificate for KeyDB.";
      };
    };

    requirePass = lib.mkOption {
      type = lib.types.str;
      default = "CHANGE_ME_USE_SOPS_OR_SECRETS_MANAGER";
      description = ''
        Password required to authenticate to KeyDB.
        In production this MUST come from a secrets manager.
      '';
    };

    maxMemory = lib.mkOption {
      type = lib.types.str;
      default = "2gb";
      description = "Maximum memory KeyDB is allowed to use.";
    };

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/keydb";
      description = "Directory for KeyDB data files (RDB snapshots).";
    };

    extraConfFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Optional second configuration file to pass to keydb-server.
        This allows runtime configuration overrides (e.g., requirepass).
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "keydb";
      description = "System user to run the KeyDB service.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "keydb";
      description = "System group for the KeyDB service.";
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
    environment.etc."keydb/keydb.conf" = {
      source = keydbConfig;
      mode = "0640";
      user = cfg.user;
      group = cfg.group;
    };

    # ── systemd service ────────────────────────────────────────────────
    systemd.services.keydb = {
      description = "Valkey Server";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;

        ExecStart = "${pkgs.valkey}/bin/valkey-server /etc/keydb/keydb.conf";

        Restart = "on-failure";
        RestartSec = 5;

        StateDirectory = "keydb";
        RuntimeDirectory = "keydb";

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
          "/var/log/keydb"
        ]
        ++ lib.optionals cfg.tls.enable [
          "/var/lib/keydb/tls"
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
      "d /var/log/keydb 0750 ${cfg.user} ${cfg.group} -"
    ]
    ++ lib.optionals cfg.tls.enable [
      "d /var/lib/keydb/tls 0750 ${cfg.user} ${cfg.group} -"
    ];
  };
}
