{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.gheproxy;
in
{
  options.services.gheproxy = {
    enable = lib.mkEnableOption "GHE Caching Reverse Proxy service";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.gheproxy;
      description = "The gheproxy package to use.";
    };

    configFile = lib.mkOption {
      type = lib.types.path;
      default = "/etc/gheproxy/config.yaml";
      description = "Path to the gheproxy configuration file.";
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
      };

      path = [ pkgs.keyutils ];

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;

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
        443 # HTTPS / TLS-terminated Git traffic
        2222 # SSH Git transport
        9090 # Prometheus metrics
      ];
    };

    # ── Shared memory sizing ───────────────────────────────────────────
    boot.devShmSize = "64m";
  };
}
