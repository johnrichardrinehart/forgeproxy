{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.forgecache;
in
{
  options.services.forgecache = {
    enable = lib.mkEnableOption "Git Caching Reverse Proxy service";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.forgecache;
      description = "The forgecache package to use.";
    };

    configFile = lib.mkOption {
      type = lib.types.path;
      default = "/etc/forgecache/config.yaml";
      description = "Path to the forgecache configuration file.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "forgecache";
      description = "System user to run the forgecache service.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "forgecache";
      description = "System group for the forgecache service.";
    };

    cacheDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/cache/forgecache";
      description = "Directory used for forgecache cache data.";
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      default = "info";
      example = "debug";
      description = "Log verbosity level for the forgecache binary.";
    };
  };

  config = lib.mkIf cfg.enable {
    # ── System user and group ──────────────────────────────────────────
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = cfg.cacheDir;
      createHome = true;
      description = "Git Caching Reverse Proxy service user";
    };

    users.groups.${cfg.group} = { };

    # ── systemd service ────────────────────────────────────────────────
    systemd.services.forgecache = {
      description = "Git Caching Reverse Proxy";
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

        ExecStart = "${cfg.package}/bin/forgecache --config ${cfg.configFile}";

        Restart = "on-failure";
        RestartSec = 5;

        # Directories managed by systemd (created automatically).
        StateDirectory = "forgecache";
        CacheDirectory = "forgecache";
        RuntimeDirectory = "forgecache";

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
