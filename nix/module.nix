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
      default = "/run/forgecache/config.yaml";
      description = "Path to the forgecache configuration file.";
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
    # ── systemd service ────────────────────────────────────────────────
    systemd.services.forgecache = {
      description = "Git Caching Reverse Proxy";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        RUST_LOG = cfg.logLevel;
      };

      path = [
        pkgs.git
        pkgs.keyutils
      ];

      serviceConfig = {
        Type = "simple";

        # DynamicUser allocates an ephemeral UID for this service invocation.
        # Secrets in the user keyring (@u) are scoped to this UID, so only
        # processes inside forgecache.service can access them.
        DynamicUser = true;

        # Links the user keyring (@u) into each process's session keyring.
        # Without this, keys in @u are addressable but not "possessed" by
        # the process, so reads fail with EACCES (default key permissions
        # only grant possessor access).
        KeyringMode = "shared";

        ExecStart = "${cfg.package}/bin/forgecache --config ${cfg.configFile}";

        Restart = "on-failure";
        RestartSec = 5;

        # Directories managed by systemd (created automatically).
        StateDirectory = "forgecache";
        CacheDirectory = "forgecache";
        RuntimeDirectory = "forgecache";

        # ── Hardening ────────────────────────────────────────────────
        # DynamicUser=true already implies: ProtectSystem=strict,
        # ProtectHome=read-only, PrivateTmp, NoNewPrivileges,
        # RestrictSUIDSGID, RemoveIPC.
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        # Note: MemoryDenyWriteExecute is intentionally omitted here.
        # ExecStartPre runs the AWS provider (awscli2/Python/libffi) under the
        # same seccomp filter as the main process, and Python requires W|X memory.
        RestrictRealtime = true;
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
