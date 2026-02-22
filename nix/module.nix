{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.forgeproxy;
in
{
  options.services.forgeproxy = {
    enable = lib.mkEnableOption "Git Caching Reverse Proxy service";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.forgeproxy;
      description = "The forgeproxy package to use.";
    };

    configFile = lib.mkOption {
      type = lib.types.path;
      default = "/run/forgeproxy/config.yaml";
      description = "Path to the forgeproxy configuration file.";
    };

    cacheDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/cache/forgeproxy";
      description = "Directory used for forgeproxy cache data.";
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      default = "info";
      example = "debug";
      description = "Log verbosity level for the forgeproxy binary.";
    };
  };

  config = lib.mkIf cfg.enable {
    # ── systemd service ────────────────────────────────────────────────
    systemd.services.forgeproxy = {
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
        # processes inside forgeproxy.service can access them.
        DynamicUser = true;

        # Links the user keyring (@u) into each process's session keyring.
        # Without this, keys in @u are addressable but not "possessed" by
        # the process, so reads fail with EACCES (default key permissions
        # only grant possessor access).
        KeyringMode = "shared";

        ExecStart = "${cfg.package}/bin/forgeproxy --config ${cfg.configFile}";

        Restart = "on-failure";
        RestartSec = 5;

        # Directories managed by systemd (created automatically).
        StateDirectory = "forgeproxy";
        CacheDirectory = "forgeproxy";
        RuntimeDirectory = "forgeproxy";

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
