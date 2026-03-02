{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.ghe-key-lookup;

  # Generate a Nix-store TOML config from module options.
  # ghe_url is omitted when null; the binary then derives it as
  # https://<ssh_target_endpoint> automatically.
  configFile = (pkgs.formats.toml { }).generate "ghe-key-lookup.toml" (
    {
      listen = cfg.listen;
      identity_file = toString cfg.identityFile;
      ssh_user = cfg.sshUser;
      ssh_target_endpoint = cfg.sshTargetEndpoint;
      ssh_port = cfg.sshPort;
      ssh_control_path = cfg.sshControlPath;
      ssh_control_persist = cfg.sshControlPersist;
      cache_ttl_pos = cfg.cacheTtlPos;
      cache_ttl_neg = cfg.cacheTtlNeg;
    }
    // lib.optionalAttrs (cfg.gheUrl != null) {
      ghe_url = cfg.gheUrl;
    }
  );
in
{
  options.services.ghe-key-lookup = {
    enable = lib.mkEnableOption "GHE SSH key fingerprint lookup service";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.ghe-key-lookup;
      description = "The ghe-key-lookup package to use.";
    };

    listen = lib.mkOption {
      type = lib.types.str;
      default = "0.0.0.0:3000";
      description = "Address and port to listen on.";
    };

    identityFile = lib.mkOption {
      type = lib.types.path;
      description = "Path to the SSH private key used to connect to the GHE admin console.";
    };

    sshUser = lib.mkOption {
      type = lib.types.str;
      default = "admin";
      description = "SSH username for the GHE admin console.";
    };

    sshTargetEndpoint = lib.mkOption {
      type = lib.types.str;
      description = ''
        Hostname of the GHE SSH admin endpoint (e.g. "ghe.example.com").
        Used as the SSH connection target and, by default, to derive gheUrl.
      '';
    };

    gheUrl = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Base URL for response url fields (e.g. "https://ghe.example.com").
        When null (the default), the binary uses https://<sshTargetEndpoint>.
        Set explicitly only when the HTTPS hostname differs from sshTargetEndpoint.
      '';
    };

    sshPort = lib.mkOption {
      type = lib.types.port;
      default = 122;
      description = "SSH port for the GHE admin console.";
    };

    sshControlPath = lib.mkOption {
      type = lib.types.str;
      default = "/run/ghe-key-lookup/ssh-control";
      description = ''
        Path for the SSH ControlMaster socket.  The first SSH call creates a
        persistent background master process; all subsequent calls reuse the
        existing TCP session without re-authenticating.
        Set to an empty string to disable multiplexing (new connection per request).
      '';
    };

    sshControlPersist = lib.mkOption {
      type = lib.types.str;
      default = "yes";
      description = ''
        How long the ControlMaster process lingers after the last client
        disconnects.  "yes" keeps it alive indefinitely; a number is treated as
        seconds; "no" disables lingering (master exits with last client).
        Only used when sshControlPath is non-empty.
      '';
    };

    cacheTtlPos = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 300;
      description = "Seconds to cache a positive result (key found).";
    };

    cacheTtlNeg = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 30;
      description = "Seconds to cache a negative result (key not found). Set to 0 to disable.";
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      default = "info";
      description = "RUST_LOG verbosity level.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.ghe-key-lookup = {
      description = "GHE SSH key fingerprint lookup service";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        RUST_LOG = cfg.logLevel;
      };

      path = [ pkgs.openssh ];

      serviceConfig = {
        Type = "simple";
        DynamicUser = true;
        KeyringMode = "shared";

        BindReadOnlyPaths = [ (toString cfg.identityFile) ];

        ExecStart = lib.escapeShellArgs [
          "${cfg.package}/bin/ghe-key-lookup"
          "--config"
          "${configFile}"
        ];

        Restart = "on-failure";
        RestartSec = 5;

        RuntimeDirectory = "ghe-key-lookup";

        # Hardening
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;
      };
    };

    networking.firewall.allowedTCPPorts = [ 3000 ];
  };
}
