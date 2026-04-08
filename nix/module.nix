{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.forgeproxy;
  cacheLayout = import ./cache-layout.nix {
    inherit lib;
    root = cfg.cacheDir;
  };
  cacheScrubScript = pkgs.writeShellApplication {
    name = "forgeproxy-cache-scrub";
    runtimeInputs = with pkgs; [
      coreutils
      findutils
      git
      gnugrep
      lsof
    ];
    text = ''
      #!/usr/bin/env bash
      set -euo pipefail

      cache_root=${lib.escapeShellArg "${cfg.cacheDir}"}
      generations_root=${lib.escapeShellArg cacheLayout.generationsRoot}
      mirrors_root=${lib.escapeShellArg cacheLayout.mirrorsRoot}
      state_generations_root=${lib.escapeShellArg cacheLayout.stateGenerationsRoot}
      tee_root=${lib.escapeShellArg cacheLayout.stateTeeRoot}
      delta_root=${lib.escapeShellArg cacheLayout.stateDeltaRoot}
      tee_max_age_minutes=15

      if [[ ! -d "$cache_root" ]]; then
        exit 0
      fi

      is_usable_bare_repo() {
        local repo_path=$1

        [[ -d "$repo_path" ]] || return 1
        [[ -f "$repo_path/HEAD" ]] || return 1

        if [[ -f "$repo_path/packed-refs" ]] && grep -Eq '^[^#^[:space:]]' "$repo_path/packed-refs"; then
          return 0
        fi

        [[ -d "$repo_path/refs" ]] || return 1
        find "$repo_path/refs" -type f -print -quit | grep -q .
      }

      git_repo_check() {
        local repo_path=$1
        shift
        git -c safe.directory='*' -C "$repo_path" "$@"
      }

      remove_repo_family() {
        local repo_entry=$1
        local repo_name owner_name generations_dir mirror_dir delta_dir tee_dir

        repo_name=$(basename "$repo_entry" .git)
        owner_name=$(basename "$(dirname "$repo_entry")")
        generations_dir="$state_generations_root/$owner_name/$repo_name.git"
        mirror_dir="$mirrors_root/$owner_name/$repo_name.git"
        delta_dir="$delta_root/$owner_name/$repo_name.git"
        tee_dir="$tee_root/$owner_name/$repo_name"

        rm -rf "$repo_entry"
        rm -rf "$generations_dir"
        rm -rf "$mirror_dir"
        rm -rf "$delta_dir"
        rm -rf "$tee_dir"
      }

      repo_is_active() {
        local repo_path=$1
        lsof +D "$repo_path" >/dev/null 2>&1
      }

      scrub_stale_tee_capture() {
        local capture_dir=$1

        if repo_is_active "$capture_dir"; then
          echo "forgeproxy-cache-scrub: skipping active tee capture $capture_dir" >&2
          return 0
        fi

        if find "$capture_dir" -type f -mmin "-$tee_max_age_minutes" -print -quit | grep -q .; then
          echo "forgeproxy-cache-scrub: skipping fresh tee capture $capture_dir" >&2
          return 0
        fi

        echo "forgeproxy-cache-scrub: removing stale tee capture $capture_dir" >&2
        if ! rm -rf "$capture_dir"; then
          echo "forgeproxy-cache-scrub: warning: failed to remove stale tee capture $capture_dir" >&2
        fi
      }

      while IFS= read -r repo_path; do
        repo_target=$repo_path
        if [[ -L "$repo_path" ]]; then
          repo_target=$(readlink -f "$repo_path" || true)
        fi

        if [[ -z "$repo_target" || ! -d "$repo_target" ]]; then
          echo "forgeproxy-cache-scrub: removing broken repo entry $repo_path" >&2
          remove_repo_family "$repo_path"
          continue
        fi

        if repo_is_active "$repo_target"; then
          echo "forgeproxy-cache-scrub: skipping active repo $repo_path" >&2
          continue
        fi

        if ! is_usable_bare_repo "$repo_target"; then
          echo "forgeproxy-cache-scrub: removing unusable bare repo $repo_path" >&2
          remove_repo_family "$repo_path"
          continue
        fi

        if ! git_repo_check "$repo_target" rev-parse --is-bare-repository >/dev/null 2>&1; then
          echo "forgeproxy-cache-scrub: removing non-bare repo $repo_path" >&2
          remove_repo_family "$repo_path"
          continue
        fi

        if ! git_repo_check "$repo_target" fsck --full >/dev/null 2>&1; then
          if repo_is_active "$repo_target"; then
            echo "forgeproxy-cache-scrub: skipping invalid-but-active repo $repo_path" >&2
            continue
          fi
          echo "forgeproxy-cache-scrub: removing invalid repo $repo_path" >&2
          remove_repo_family "$repo_path"
        fi
      done < <(find "$generations_root" -mindepth 2 -maxdepth 2 \( -type d -o -type l \) -name '*.git' -print 2>/dev/null)

      if [[ -d "$tee_root" ]]; then
        while IFS= read -r capture_dir; do
          scrub_stale_tee_capture "$capture_dir"
        done < <(find "$tee_root" -mindepth 3 -maxdepth 3 -type d -print)
      fi
    '';
  };
in
{
  imports = [ ./otel-collector.nix ];

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

    runtimeResourceFile = lib.mkOption {
      type = lib.types.path;
      default = "/run/forgeproxy/runtime-resource-attributes.json";
      description = ''
        Path to the runtime-discovered observability resource attributes file.
        forgeproxy populates this at service startup so the app and the
        host-local collector can share the same stable instance metadata.
      '';
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

    allowEnvSecretFallback = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Allow forgeproxy to read secrets from environment variables when a
        kernel keyring lookup misses. Hardened closures should keep this false;
        dev closures may set true for convenience.
      '';
    };

    validation.periodicFullFsckIntervalSec = lib.mkOption {
      type = lib.types.nullOr lib.types.int;
      default = 86400;
      example = 86400;
      description = ''
        When set, a separate systemd timer runs a `git fsck --full` scrub over
        on-disk cached bare repos at this interval in seconds. Invalid local
        repos are removed so the next request rehydrates them from upstream or
        S3 instead of serving broken state. Set to `null` to disable the timer.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    users.groups.forgeproxy-cache = { };

    # ── systemd service ────────────────────────────────────────────────
    systemd.services.forgeproxy = {
      description = "Git Caching Reverse Proxy";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        RUST_LOG = cfg.logLevel;
        FORGEPROXY_ALLOW_ENV_SECRET_FALLBACK = if cfg.allowEnvSecretFallback then "true" else "false";
      };

      path = [
        pkgs.git
        pkgs.keyutils
      ];

      serviceConfig = {
        Type = "simple";
        KillMode = "mixed";

        # DynamicUser allocates an ephemeral UID for this service invocation.
        # Secrets in the user keyring (@u) are scoped to this UID, so only
        # processes inside forgeproxy.service can access them.
        DynamicUser = true;
        SupplementaryGroups = [ "forgeproxy-cache" ];
        UMask = "0002";

        # Links the user keyring (@u) into each process's session keyring.
        # Without this, keys in @u are addressable but not "possessed" by
        # the process, so reads fail with EACCES (default key permissions
        # only grant possessor access).
        KeyringMode = "shared";

        ExecStart =
          "${cfg.package}/bin/forgeproxy"
          + " --config ${cfg.configFile}"
          + " --runtime-resource-file ${cfg.runtimeResourceFile}";
        ExecStartPre = lib.mkAfter [
          # Generate stable resource attributes before the main process starts so
          # traces, logs, and scraped metrics all use the same instance identity.
          "${cfg.package}/bin/forgeproxy write-runtime-resource-attributes --output ${cfg.runtimeResourceFile}"
        ];

        Restart = "on-failure";
        RestartSec = 5;
        TimeoutStopSec = "5min";

        # RuntimeDirectory is per-service. The shared cache tree is managed
        # separately via tmpfiles plus forgeproxy-cache group permissions.
        StateDirectory = "forgeproxy";
        RuntimeDirectory = "forgeproxy";
        ReadWritePaths = [ cfg.cacheDir ];

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

    systemd.services.forgeproxy-cache-scrub =
      lib.mkIf (cfg.validation.periodicFullFsckIntervalSec != null)
        {
          description = "Validate and scrub invalid forgeproxy cached repos";
          after = [ "local-fs.target" ];
          wants = [ "local-fs.target" ];

          serviceConfig = {
            Type = "oneshot";
            DynamicUser = true;
            SupplementaryGroups = [ "forgeproxy-cache" ];
            UMask = "0002";
            ReadWritePaths = [ cfg.cacheDir ];
            ProtectKernelTunables = true;
            ProtectKernelModules = true;
            ProtectControlGroups = true;
            RestrictNamespaces = true;
            LockPersonality = true;
            RestrictRealtime = true;
          };

          script = ''
            exec ${cacheScrubScript}/bin/forgeproxy-cache-scrub
          '';
        };

    systemd.timers.forgeproxy-cache-scrub =
      lib.mkIf (cfg.validation.periodicFullFsckIntervalSec != null)
        {
          description = "Periodic forgeproxy cache scrub";
          wantedBy = [ "timers.target" ];
          timerConfig = {
            OnBootSec = "15m";
            OnUnitActiveSec = "${toString cfg.validation.periodicFullFsckIntervalSec}s";
            Persistent = true;
            Unit = "forgeproxy-cache-scrub.service";
          };
        };

    systemd.tmpfiles.rules = [
      "d ${cfg.cacheDir} 2775 root forgeproxy-cache - -"
      "d ${cacheLayout.generationsRoot} 2775 root forgeproxy-cache - -"
      "d ${cacheLayout.mirrorsRoot} 2775 root forgeproxy-cache - -"
      "d ${cacheLayout.snapshotsRoot} 2775 root forgeproxy-cache - -"
      "d ${cacheLayout.stateRoot} 2775 root forgeproxy-cache - -"
      "d ${cacheLayout.stateTeeRoot} 2775 root forgeproxy-cache - -"
    ];

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
