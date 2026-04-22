{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.forgeproxy-secrets;
in
{
  options.services.forgeproxy-secrets = {
    enable = lib.mkEnableOption "kernel keyring secrets loader for forgeproxy";

    providerScript = lib.mkOption {
      type = lib.types.package;
      description = ''
        Script (derivation) that loads secrets into the user keyring
        via `keyctl padd user <key> @u`.  keyutils is always on PATH.
      '';
    };

    environment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = "Non-secret environment variables passed to the provider script.";
    };

    refreshIntervalSec = lib.mkOption {
      type = lib.types.nullOr lib.types.int;
      default = 60;
      description = ''
        When set, periodically re-run the provider via `systemctl reload
        forgeproxy.service` so updated governing secret resources are
        materialized into `/run/forgeproxy` and the service keyring without
        restarting forgeproxy. Set to `null` to disable periodic refresh.
      '';
    };
  };

  # Inject the provider as ExecStartPre into forgeproxy.service.
  # Keys land in the dynamic user's keyring (@u) — DynamicUser=true scopes
  # the keyring to this service unit.
  config = lib.mkIf (cfg.enable && (config.services.forgeproxy.enable or false)) {
    systemd.services.forgeproxy = {
      path = [ pkgs.keyutils ];
      environment = cfg.environment;
      serviceConfig = {
        ExecStartPre = [ "${cfg.providerScript}" ];
        ExecReload = [ "${cfg.providerScript}" ];
      };
    };

    systemd.services.forgeproxy-secrets-refresh = lib.mkIf (cfg.refreshIntervalSec != null) {
      description = "Refresh forgeproxy runtime secrets";
      after = [ "forgeproxy.service" ];
      wants = [ "forgeproxy.service" ];

      serviceConfig.Type = "oneshot";
      script = ''
        if ${pkgs.systemd}/bin/systemctl is-active --quiet forgeproxy.service; then
          exec ${pkgs.systemd}/bin/systemctl reload forgeproxy.service
        fi
      '';
    };

    systemd.timers.forgeproxy-secrets-refresh = lib.mkIf (cfg.refreshIntervalSec != null) {
      description = "Periodic forgeproxy runtime secrets refresh";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "${toString cfg.refreshIntervalSec}s";
        OnUnitActiveSec = "${toString cfg.refreshIntervalSec}s";
        Unit = "forgeproxy-secrets-refresh.service";
      };
    };
  };
}
