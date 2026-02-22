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
  };

  # Inject the provider as ExecStartPre into forgeproxy.service.
  # Keys land in the dynamic user's keyring (@u) — DynamicUser=true scopes
  # the keyring to this service unit.
  config = lib.mkIf (cfg.enable && (config.services.forgeproxy.enable or false)) {
    systemd.services.forgeproxy = {
      path = [ pkgs.keyutils ];
      environment = cfg.environment;
      serviceConfig.ExecStartPre = [ "${cfg.providerScript}" ];
    };
  };
}
