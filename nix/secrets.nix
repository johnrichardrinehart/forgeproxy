{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.forgecache-secrets;
in
{
  options.services.forgecache-secrets = {
    enable = lib.mkEnableOption "kernel keyring secrets loader for forgecache";

    providerScript = lib.mkOption {
      type = lib.types.package;
      description = ''
        Script (derivation) that loads secrets into the session keyring
        via `keyctl padd user <key> @s`.  keyutils is always on PATH.
      '';
    };

    environment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = "Non-secret environment variables passed to the provider script.";
    };
  };

  # Inject the provider as ExecStartPre into forgecache.service.
  # Keys land in forgecache's own private session keyring — no cross-service
  # keyring sharing required.
  config = lib.mkIf (cfg.enable && (config.services.forgecache.enable or false)) {
    systemd.services.forgecache = {
      path = [ pkgs.keyutils ];
      environment = cfg.environment;
      serviceConfig.ExecStartPre = [ "${cfg.providerScript}" ];
    };
  };
}
