{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.gheproxy-secrets;
in
{
  options.services.gheproxy-secrets = {
    enable = lib.mkEnableOption "kernel keyring secrets loader for gheproxy";

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

  # Inject the provider as ExecStartPre into gheproxy.service.
  # Keys land in gheproxy's own private session keyring — no cross-service
  # keyring sharing required.
  config = lib.mkIf (cfg.enable && (config.services.gheproxy.enable or false)) {
    systemd.services.gheproxy = {
      path = [ pkgs.keyutils ];
      environment = cfg.environment;
      serviceConfig.ExecStartPre = [ "${cfg.providerScript}" ];
    };
  };
}
