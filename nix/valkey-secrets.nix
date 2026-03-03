{
  config,
  lib,
  ...
}:

let
  cfg = config.services.valkey-secrets;
in
{
  options.services.valkey-secrets = {
    enable = lib.mkEnableOption "auth secrets loader for Valkey";

    providerScript = lib.mkOption {
      type = lib.types.package;
      description = ''
        Derivation containing a script that fetches the Valkey authentication
        token from a secrets manager (e.g., AWS Secrets Manager) and writes the
        requirepass value to services.valkey.extraConfFile.
        Users provide this derivation; see flake.nix awsValkeyAuthProvider for reference.
      '';
    };

    environment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = ''
        Environment variables to pass to the provider script.
      '';
    };
  };

  config = lib.mkIf (cfg.enable && (config.services.valkey.enable or false)) {
    services.valkey.extraConfFile = "/run/valkey/runtime.conf";

    systemd.services.valkey = {
      environment = cfg.environment;
      serviceConfig.ExecStartPre = [ "${cfg.providerScript}" ];
    };
  };
}
