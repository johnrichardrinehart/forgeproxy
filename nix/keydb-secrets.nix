{
  config,
  lib,
  ...
}:

let
  cfg = config.services.keydb-secrets;
in
{
  options.services.keydb-secrets = {
    enable = lib.mkEnableOption "secrets loader for KeyDB";

    providerScript = lib.mkOption {
      type = lib.types.package;
      description = ''
        Derivation containing a script that fetches TLS material and authentication
        credentials from a secrets manager (e.g., AWS Secrets Manager), writes TLS
        files to the paths configured in services.keydb.tls.{certFile,keyFile,caFile},
        and writes the requirepass value to services.keydb.extraConfFile.
        Users provide this derivation; see flake.nix awsKeydbProvider for reference.
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

  config = lib.mkIf (cfg.enable && (config.services.keydb.enable or false)) {
    services.keydb.extraConfFile = "/run/keydb/runtime.conf";

    systemd.services.keydb = {
      environment = cfg.environment;
      serviceConfig.ExecStartPre = [ "${cfg.providerScript}" ];
    };
  };
}
