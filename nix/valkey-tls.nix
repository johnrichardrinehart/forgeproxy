{
  config,
  lib,
  ...
}:

let
  cfg = config.services.valkey-tls;
in
{
  options.services.valkey-tls = {
    enable = lib.mkEnableOption "TLS certificate loader for Valkey";

    providerScript = lib.mkOption {
      type = lib.types.package;
      description = ''
        Derivation containing a script that fetches TLS material from a secrets
        manager (e.g., AWS Secrets Manager) and writes certificate files to the
        paths configured in services.valkey.tls.{certFile,keyFile,caFile}.
        Users provide this derivation; see flake.nix awsValkeyTlsProvider for reference.
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
    systemd.services.valkey = {
      environment = cfg.environment;
      serviceConfig.ExecStartPre = [ "${cfg.providerScript}" ];
    };
  };
}
