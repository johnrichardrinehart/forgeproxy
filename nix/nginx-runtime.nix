{
  config,
  lib,
  ...
}:

let
  cfg = config.services.forgecache-nginx-runtime;
in
{
  options.services.forgecache-nginx-runtime = {
    enable = lib.mkEnableOption "runtime nginx config provider for forgecache";

    providerScript = lib.mkOption {
      type = lib.types.package;
      description = ''
        Derivation containing a script that fetches nginx configuration from
        a secrets manager and writes the upstream hostname, port, and TLS material
        to /run/nginx/forgecache-*.conf files at boot.
        Users provide this derivation; see flake.nix awsNginxProvider for reference.
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

  config = lib.mkIf cfg.enable {
    systemd.services.nginx = {
      environment = cfg.environment;
      preStart = lib.mkBefore ''
        ${cfg.providerScript}
      '';
    };
  };
}
