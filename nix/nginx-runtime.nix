{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.forgeproxy-nginx-runtime;
in
{
  options.services.forgeproxy-nginx-runtime = {
    enable = lib.mkEnableOption "runtime nginx config provider for forgeproxy";

    providerScript = lib.mkOption {
      type = lib.types.package;
      description = ''
        Derivation containing a script that fetches nginx configuration from
        a secrets manager and writes the upstream hostname, port, and TLS material
        to /run/nginx/forgeproxy-*.conf files at boot.
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
      path = lib.mkAfter [ pkgs.keyutils ];
      environment = cfg.environment;
      serviceConfig.KeyringMode = lib.mkDefault "shared";
      preStart = lib.mkBefore ''
        ${cfg.providerScript}
        CERT_ID=$(keyctl search @u user NGINX_TLS_CERT 2>/dev/null || true)
        KEY_ID=$(keyctl search @u user NGINX_TLS_KEY 2>/dev/null || true)
        if [ -n "$CERT_ID" ] && [ -n "$KEY_ID" ]; then
          mkdir -p /run/nginx/ssl
          keyctl pipe "$CERT_ID" > /run/nginx/ssl/cert.pem
          keyctl pipe "$KEY_ID" > /run/nginx/ssl/key.pem
          chmod 600 /run/nginx/ssl/key.pem
        fi
      '';
    };
  };
}
