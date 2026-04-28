{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.forgeproxy-nginx-runtime;
  materializeTls = pkgs.writeShellScript "forgeproxy-nginx-materialize-tls" ''
    set -euo pipefail

    CERT_ID=$(${pkgs.keyutils}/bin/keyctl search @u user NGINX_TLS_CERT 2>/dev/null || true)
    KEY_ID=$(${pkgs.keyutils}/bin/keyctl search @u user NGINX_TLS_KEY 2>/dev/null || true)
    if [ -n "$CERT_ID" ] && [ -n "$KEY_ID" ]; then
      install -d -m 0750 /run/nginx/ssl
      rm -f /run/nginx/ssl/cert.pem /run/nginx/ssl/key.pem
      ${pkgs.keyutils}/bin/keyctl pipe "$CERT_ID" > /run/nginx/ssl/cert.pem.tmp
      ${pkgs.keyutils}/bin/keyctl pipe "$KEY_ID" > /run/nginx/ssl/key.pem.tmp
      chmod 0640 /run/nginx/ssl/cert.pem.tmp
      chmod 0600 /run/nginx/ssl/key.pem.tmp
      mv /run/nginx/ssl/cert.pem.tmp /run/nginx/ssl/cert.pem
      mv /run/nginx/ssl/key.pem.tmp /run/nginx/ssl/key.pem
      if [ "$(id -u)" -eq 0 ]; then
        chown nginx:nginx /run/nginx/ssl/cert.pem /run/nginx/ssl/key.pem
      fi
    fi
  '';
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

    refreshIntervalSec = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.positive;
      default = null;
      example = 15;
      description = ''
        Optional interval for re-running the runtime provider and reloading
        nginx. This lets AWS instance tag changes, including emergency
        forgeproxy-disable, take effect without restarting the instance.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.nginx = {
      path = lib.mkAfter [ pkgs.keyutils ];
      environment = cfg.environment;
      serviceConfig = {
        KeyringMode = lib.mkDefault "shared";
        RuntimeDirectory = lib.mkForce [
          "nginx"
          "nginx/ssl"
        ];
        RuntimeDirectoryMode = "0750";
      };
      preStart = lib.mkBefore ''
        ${cfg.providerScript}
        ${materializeTls}
      '';
    };

    systemd.services.forgeproxy-nginx-runtime-refresh = lib.mkIf (cfg.refreshIntervalSec != null) {
      description = "Refresh forgeproxy nginx runtime configuration";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      environment = cfg.environment;
      path = [
        pkgs.keyutils
        config.services.nginx.package
      ];
      serviceConfig = {
        Type = "oneshot";
        KeyringMode = "shared";
        MemoryDenyWriteExecute = false;
      };
      script = ''
        ${cfg.providerScript}
        ${materializeTls}
        ${config.services.nginx.package}/bin/nginx -t
        ${pkgs.systemd}/bin/systemctl reload nginx.service
      '';
    };

    systemd.timers.forgeproxy-nginx-runtime-refresh = lib.mkIf (cfg.refreshIntervalSec != null) {
      description = "Periodically refresh forgeproxy nginx runtime configuration";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "${toString cfg.refreshIntervalSec}s";
        OnUnitActiveSec = "${toString cfg.refreshIntervalSec}s";
        Unit = "forgeproxy-nginx-runtime-refresh.service";
      };
    };
  };
}
