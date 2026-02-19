{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.forgecache-nginx;
  backendCfg = config.services.forgecache.backend._derived;
in
{
  imports = [
    ./backend.nix
  ];
  options.services.forgecache-nginx = {
    enable = lib.mkEnableOption "nginx reverse proxy for forgecache";

    serverName = lib.mkOption {
      type = lib.types.str;
      default = "forgecache.internal.example.gov";
      description = "Virtual host server name for the nginx proxy.";
    };

    sslCertificate = lib.mkOption {
      type = lib.types.path;
      default = "/etc/ssl/forgecache/cert.pem";
      description = "Path to the TLS certificate.";
    };

    sslCertificateKey = lib.mkOption {
      type = lib.types.path;
      default = "/etc/ssl/forgecache/key.pem";
      description = "Path to the TLS certificate private key.";
    };

    upstreamHostname = lib.mkOption {
      type = lib.types.str;
      default = "ghe.internal.example.gov";
      description = "Hostname of the upstream Git forge server.";
    };

    upstreamPort = lib.mkOption {
      type = lib.types.port;
      default = 443;
      description = "Port of the upstream Git forge server.";
    };

    backendPort = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "Local port on which the forgecache backend listens.";
    };

    resolver = lib.mkOption {
      type = lib.types.str;
      default = "169.254.169.253";
      description = "DNS resolver address (AWS VPC default).";
    };

    archiveCachePath = lib.mkOption {
      type = lib.types.path;
      default = "/var/cache/nginx/archives";
      description = "Filesystem path for the nginx proxy cache of archive downloads.";
    };

    archiveCacheSize = lib.mkOption {
      type = lib.types.str;
      default = "10g";
      description = "Maximum size of the nginx archive proxy cache.";
    };

    archiveCacheInactive = lib.mkOption {
      type = lib.types.str;
      default = "365d";
      description = "Duration after which inactive cache entries are purged.";
    };
  };

  config = lib.mkIf cfg.enable {
    services.nginx = {
      enable = true;

      recommendedTlsSettings = true;
      recommendedProxySettings = true;
      recommendedGzipSettings = true;

      # ── Global HTTP-level configuration ────────────────────────────
      appendHttpConfig = ''
        # Runtime-configured upstream block (written by nginx-runtime provider at boot).
        include /run/nginx/forgecache-upstream.conf;

        # Proxy cache for archive / tarball responses.
        proxy_cache_path ${cfg.archiveCachePath}
          levels=1:2
          keys_zone=archives:64m
          max_size=${cfg.archiveCacheSize}
          inactive=${cfg.archiveCacheInactive}
          use_temp_path=off;

        # DNS resolver for dynamic upstream resolution.
        resolver ${cfg.resolver} valid=300s;
        resolver_timeout 5s;

        # Map backend-specific webhook event header to normalized header.
        map $http_${
          lib.toLower (builtins.replaceStrings [ "-" ] [ "_" ] backendCfg.webhookEventHeader)
        } $webhook_event {
          default $http_${
            lib.toLower (builtins.replaceStrings [ "-" ] [ "_" ] backendCfg.webhookEventHeader)
          };
        }

        # Map backend-specific webhook signature header to normalized header.
        map $http_${
          lib.toLower (builtins.replaceStrings [ "-" ] [ "_" ] backendCfg.webhookSignatureHeader)
        } $webhook_signature {
          default $http_${
            lib.toLower (builtins.replaceStrings [ "-" ] [ "_" ] backendCfg.webhookSignatureHeader)
          };
        }
      '';

      virtualHosts.${cfg.serverName} = {
        forceSSL = true;
        sslCertificate = cfg.sslCertificate;
        sslCertificateKey = cfg.sslCertificateKey;

        extraConfig = ''
          # Runtime-configured upstream hostname variable (written by nginx-runtime provider at boot).
          include /run/nginx/forgecache-server.conf;
        '';

        locations = {
          # ── Git smart HTTP: info/refs ────────────────────────────
          "~ ^/(.+)/info/refs$" = {
            proxyPass = "http://127.0.0.1:${toString cfg.backendPort}";
            extraConfig = ''
              proxy_set_header Authorization $http_authorization;
              proxy_set_header Host $host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
              proxy_buffering off;
              proxy_request_buffering off;
            '';
          };

          # ── Git smart HTTP: git-upload-pack ──────────────────────
          "~ ^/(.+)/git-upload-pack$" = {
            proxyPass = "http://127.0.0.1:${toString cfg.backendPort}";
            extraConfig = ''
              proxy_set_header Authorization $http_authorization;
              proxy_set_header Host $host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
              proxy_buffering off;
              proxy_request_buffering off;
              client_max_body_size 0;
            '';
          };

          # ── Git smart HTTP: git-receive-pack ─────────────────────
          "~ ^/(.+)/git-receive-pack$" = {
            proxyPass = "http://127.0.0.1:${toString cfg.backendPort}";
            extraConfig = ''
              proxy_set_header Authorization $http_authorization;
              proxy_set_header Host $host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
              proxy_buffering off;
              proxy_request_buffering off;
              client_max_body_size 0;
            '';
          };

          # ── Bundle-URI endpoint ──────────────────────────────────
          "/bundles/" = {
            proxyPass = "http://127.0.0.1:${toString cfg.backendPort}/bundles/";
            extraConfig = ''
              proxy_set_header Host $host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
            '';
          };

          # ── Archive / tarball downloads (cached) ─────────────────
          "~ ^/(.+)/(archive|tarball|zipball)/" = {
            proxyPass = "https://forge-upstream";
            extraConfig = ''
              proxy_set_header Authorization $http_authorization;
              proxy_set_header Host $forge_upstream_host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;

              proxy_cache archives;
              proxy_cache_valid 200 365d;
              proxy_cache_valid 302 60s;
              proxy_cache_key $scheme$proxy_host$request_uri$http_authorization;
              proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;

              add_header X-Cache-Status $upstream_cache_status;
            '';
          };

          # ── API pass-through ───────────────────────────────────
          "${backendCfg.apiPathPrefix}/" = {
            proxyPass = "https://forge-upstream${backendCfg.apiPathPrefix}/";
            extraConfig = ''
              proxy_set_header Authorization $http_authorization;
              proxy_set_header Host $forge_upstream_host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
              proxy_ssl_server_name on;
            '';
          };

          # ── Health check (proxied to backend) ────────────────────
          "/healthz" = {
            proxyPass = "http://127.0.0.1:${toString cfg.backendPort}/healthz";
            extraConfig = ''
              proxy_set_header Host $host;
            '';
          };

          # ── Webhook receiver ─────────────────────────────────────
          "/webhook" = {
            proxyPass = "http://127.0.0.1:${toString cfg.backendPort}/webhook";
            extraConfig = ''
              proxy_set_header Host $host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;

              # Pass through original backend-specific headers.
              proxy_set_header ${backendCfg.webhookEventHeader} $http_${
                lib.toLower (builtins.replaceStrings [ "-" ] [ "_" ] backendCfg.webhookEventHeader)
              };
              proxy_set_header ${backendCfg.webhookSignatureHeader} $http_${
                lib.toLower (builtins.replaceStrings [ "-" ] [ "_" ] backendCfg.webhookSignatureHeader)
              };

              # Normalized headers for the Rust backend.
              proxy_set_header X-Webhook-Event $webhook_event;
              proxy_set_header X-Webhook-Signature $webhook_signature;
            '';
          };
        };
      };
    };

    # Ensure the cache directory exists with correct ownership.
    systemd.tmpfiles.rules = [
      "d ${cfg.archiveCachePath} 0750 nginx nginx -"
    ];
  };
}
