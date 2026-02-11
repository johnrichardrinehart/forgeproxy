{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.gheproxy-nginx;
in
{
  options.services.gheproxy-nginx = {
    enable = lib.mkEnableOption "nginx reverse proxy for gheproxy";

    serverName = lib.mkOption {
      type = lib.types.str;
      default = "gheproxy.internal.example.gov";
      description = "Virtual host server name for the nginx proxy.";
    };

    sslCertificate = lib.mkOption {
      type = lib.types.path;
      default = "/etc/ssl/gheproxy/cert.pem";
      description = "Path to the TLS certificate.";
    };

    sslCertificateKey = lib.mkOption {
      type = lib.types.path;
      default = "/etc/ssl/gheproxy/key.pem";
      description = "Path to the TLS certificate private key.";
    };

    gheUpstream = lib.mkOption {
      type = lib.types.str;
      default = "ghe.internal.example.gov";
      description = "Hostname of the upstream GitHub Enterprise server.";
    };

    gheUpstreamPort = lib.mkOption {
      type = lib.types.port;
      default = 443;
      description = "Port of the upstream GitHub Enterprise server.";
    };

    backendPort = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "Local port on which the gheproxy backend listens.";
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
        # Upstream block for the GitHub Enterprise server.
        upstream ghe-upstream {
          server ${cfg.gheUpstream}:${toString cfg.gheUpstreamPort};
          keepalive 32;
        }

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
      '';

      virtualHosts.${cfg.serverName} = {
        forceSSL = true;
        sslCertificate = cfg.sslCertificate;
        sslCertificateKey = cfg.sslCertificateKey;

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
            proxyPass = "https://ghe-upstream";
            extraConfig = ''
              proxy_set_header Authorization $http_authorization;
              proxy_set_header Host ${cfg.gheUpstream};
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

          # ── GitHub API pass-through ──────────────────────────────
          "/api/" = {
            proxyPass = "https://ghe-upstream/api/";
            extraConfig = ''
              proxy_set_header Authorization $http_authorization;
              proxy_set_header Host ${cfg.gheUpstream};
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
              proxy_ssl_server_name on;
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
              proxy_set_header X-GitHub-Event $http_x_github_event;
              proxy_set_header X-Hub-Signature-256 $http_x_hub_signature_256;
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
