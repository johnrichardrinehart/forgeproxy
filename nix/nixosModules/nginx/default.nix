{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.forgeproxy-nginx;
  backendCfg = config.services.forgeproxy.backend._derived;
in
{
  imports = [
    ../forgeproxy/backend.nix
  ];
  options.services.forgeproxy-nginx = {
    enable = lib.mkEnableOption "nginx reverse proxy for forgeproxy";

    serverName = lib.mkOption {
      type = lib.types.str;
      default = "forgeproxy.internal.example.com";
      description = "Virtual host server name for the nginx proxy.";
    };

    sslCertificate = lib.mkOption {
      type = lib.types.path;
      default = "/run/nginx/ssl/cert.pem";
      description = "Path to the TLS certificate.";
    };

    sslCertificateKey = lib.mkOption {
      type = lib.types.path;
      default = "/run/nginx/ssl/key.pem";
      description = "Path to the TLS certificate private key.";
    };

    upstreamHostname = lib.mkOption {
      type = lib.types.str;
      default = "ghe.internal.example.com";
      description = "Hostname of the upstream Git forge server.";
    };

    upstreamPort = lib.mkOption {
      type = lib.types.port;
      default = 443;
      description = "Port of the upstream Git forge server.";
    };

    upstreamSshPort = lib.mkOption {
      type = lib.types.port;
      default = 22;
      description = "SSH port of the upstream Git forge server.";
    };

    backendPort = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "Local port on which the forgeproxy backend listens.";
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

    sshProxy = {
      enable = lib.mkEnableOption "nginx stream proxy in front of forgeproxy SSH";

      listenAddress = lib.mkOption {
        type = lib.types.str;
        default = "0.0.0.0";
        description = "Address for nginx to listen on for client SSH Git traffic.";
      };

      listenPort = lib.mkOption {
        type = lib.types.port;
        default = 2222;
        description = "Port for nginx to listen on for client SSH Git traffic.";
      };

      localAddress = lib.mkOption {
        type = lib.types.str;
        default = "127.0.0.1";
        description = "Address of the local forgeproxy SSH listener behind nginx.";
      };

      localPort = lib.mkOption {
        type = lib.types.port;
        default = 2223;
        description = "Port of the local forgeproxy SSH listener behind nginx.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    services.nginx = {
      enable = true;

      recommendedTlsSettings = true;
      recommendedProxySettings = true;
      recommendedGzipSettings = true;

      commonHttpConfig = ''
        log_format forgeproxy_upstream
          '$remote_addr - $remote_user [$time_local] "$request" '
          '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
          'request_time=$request_time '
          'upstream_addr="$upstream_addr" '
          'upstream_status="$upstream_status" '
          'upstream_response_time="$upstream_response_time" '
          'upstream_bytes_sent="$upstream_bytes_sent" '
          'upstream_bytes_received="$upstream_bytes_received" '
          'forgeproxy_upstream_fallback="$upstream_http_x_forgeproxy_upstream_fallback" '
          'forgeproxy_upstream_fallback_reason="$upstream_http_x_forgeproxy_upstream_fallback_reason" '
          'sent_forgeproxy_upstream_fallback="$sent_http_x_forgeproxy_upstream_fallback" '
          'sent_forgeproxy_upstream_fallback_reason="$sent_http_x_forgeproxy_upstream_fallback_reason" '
          'forgeproxy_disabled="$forgeproxy_disabled"';
      '';

      streamConfig = lib.mkIf cfg.sshProxy.enable ''
        include /run/nginx/forgeproxy-stream.conf;
        resolver ${cfg.resolver} valid=300s;
        resolver_timeout 5s;

        log_format forgeproxy_ssh
          '$remote_addr [$time_local] '
          'protocol="$protocol" status="$status" bytes_sent="$bytes_sent" bytes_received="$bytes_received" '
          'session_time="$session_time" upstream_addr="$upstream_addr" '
          'forgeproxy_disabled="$forgeproxy_disabled" ssh_target="$forgeproxy_ssh_target"';

        server {
          listen ${cfg.sshProxy.listenAddress}:${toString cfg.sshProxy.listenPort};
          proxy_pass $forgeproxy_ssh_target;
          proxy_connect_timeout 30s;
          proxy_timeout 15m;
          access_log /var/log/nginx/ssh-access.log forgeproxy_ssh;
        }
      '';

      # ── Global HTTP-level configuration ────────────────────────────
      appendHttpConfig = ''
        proxy_headers_hash_max_size 1024;
        proxy_headers_hash_bucket_size 128;

        # Runtime-configured upstream block (written by nginx-runtime provider at boot).
        include /run/nginx/forgeproxy-upstream.conf;

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
          access_log /var/log/nginx/access.log forgeproxy_upstream;

          # Runtime-configured upstream hostname variable (written by nginx-runtime provider at boot).
          include /run/nginx/forgeproxy-server.conf;
        '';

        locations = {
          # ── Git smart HTTP: info/refs ────────────────────────────
          "~ ^/(.+)/info/refs$" = {
            proxyPass = "http://127.0.0.1:${toString cfg.backendPort}";
            extraConfig = ''
              error_page 531 = @forge_upstream_https;
              if ($forgeproxy_disabled = "true") {
                return 531;
              }
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
              proxy_intercept_errors on;
              error_page 530 = @forge_upstream_git_upload_pack;
              error_page 531 = @forge_upstream_git_upload_pack;
              if ($forgeproxy_disabled = "true") {
                return 531;
              }
              proxy_set_header Authorization $http_authorization;
              proxy_set_header Host $host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
              proxy_buffering off;
              proxy_request_buffering on;
              client_max_body_size 0;
              client_body_timeout 15m;
              proxy_connect_timeout 30s;
              proxy_read_timeout 15m;
              proxy_send_timeout 15m;
              send_timeout 15m;
            '';
          };

          "@forge_upstream_git_upload_pack" = {
            extraConfig = ''
              internal;
              proxy_pass https://forge-upstream;
              proxy_set_header Authorization $http_authorization;
              proxy_set_header Host $forge_upstream_host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
              proxy_ssl_server_name on;
              proxy_ssl_name $forge_upstream_host;
              proxy_buffering off;
              proxy_request_buffering on;
              client_max_body_size 0;
              client_body_timeout 15m;
              proxy_connect_timeout 30s;
              proxy_read_timeout 15m;
              proxy_send_timeout 15m;
              send_timeout 15m;
            '';
          };

          "@forge_upstream_https" = {
            extraConfig = ''
              internal;
              proxy_pass https://forge-upstream;
              proxy_set_header Authorization $http_authorization;
              proxy_set_header Host $forge_upstream_host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
              proxy_ssl_server_name on;
              proxy_ssl_name $forge_upstream_host;
              proxy_buffering off;
              proxy_request_buffering off;
              client_max_body_size 0;
              client_body_timeout 15m;
              proxy_connect_timeout 30s;
              proxy_read_timeout 15m;
              proxy_send_timeout 15m;
              send_timeout 15m;
            '';
          };

          # ── Git smart HTTP: git-receive-pack ─────────────────────
          "~ ^/(.+)/git-receive-pack$" = {
            proxyPass = "http://127.0.0.1:${toString cfg.backendPort}";
            extraConfig = ''
              error_page 531 = @forge_upstream_https;
              if ($forgeproxy_disabled = "true") {
                return 531;
              }
              proxy_set_header Authorization $http_authorization;
              proxy_set_header Host $host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
              proxy_buffering off;
              proxy_request_buffering off;
              client_max_body_size 0;
              client_body_timeout 15m;
              proxy_connect_timeout 30s;
              proxy_read_timeout 15m;
              proxy_send_timeout 15m;
              send_timeout 15m;
            '';
          };

          # ── Bundle-URI endpoint ──────────────────────────────────
          "/bundles/" = {
            proxyPass = "http://127.0.0.1:${toString cfg.backendPort}/bundles/";
            extraConfig = ''
              error_page 531 = @forge_upstream_https;
              if ($forgeproxy_disabled = "true") {
                return 531;
              }
              proxy_set_header Host $host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
            '';
          };

          # ── Archive / tarball downloads (cached) ─────────────────
          "~ ^/(.+)/(archive|tarball|zipball)/" = {
            extraConfig = ''
              proxy_pass https://forge-upstream;
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
              proxy_cache_bypass $forgeproxy_disabled;
              proxy_no_cache $forgeproxy_disabled;

              add_header X-Cache-Status $upstream_cache_status;
            '';
          };

          # ── API pass-through ───────────────────────────────────
          "${backendCfg.apiPathPrefix}/" = {
            extraConfig = ''
              proxy_pass https://forge-upstream${backendCfg.apiPathPrefix}/;
              proxy_set_header Authorization $http_authorization;
              proxy_set_header Host $forge_upstream_host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
              proxy_ssl_server_name on;
              proxy_ssl_name $forge_upstream_host;
              proxy_buffering off;
              proxy_request_buffering off;
              client_max_body_size 0;
              client_body_timeout 15m;
              proxy_connect_timeout 30s;
              proxy_read_timeout 15m;
              proxy_send_timeout 15m;
              send_timeout 15m;
            '';
          };

          # ── Web UI / generic upstream pass-through ───────────────
          "/" = {
            extraConfig = ''
              proxy_pass https://forge-upstream;
              proxy_set_header Authorization $http_authorization;
              proxy_set_header Host $forge_upstream_host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
              proxy_ssl_server_name on;
              proxy_ssl_name $forge_upstream_host;
            '';
          };

          # ── Health check (proxied to backend) ────────────────────
          "/healthz" = {
            proxyPass = "http://127.0.0.1:${toString cfg.backendPort}/healthz";
            extraConfig = ''
              if ($forgeproxy_disabled = "true") {
                return 200 "forgeproxy disabled by instance tag\n";
              }
              proxy_set_header Host $host;
            '';
          };

          "/readyz" = {
            proxyPass = "http://127.0.0.1:${toString cfg.backendPort}/readyz";
            extraConfig = ''
              if ($forgeproxy_disabled = "true") {
                return 200 "forgeproxy disabled by instance tag\n";
              }
              proxy_set_header Host $host;
            '';
          };

          # ── Webhook receiver ─────────────────────────────────────
          "/webhook" = {
            proxyPass = "http://127.0.0.1:${toString cfg.backendPort}/webhook";
            extraConfig = ''
              error_page 531 = @forge_upstream_https;
              if ($forgeproxy_disabled = "true") {
                return 531;
              }
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

    # The NixOS nginx module enables MemoryDenyWriteExecute by default, but
    # the preStart provider runs awscli2 (Python/libffi) which requires W|X memory.
    systemd.services.nginx.serviceConfig.MemoryDenyWriteExecute = lib.mkForce false;

    # The runtime provider may load secrets into the kernel keyring during
    # ExecStartPre. Keep nginx's syscall allowlist compatible with keyctl(2).
    systemd.services.nginx.serviceConfig.SystemCallFilter = lib.mkAfter [ "@keyring" ];

    # Ensure nginx can open configured log files when validating config, even
    # if the image or another startup path created them with root ownership.
    systemd.tmpfiles.rules = [
      "d ${cfg.archiveCachePath} 0750 nginx nginx -"
      "d /var/log/nginx 0750 nginx nginx -"
      "z /var/log/nginx 0750 nginx nginx -"
      "f /var/log/nginx/access.log 0640 nginx nginx -"
      "z /var/log/nginx/access.log 0640 nginx nginx -"
      "f /var/log/nginx/error.log 0640 nginx nginx -"
      "z /var/log/nginx/error.log 0640 nginx nginx -"
      "f /var/log/nginx/ssh-access.log 0640 nginx nginx -"
      "z /var/log/nginx/ssh-access.log 0640 nginx nginx -"
    ];

    # Create stub runtime config files so nginx can start even if the
    # provider hasn't run yet.  The runtime provider overwrites these.
    systemd.services.nginx.preStart = lib.mkBefore ''
      mkdir -p /run/nginx
      if [ ! -f /run/nginx/forgeproxy-upstream.conf ]; then
        echo 'upstream forge-upstream { server ${cfg.upstreamHostname}:${toString cfg.upstreamPort}; }' \
          > /run/nginx/forgeproxy-upstream.conf
      fi
      if [ ! -f /run/nginx/forgeproxy-server.conf ]; then
        printf 'set $%s "%s";\nset $%s "%s";\n' \
          forge_upstream_host ${cfg.upstreamHostname} \
          forgeproxy_disabled false \
          > /run/nginx/forgeproxy-server.conf
      fi
      if ${lib.boolToString cfg.sshProxy.enable}; then
        if [ ! -f /run/nginx/forgeproxy-stream.conf ]; then
          {
            printf '%s\n' 'map $time_iso8601 $forgeproxy_disabled {'
            printf '%s\n' '  default "false";'
            printf '%s\n' '}'
            printf '%s\n' ""
            printf '%s\n' 'map $time_iso8601 $forgeproxy_ssh_target {'
            printf '%s\n' '  default "${cfg.sshProxy.localAddress}:${toString cfg.sshProxy.localPort}";'
            printf '%s\n' '}'
          } > /run/nginx/forgeproxy-stream.conf
        fi
      fi
    '';
  };
}
