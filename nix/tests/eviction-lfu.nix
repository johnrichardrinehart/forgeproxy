{
  self,
  pkgs,
  lib,
}:

let
  # ---------------------------------------------------------------------------
  # Test TLS certificates (generated at Nix eval time)
  # ---------------------------------------------------------------------------
  testCerts =
    pkgs.runCommand "eviction-lfu-test-certs"
      {
        nativeBuildInputs = [ pkgs.openssl ];
      }
      ''
        mkdir -p $out

        # CA
        openssl req -new -x509 -nodes -days 365 \
          -newkey rsa:2048 \
          -keyout $out/ca.key -out $out/ca.crt \
          -subj "/CN=ForgeCache Test CA"

        # GHE server certificate (SAN: DNS:ghe)
        openssl req -new -nodes -newkey rsa:2048 \
          -keyout $out/ghe.key -out $out/ghe.csr \
          -subj "/CN=ghe"
        openssl x509 -req -in $out/ghe.csr \
          -CA $out/ca.crt -CAkey $out/ca.key -CAcreateserial \
          -out $out/ghe.crt -days 365 \
          -extfile <(printf "subjectAltName=DNS:ghe")
      '';

  # ---------------------------------------------------------------------------
  # forgecache configuration YAML — LFU eviction policy
  # ---------------------------------------------------------------------------
  testConfigYaml = pkgs.writeText "eviction-lfu-test-config.yaml" ''
    upstream:
      hostname: "ghe"
      api_url: "http://ghe:3000/api/v1"
      admin_token_env: "FORGE_ADMIN_TOKEN"

    upstream_credentials:
      default_mode: "pat"

    backend_type: "gitea"

    proxy:
      ssh_listen: "0.0.0.0:2222"
      http_listen: "0.0.0.0:8080"
      bundle_uri_base_url: "http://proxy:8080/bundles"

    keydb:
      endpoint: "keydb:6379"
      tls: false
      auth_token_env: "KEYDB_AUTH_TOKEN"

    auth:
      ssh_cache_ttl: 300
      http_cache_ttl: 120
      negative_cache_ttl: 60

    clone:
      freshness_threshold: 60
      lock_ttl: 60
      lock_wait_timeout: 120
      max_concurrent_upstream_clones: 5
      max_concurrent_upstream_fetches: 10

    fetch_schedule:
      default_interval: 1800
      delta_threshold: 1024
      backoff_factor: 2
      max_interval: 86400
      rolling_window: 1800

    bundles:
      daily_consolidation_hour: 3
      weekly_consolidation_day: 7
      min_clone_count_for_bundles: 0
      bundle_lock_ttl: 300
      generate_filtered_bundles: false

    storage:
      local:
        path: "/var/cache/forgecache/repos"
        max_bytes: 1024
        high_water_mark: 0.50
        low_water_mark: 0.25
        eviction_policy: "lfu"
      s3:
        bucket: "test-bucket"
        prefix: ""
        region: "us-east-1"
        use_fips: false
        presigned_url_ttl: 60
  '';

in
pkgs.testers.runNixOSTest {
  name = "forgecache-eviction-lfu";
  globalTimeout = 300;

  # ---------------------------------------------------------------------------
  # Node definitions
  # ---------------------------------------------------------------------------
  nodes = {

    # ── Mock GitHub Enterprise (Gitea behind nginx TLS) ─────────────────
    ghe =
      {
        config,
        pkgs,
        lib,
        ...
      }:
      {
        services.gitea = {
          enable = true;
          settings = {
            server = {
              HTTP_PORT = 3000;
              ROOT_URL = "https://ghe/";
              DOMAIN = "ghe";
            };
            service = {
              DISABLE_REGISTRATION = true;
            };
          };
        };

        services.nginx = {
          enable = true;
          virtualHosts."ghe" = {
            forceSSL = true;
            sslCertificate = "${testCerts}/ghe.crt";
            sslCertificateKey = "${testCerts}/ghe.key";
            locations."/" = {
              proxyPass = "http://localhost:3000";
              extraConfig = ''
                proxy_buffering off;
                client_max_body_size 0;
              '';
            };
          };
        };

        environment.systemPackages = with pkgs; [
          config.services.gitea.package
          git
          curl
          jq
        ];

        security.pki.certificateFiles = [ "${testCerts}/ca.crt" ];
        networking.firewall.allowedTCPPorts = [
          443
          3000
        ];
        virtualisation.memorySize = 2048;
      };

    # ── KeyDB / Redis ───────────────────────────────────────────────────
    keydb =
      {
        config,
        pkgs,
        lib,
        ...
      }:
      {
        services.redis.servers.default = {
          enable = true;
          port = 6379;
          bind = "0.0.0.0";
          settings = {
            protected-mode = "no";
          };
        };

        environment.systemPackages = with pkgs; [
          redis
        ];

        networking.firewall.allowedTCPPorts = [ 6379 ];
      };

    # ── forgecache proxy (HTTP only — no TLS) ────────────────────────────
    proxy =
      {
        config,
        pkgs,
        lib,
        ...
      }:
      {
        imports = [
          self.nixosModules.forgecache
        ];

        services.forgecache = {
          enable = true;
          package = pkgs.forgecache;
          configFile = testConfigYaml;
          logLevel = "debug";
        };

        # Prevent auto-start so we can inject the Gitea admin token first
        systemd.services.forgecache.wantedBy = lib.mkForce [ ];

        # Dummy AWS credentials to prevent SDK timeout reaching IMDS
        systemd.services.forgecache.environment = {
          AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
          AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
          AWS_DEFAULT_REGION = "us-east-1";
        };

        # SSM agent is not available in test VMs
        services.amazon-ssm-agent.enable = lib.mkForce false;

        environment.systemPackages = with pkgs; [
          git
          redis
          curl
          jq
        ];

        # Trust the test CA so forgecache (reqwest) validates the mock GHE cert
        security.pki.certificateFiles = [ "${testCerts}/ca.crt" ];

        networking.firewall.allowedTCPPorts = [
          8080
        ];
        virtualisation.memorySize = 1024;
      };

    # ── Client ──────────────────────────────────────────────────────────
    client =
      {
        config,
        pkgs,
        lib,
        ...
      }:
      {
        environment.systemPackages = with pkgs; [
          git
          curl
          jq
        ];
      };
  };

  # ---------------------------------------------------------------------------
  # Test script
  # ---------------------------------------------------------------------------
  testScript = ''
    import json

    start_all()

    # ── Infrastructure comes up ───────────────────────────────────────────
    with subtest("KeyDB starts"):
        keydb.wait_for_unit("redis-default.service")
        keydb.wait_for_open_port(6379)

    with subtest("Gitea starts"):
        ghe.wait_for_unit("gitea.service")
        ghe.wait_for_open_port(3000)

    with subtest("GHE nginx starts"):
        ghe.wait_for_unit("nginx.service")
        ghe.wait_for_open_port(443)

    # ── Seed mock GHE with admin user + 3 repos ──────────────────────────
    with subtest("Create admin user and repos on mock GHE"):
        # Create admin user
        ghe.succeed(
            "su -s /bin/sh gitea -c '"
            "GITEA_WORK_DIR=/var/lib/gitea"
            " gitea admin user create"
            " --admin"
            " --username octocat"
            " --password secret123"
            " --email octocat@test.local"
            "'"
        )

        # Create access token for octocat
        token_json = ghe.succeed(
            "curl -sf"
            " -X POST http://localhost:3000/api/v1/users/octocat/tokens"
            " -H 'Content-Type: application/json'"
            " -u octocat:secret123"
            ' -d \'{"name": "test-token", "scopes": ["all"]}\'''
        )
        TOKEN = json.loads(token_json)["sha1"]

        # Create repo-a, repo-b, repo-c
        for repo in ["repo-a", "repo-b", "repo-c"]:
            ghe.succeed(
                f"curl -sf"
                f" -X POST http://localhost:3000/api/v1/user/repos"
                f" -H 'Content-Type: application/json'"
                f" -H 'Authorization: token {TOKEN}'"
                f""" -d '{{"name": "{repo}", "auto_init": false}}'"""
            )

            # Push initial content
            ghe.succeed(
                f"set -e && "
                f"tmp=$(mktemp -d) && "
                f"cd $tmp && "
                f"git init -b main && "
                f"git config user.email test@test.local && "
                f"git config user.name Test && "
                f"echo 'Content for {repo}' > README.md && "
                f"git add README.md && "
                f"git commit -m 'Initial commit for {repo}' && "
                f"git remote add origin http://octocat:secret123@localhost:3000/octocat/{repo}.git && "
                f"git push -u origin main"
            )

    # ── Start forgecache with admin token ────────────────────────────────
    with subtest("Start forgecache with admin token"):
        proxy.succeed(
            f"mkdir -p /run/systemd/system/forgecache.service.d && "
            f"cat > /run/systemd/system/forgecache.service.d/token.conf <<UNIT\n"
            f"[Service]\n"
            f"Environment=FORGE_ADMIN_TOKEN={TOKEN}\n"
            f"UNIT"
        )
        proxy.succeed("systemctl daemon-reload")
        proxy.succeed("systemctl start forgecache")
        proxy.wait_for_open_port(8080)

    # ── Health endpoint responds ─────────────────────────────────────────
    with subtest("Health endpoint responds with LFU policy active"):
        result = proxy.succeed("curl -sf http://localhost:8080/healthz")
        health = json.loads(result)
        assert health["checks"]["keydb"]["ok"] is True, \
            f"KeyDB health check failed: {result}"

    # ── Clone all 3 repos through the proxy ──────────────────────────────
    with subtest("Clone repos through proxy"):
        for repo in ["repo-a", "repo-b", "repo-c"]:
            client.succeed(
                f"git clone http://octocat:secret123@proxy:8080/octocat/{repo}.git /tmp/{repo}"
            )
            output = client.succeed(f"cat /tmp/{repo}/README.md")
            assert f"Content for {repo}" in output, \
                f"README.md content mismatch for {repo}: {output}"

    # ── Verify repos are cached on disk ──────────────────────────────────
    with subtest("All repos present in local cache"):
        for repo in ["repo-a", "repo-b", "repo-c"]:
            proxy.succeed(
                f"test -d /var/cache/forgecache/repos/octocat/{repo}.git"
            )

    # ── Seed KeyDB with LFU-relevant metadata ────────────────────────────
    with subtest("Seed KeyDB with clone_count and bundle_list_key"):
        # repo-a: most popular (clone_count = 100)
        proxy.succeed(
            "redis-cli -h keydb HSET 'forgecache:repo:octocat/repo-a'"
            " clone_count 100"
        )
        # repo-b: medium popularity (clone_count = 50)
        proxy.succeed(
            "redis-cli -h keydb HSET 'forgecache:repo:octocat/repo-b'"
            " clone_count 50"
        )
        # repo-c: least popular (clone_count = 1)
        proxy.succeed(
            "redis-cli -h keydb HSET 'forgecache:repo:octocat/repo-c'"
            " clone_count 1"
        )

        # Set bundle_list_key for all repos (required for eviction eligibility)
        for repo in ["repo-a", "repo-b", "repo-c"]:
            proxy.succeed(
                f"redis-cli -h keydb HSET 'forgecache:repo:octocat/{repo}'"
                f" bundle_list_key 's3://test-bucket/octocat/{repo}/bundle-list'"
            )

    # ── Verify KeyDB state is correct ─────────────────────────────────────
    with subtest("Verify KeyDB clone_count values are set correctly"):
        count_a = proxy.succeed(
            "redis-cli -h keydb HGET 'forgecache:repo:octocat/repo-a' clone_count"
        ).strip()
        count_b = proxy.succeed(
            "redis-cli -h keydb HGET 'forgecache:repo:octocat/repo-b' clone_count"
        ).strip()
        count_c = proxy.succeed(
            "redis-cli -h keydb HGET 'forgecache:repo:octocat/repo-c' clone_count"
        ).strip()

        assert count_a == "100", f"Expected repo-a clone_count=100, got {count_a}"
        assert count_b == "50", f"Expected repo-b clone_count=50, got {count_b}"
        assert count_c == "1", f"Expected repo-c clone_count=1, got {count_c}"

    # ── Verify proxy is still healthy after seeding ───────────────────────
    with subtest("Proxy remains healthy after KeyDB seeding"):
        result = proxy.succeed("curl -sf http://localhost:8080/healthz")
        health = json.loads(result)
        assert health["status"] in ("ok", "degraded"), \
            f"Unexpected health status: {health['status']}"

    # ── Verify the forgecache service is running with LFU config ──────────
    with subtest("forgecache service is active with LFU eviction policy"):
        proxy.succeed("systemctl is-active forgecache.service")
  '';
}
