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
    pkgs.runCommand "forgecache-test-certs"
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

        # Proxy server certificate (SAN: DNS:proxy)
        openssl req -new -nodes -newkey rsa:2048 \
          -keyout $out/proxy.key -out $out/proxy.csr \
          -subj "/CN=proxy"
        openssl x509 -req -in $out/proxy.csr \
          -CA $out/ca.crt -CAkey $out/ca.key -CAcreateserial \
          -out $out/proxy.crt -days 365 \
          -extfile <(printf "subjectAltName=DNS:proxy")
      '';

  # ---------------------------------------------------------------------------
  # forgecache configuration YAML for the test environment
  # ---------------------------------------------------------------------------
  testConfigYaml = pkgs.writeText "forgecache-test-config.yaml" ''
    upstream:
      hostname: "ghe"
      api_url: "http://ghe:3000/api/v1"
      admin_token_env: "FORGE_ADMIN_TOKEN"

    upstream_credentials:
      default_mode: "pat"

    proxy:
      ssh_listen: "0.0.0.0:2222"
      http_listen: "127.0.0.1:8080"
      bundle_uri_base_url: "https://proxy/bundles"

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
      min_clone_count_for_bundles: 2
      bundle_lock_ttl: 300
      generate_filtered_bundles: false

    storage:
      local:
        path: "/var/cache/forgecache/repos"
        max_bytes: 1073741824
        high_water_mark: 0.90
        low_water_mark: 0.75
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
  name = "forgecache-basic";
  globalTimeout = 600;

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

            # Everything (git smart HTTP, API, web UI) → Gitea
            # Let nginx use default Host ($proxy_host = localhost:3000)
            # so Gitea doesn't get confused by Host: ghe on HTTP.
            locations."/" = {
              proxyPass = "http://localhost:3000";
              extraConfig = ''
                proxy_buffering off;
                client_max_body_size 0;
              '';
            };
          };
        };

        # Expose gitea CLI + git + curl for test script commands
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

        networking.firewall.allowedTCPPorts = [ 6379 ];
      };

    # ── forgecache + nginx TLS termination ────────────────────────────────
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
          self.nixosModules.nginx
        ];

        services.forgecache = {
          enable = true;
          package = pkgs.forgecache;
          configFile = testConfigYaml;
          logLevel = "debug";
        };

        services.forgecache-nginx = {
          enable = true;
          serverName = "proxy";
          sslCertificate = "${testCerts}/proxy.crt";
          sslCertificateKey = "${testCerts}/proxy.key";
          gheUpstream = "ghe";
          resolver = "127.0.0.53";
        };

        # Dummy AWS credentials to prevent SDK timeout reaching IMDS
        systemd.services.forgecache.environment = {
          AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
          AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
          AWS_DEFAULT_REGION = "us-east-1";
        };

        # SSM agent is not available in test VMs
        services.amazon-ssm-agent.enable = lib.mkForce false;

        # Extra packages needed by the test script on this node
        environment.systemPackages = with pkgs; [
          curl
          jq
        ];

        # Trust the test CA so forgecache (reqwest) validates the mock GHE cert
        security.pki.certificateFiles = [ "${testCerts}/ca.crt" ];

        networking.firewall.allowedTCPPorts = [
          443
          2222
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
        security.pki.certificateFiles = [ "${testCerts}/ca.crt" ];
      };
  };

  # ---------------------------------------------------------------------------
  # Test script
  # ---------------------------------------------------------------------------
  testScript = ''
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

    # ── Seed mock GHE with test user and repo ─────────────────────────────
    with subtest("Create test user and repo on mock GHE"):
        # Create the admin user (octocat) — must run as gitea user
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

        # Create the hello-world repo via API
        ghe.succeed(
            "curl -sf"
            " -X POST http://localhost:3000/api/v1/user/repos"
            " -H 'Content-Type: application/json'"
            " -u octocat:secret123"
            ' -d \'{"name": "hello-world", "auto_init": false}\'''
        )

        # Push initial content
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "cd $tmp && "
            "git init -b main && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "echo 'Hello World' > README.md && "
            "git add README.md && "
            "git commit -m 'Initial commit' && "
            "git remote add origin http://octocat:secret123@localhost:3000/octocat/hello-world.git && "
            "git push -u origin main"
        )

        # Verify the repo is accessible via Gitea API
        ghe.succeed(
            "curl -sf"
            " -u octocat:secret123"
            " http://localhost:3000/api/v1/repos/octocat/hello-world"
            " | jq -e '.permissions.pull == true'"
        )

    # ── Proxy services come up ────────────────────────────────────────────
    with subtest("forgecache service starts"):
        proxy.wait_for_unit("forgecache.service")
        proxy.wait_for_open_port(8080)

    with subtest("Proxy nginx starts"):
        proxy.wait_for_unit("nginx.service")
        proxy.wait_for_open_port(443)

    # ── Health and metrics endpoints ──────────────────────────────────────
    with subtest("Health endpoint responds"):
        result = proxy.succeed("curl -sf http://localhost:8080/healthz")
        proxy.succeed(
            "curl -sf http://localhost:8080/healthz"
            " | jq -e '.checks.keydb.ok == true'"
        )

    with subtest("Metrics endpoint responds"):
        result = proxy.succeed("curl -sf http://localhost:8080/metrics")
        assert "# EOF" in result or "forgecache" in result.lower() or "process" in result.lower(), \
            f"Metrics endpoint did not return expected content: {result[:200]}"

    # ── Push rejection ────────────────────────────────────────────────────
    with subtest("Push (git-receive-pack) is rejected with 403"):
        exit_code = proxy.execute(
            "curl -sf"
            " -X POST"
            " -H 'Content-Type: application/x-git-receive-pack-request'"
            " -H 'Authorization: Basic b2N0b2NhdDpzZWNyZXQxMjM='"
            " http://localhost:8080/octocat/hello-world/git-receive-pack"
        )[0]
        assert exit_code != 0, "Expected curl to fail (non-2xx status)"

        status = proxy.succeed(
            "curl -s -o /dev/null -w '%{http_code}'"
            " -X POST"
            " -H 'Content-Type: application/x-git-receive-pack-request'"
            " -H 'Authorization: Basic b2N0b2NhdDpzZWNyZXQxMjM='"
            " http://localhost:8080/octocat/hello-world/git-receive-pack"
        )
        assert status.strip().strip("'") == "403", f"Expected HTTP 403, got {status}"

    # ── HTTPS clone through the proxy ─────────────────────────────────────
    with subtest("HTTPS clone through proxy succeeds"):
        client.succeed(
            "git clone https://octocat:secret123@proxy/octocat/hello-world.git /tmp/repo"
        )
        output = client.succeed("cat /tmp/repo/README.md")
        assert "Hello World" in output, f"README.md content mismatch: {output}"
  '';
}
