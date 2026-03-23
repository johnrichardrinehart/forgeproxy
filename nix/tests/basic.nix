{
  self,
  pkgs,
  lib,
}:

let
  common = import ./common.nix { inherit pkgs lib; };

  # ---------------------------------------------------------------------------
  # Test TLS certificates (generated at Nix eval time)
  # ---------------------------------------------------------------------------
  testCerts =
    pkgs.runCommand "forgeproxy-test-certs"
      {
        nativeBuildInputs = [ pkgs.openssl ];
      }
      ''
        mkdir -p $out

        # CA
        openssl req -new -x509 -nodes -days 365 \
          -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
          -keyout $out/ca.key -out $out/ca.crt \
          -subj "/CN=ForgeProxy Test CA"

        # GHE server certificate (SAN: DNS:ghe)
        openssl req -new -nodes \
          -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
          -keyout $out/ghe.key -out $out/ghe.csr \
          -subj "/CN=ghe"
        openssl x509 -req -in $out/ghe.csr \
          -CA $out/ca.crt -CAkey $out/ca.key -CAcreateserial \
          -out $out/ghe.crt -days 365 -sha256 \
          -extfile <(printf "subjectAltName=DNS:ghe")

        # Proxy server certificate (SAN: DNS:proxy)
        openssl req -new -nodes \
          -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
          -keyout $out/proxy.key -out $out/proxy.csr \
          -subj "/CN=proxy"
        openssl x509 -req -in $out/proxy.csr \
          -CA $out/ca.crt -CAkey $out/ca.key -CAcreateserial \
          -out $out/proxy.crt -days 365 -sha256 \
          -extfile <(printf "subjectAltName=DNS:proxy")
      '';

  # ---------------------------------------------------------------------------
  # forgeproxy configuration YAML for the test environment
  # ---------------------------------------------------------------------------
  testConfigYaml = pkgs.writeText "forgeproxy-test-config.yaml" ''
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

    valkey:
      endpoint: "valkey:6379"
      tls: false
      auth_token_env: "VALKEY_AUTH_TOKEN"

    auth:
      ssh_cache_ttl: 300
      http_cache_ttl: 120
      negative_cache_ttl: 60

    clone:
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
        path: "/var/cache/forgeproxy/repos"
        max_bytes: 1073741824
        high_water_mark: 0.90
        low_water_mark: 0.75
        eviction_policy: "lfu"
      s3:
        bucket: "test-bucket"
        prefix: ""
        region: "us-east-1"
        endpoint: "http://s3:9000"
        use_fips: false
        presigned_url_ttl: 60

    observability:
      metrics:
        prometheus:
          enabled: true
      exporters:
        otlp:
          enabled: true
          endpoint: "http://127.0.0.1:4317"
          protocol: "grpc"
          export_interval_secs: 15
  '';

in
pkgs.testers.runNixOSTest {
  name = "forgeproxy-basic";
  globalTimeout = 210;

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
        virtualisation.memorySize = 1536;
      };

    # ── Valkey / Redis ───────────────────────────────────────────────────
    valkey = common.mkValkeyNode { };

    s3 = common.mkS3Node { };

    # ── forgeproxy + nginx TLS termination ────────────────────────────────
    proxy =
      {
        config,
        pkgs,
        lib,
        ...
      }:
      {
        imports = [
          self.nixosModules.forgeproxy
          self.nixosModules.nginx
          self.nixosModules.nginx-runtime
        ];

        services.forgeproxy = {
          enable = true;
          package = pkgs.forgeproxy;
          configFile = testConfigYaml;
          logLevel = "debug";
        };

        services.forgeproxy-nginx = {
          enable = true;
          serverName = "proxy";
        };

        # Exercise the runtime provider + keyring materialization path used in prod.
        services.forgeproxy-nginx-runtime = {
          enable = true;
          providerScript = pkgs.writeShellScript "nginx-runtime-config" ''
            set -euo pipefail
            put_key() {
              local key_desc="$1"
              local src_file="$2"
              local existing_id
              existing_id=$(${pkgs.keyutils}/bin/keyctl search @u user "$key_desc" 2>/dev/null || true)
              if [ -n "$existing_id" ]; then
                ${pkgs.keyutils}/bin/keyctl pupdate "$existing_id" < "$src_file"
              else
                ${pkgs.keyutils}/bin/keyctl padd user "$key_desc" @u < "$src_file" >/dev/null
              fi
            }
            cat > /run/nginx/forgeproxy-upstream.conf <<'EOFCONF'
            upstream forge-upstream {
              server ghe:443;
              keepalive 32;
            }
            EOFCONF
            cat > /run/nginx/forgeproxy-server.conf <<'EOFCONF'
            set $forge_upstream_host "ghe";
            EOFCONF
            put_key NGINX_TLS_CERT "${testCerts}/proxy.crt"
            put_key NGINX_TLS_KEY "${testCerts}/proxy.key"
          '';
        };

        # Dummy AWS credentials to prevent SDK timeout reaching IMDS
        systemd.services.forgeproxy.environment = {
          AWS_ACCESS_KEY_ID = "minioadmin";
          AWS_SECRET_ACCESS_KEY = "minioadmin";
          AWS_DEFAULT_REGION = "us-east-1";
          FORGEPROXY_ALLOW_ENV_SECRET_FALLBACK = lib.mkForce "true";
          FORGE_ADMIN_TOKEN = lib.mkForce common.giteaAdminToken;
        };

        # SSM agent is not available in test VMs
        services.amazon-ssm-agent.enable = lib.mkForce false;

        # Extra packages needed by the test script on this node
        environment.systemPackages = with pkgs; [
          curl
          jq
        ];

        # Trust the test CA so forgeproxy (reqwest) validates the mock GHE cert
        security.pki.certificateFiles = [ "${testCerts}/ca.crt" ];

        networking.firewall.allowedTCPPorts = [
          443
          2222
        ];
        virtualisation.memorySize = 768;
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
          pv
        ];
        security.pki.certificateFiles = [ "${testCerts}/ca.crt" ];
      };
  };

  # ---------------------------------------------------------------------------
  # Test script
  # ---------------------------------------------------------------------------
  testScript = ''
    def pkt_line(payload: str) -> str:
        return f"{len(payload) + 4:04x}{payload}"

    ghe.start()
    valkey.start()
    s3.start()

    # ── Infrastructure comes up ───────────────────────────────────────────
    ${common.valkeyStartScript}

    ${common.s3StartScript}

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
            " --username ${common.giteaAdminUser}"
            " --password ${common.giteaAdminPassword}"
            " --email ${common.giteaAdminUser}@test.local"
            "'"
        )

        ${common.giteaSeedAdminTokenScript}

        # Create the hello-world repo via API
        ghe.succeed(
            "curl -sf"
            " -X POST http://localhost:3000/api/v1/user/repos"
            " -H 'Content-Type: application/json'"
            " -u ${common.giteaAdminUser}:${common.giteaAdminPassword}"
            ' -d \'{"name": "hello-world", "auto_init": false}\'''
        )
        ghe.succeed(
            "curl -sf"
            " -X POST http://localhost:3000/api/v1/user/repos"
            " -H 'Content-Type: application/json'"
            " -u ${common.giteaAdminUser}:${common.giteaAdminPassword}"
            ' -d \'{"name": "shallow-only", "auto_init": false}\'''
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
            "head -c 33554432 /dev/urandom > BIG.bin && "
            "git add README.md && "
            "git add BIG.bin && "
            "git commit -m 'Initial commit' && "
            "git remote add origin http://${common.giteaAdminUser}:${common.giteaAdminPassword}@localhost:3000/${common.giteaAdminUser}/hello-world.git && "
            "git push -u origin main"
        )
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "cd $tmp && "
            "git init -b main && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "echo 'Shallow repo' > README.md && "
            "git add README.md && "
            "git commit -m 'Initial commit' && "
            "git remote add origin http://${common.giteaAdminUser}:${common.giteaAdminPassword}@localhost:3000/${common.giteaAdminUser}/shallow-only.git && "
            "git push -u origin main"
        )

        # Verify the repo is accessible via Gitea API
        ghe.succeed(
            "curl -sf"
            " -u ${common.giteaAdminUser}:${common.giteaAdminPassword}"
            " http://localhost:3000/api/v1/repos/${common.giteaAdminUser}/hello-world"
            " | jq -e '.permissions.pull == true'"
        )

    # ── Proxy services come up ────────────────────────────────────────────
    with subtest("Start proxy and client VMs after upstream is ready"):
        proxy.start()
        client.start()

    with subtest("forgeproxy service starts"):
        proxy.wait_for_unit("forgeproxy.service")
        proxy.wait_for_open_port(8080)

    with subtest("Shared config enables the on-host OTLP collector"):
        proxy.wait_for_unit("forgeproxy-otlp-collector.service")
        rendered = proxy.succeed("cat /run/forgeproxy-otelcol/config.yaml")
        assert 'targets: ["127.0.0.1:8080"]' in rendered, rendered
        assert 'endpoint: "127.0.0.1:4317"' in rendered, rendered

    with subtest("Proxy nginx starts"):
        proxy.wait_for_unit("nginx.service")
        proxy.wait_for_open_port(443)

    # ── Health and metrics endpoints ──────────────────────────────────────
    with subtest("Health endpoint responds"):
        result = proxy.succeed("curl -sf http://localhost:8080/healthz")
        proxy.succeed(
            "curl -sf http://localhost:8080/healthz"
            " | jq -e '.checks.valkey.ok == true'"
        )

    with subtest("Metrics endpoint responds"):
        result = proxy.succeed("curl -sf http://localhost:8080/metrics")
        assert "# EOF" in result or "forgeproxy" in result.lower() or "process" in result.lower(), \
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

    with subtest("Initial clone publishes a generation"):
        proxy.wait_until_succeeds(
            "test -L /var/cache/forgeproxy/repos/octocat/hello-world.git"
        )
        proxy.wait_until_succeeds(
            "find /var/cache/forgeproxy/repos/.generations/octocat/hello-world.git -mindepth 1 -maxdepth 1 -type d | grep -q ."
        )

    with subtest("Forgeproxy metrics are exported at /metrics"):
        proxy.succeed(
            "curl -sf http://localhost:8080/metrics"
            " | grep -q '^forgeproxy_bundle_generation_total '"
        )
        proxy.succeed(
            "curl -sf http://localhost:8080/metrics"
            " | grep -q '^forgeproxy_archive_cache_misses_total '"
        )

    with subtest("Pinned fetch still uses cache after waiting"):
        client.succeed("sleep 6")
        client.succeed(
            "rm -rf /tmp/pinnedfetch && "
            "git init /tmp/pinnedfetch && "
            "git -C /tmp/pinnedfetch remote add origin https://octocat:secret123@proxy/octocat/hello-world.git && "
            "git -C /tmp/pinnedfetch fetch origin main"
        )
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy --no-pager | grep -F 'serving upload-pack directly from local disk'"
        )

    with subtest("Mutable ref updates publish a new generation while leased readers keep the old one alive"):
        old_rev = ghe.succeed(
            "git ls-remote http://octocat:secret123@localhost:3000/octocat/hello-world.git refs/heads/main | cut -f1"
        ).strip()
        request_body = (
            pkt_line(
                f"want {old_rev} multi_ack_detailed side-band-64k thin-pack ofs-delta agent=forgeproxy-test\n"
            )
            + pkt_line("done\n")
            + "0000"
        )
        client.succeed(
            "cat > /tmp/slow-upload-pack.req <<'EOF'\n"
            f"{request_body}\n"
            "EOF"
        )
        client.execute(
            "sh -lc '"
            "set -o pipefail; "
            "curl -sf"
            " -u octocat:secret123"
            " -H \"Content-Type: application/x-git-upload-pack-request\""
            " --data-binary @/tmp/slow-upload-pack.req"
            " https://proxy/octocat/hello-world.git/git-upload-pack"
            " | pv -qL 1048576 > /tmp/slow-upload-pack.out"
            " 2> /tmp/slow-upload-pack.err; "
            "echo $? > /tmp/slow-upload-pack.status"
            "' &"
        )
        proxy.wait_until_succeeds(
            "pgrep -af 'git upload-pack --stateless-rpc --strict .*/hello-world' >/dev/null"
        )
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy --no-pager | grep -F 'serving upload-pack directly from local disk' >/dev/null"
        )
        old_generation = proxy.succeed(
            "readlink -f /var/cache/forgeproxy/repos/octocat/hello-world.git"
        ).strip()
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "git clone http://octocat:secret123@localhost:3000/octocat/hello-world.git $tmp && "
            "cd $tmp && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "echo 'Second commit' >> README.md && "
            "git add README.md && "
            "git commit -m 'Second commit' && "
            "git push origin main"
        )
        updated_rev = ghe.succeed(
            "git ls-remote http://octocat:secret123@localhost:3000/octocat/hello-world.git refs/heads/main | cut -f1"
        ).strip()
        client.succeed("git -C /tmp/repo fetch origin main")
        proxy.wait_until_succeeds(
            f"test \"$(readlink -f /var/cache/forgeproxy/repos/octocat/hello-world.git)\" != '{old_generation}'"
        )
        proxy.wait_until_succeeds(
            f"git --git-dir /var/cache/forgeproxy/repos/octocat/hello-world.git rev-parse refs/heads/main | grep -Fx '{updated_rev}'"
        )
        client.wait_until_succeeds("test -f /tmp/slow-upload-pack.status")
        client.succeed("grep -qx 0 /tmp/slow-upload-pack.status")
        proxy.wait_until_succeeds(f"! test -d '{old_generation}'")
        proxy.wait_until_succeeds(
            "test $(find /var/cache/forgeproxy/repos/.generations/octocat/hello-world.git -mindepth 1 -maxdepth 1 -type d | wc -l) -eq 1"
        )

    with subtest("Shallow-first clone still results in a stored generation"):
        client.succeed(
            "rm -rf /tmp/shallow-only && "
            "git clone --depth=1 https://octocat:secret123@proxy/octocat/shallow-only.git /tmp/shallow-only"
        )
        proxy.wait_until_succeeds(
            "test -L /var/cache/forgeproxy/repos/octocat/shallow-only.git"
        )
        proxy.wait_until_succeeds(
            "find /var/cache/forgeproxy/repos/.generations/octocat/shallow-only.git -mindepth 1 -maxdepth 1 -type d | grep -q ."
        )

    with subtest("Successful clone cleans tee capture"):
        proxy.wait_until_succeeds(
            "! test -d /var/cache/forgeproxy/repos/_tee/octocat/hello-world || "
            "find /var/cache/forgeproxy/repos/_tee/octocat/hello-world -mindepth 1 -maxdepth 1 -type d | wc -l | grep -qx 0"
        )
  '';
}
