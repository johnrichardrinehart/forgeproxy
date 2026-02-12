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
    pkgs.runCommand "ssh-authz-test-certs"
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
  # Test SSH keypairs (generated at Nix eval time)
  # ---------------------------------------------------------------------------
  testSshKeys =
    pkgs.runCommand "test-ssh-keys"
      {
        nativeBuildInputs = [ pkgs.openssh ];
      }
      ''
        mkdir -p $out
        ssh-keygen -t ed25519 -f $out/alice -N "" -C "alice@test"
        ssh-keygen -t ed25519 -f $out/bob -N "" -C "bob@test"
        ssh-keygen -l -f $out/alice.pub -E sha256 | awk '{print $2}' > $out/alice.fp
        ssh-keygen -l -f $out/bob.pub -E sha256 | awk '{print $2}' > $out/bob.fp
      '';

  # ---------------------------------------------------------------------------
  # forgecache configuration YAML for the test environment
  # ---------------------------------------------------------------------------
  testConfigYaml = pkgs.writeText "ssh-authz-test-config.yaml" ''
    upstream:
      hostname: "ghe"
      api_url: "http://ghe:3000/api/v1"
      admin_token_env: "FORGE_ADMIN_TOKEN"

    upstream_credentials:
      default_mode: "pat"

    backend_type: "gitea"

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
  name = "forgecache-ssh-authz";
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
              DISABLE_REGISTRATION = false;
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

    # ── forgecache (SSH only — no nginx needed) ──────────────────────────
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

        # Extra packages needed by the test script on this node
        environment.systemPackages = with pkgs; [
          git
          redis
          curl
          jq
        ];

        # Trust the test CA so forgecache (reqwest) validates the mock GHE cert
        security.pki.certificateFiles = [ "${testCerts}/ca.crt" ];

        networking.firewall.allowedTCPPorts = [
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
          openssh
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

    # ── Seed Gitea with users, repos, and collaborators ──────────────────
    with subtest("Seed Gitea"):
        # Create admin user (octocat)
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

        # Create user alice (non-admin)
        ghe.succeed(
            f"curl -sf"
            f" -X POST http://localhost:3000/api/v1/admin/users"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"login_name": "alice", "username": "alice", "password": "alice123", "email": "alice@test.local", "must_change_password": false}}'"""
        )

        # Create user bob (non-admin)
        ghe.succeed(
            f"curl -sf"
            f" -X POST http://localhost:3000/api/v1/admin/users"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"login_name": "bob", "username": "bob", "password": "bob12345", "email": "bob@test.local", "must_change_password": false}}'"""
        )

        # Create private repo: octocat/repo-cached
        ghe.succeed(
            f"curl -sf"
            f" -X POST http://localhost:3000/api/v1/user/repos"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"name": "repo-cached", "private": true, "auto_init": false}}'"""
        )

        # Create private repo: octocat/repo-uncached
        ghe.succeed(
            f"curl -sf"
            f" -X POST http://localhost:3000/api/v1/user/repos"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"name": "repo-uncached", "private": true, "auto_init": false}}'"""
        )

        # Push initial content to repo-cached
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "cd $tmp && "
            "git init -b main && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "echo 'cached repo' > README.md && "
            "git add README.md && "
            "git commit -m 'Initial commit' && "
            "git remote add origin http://octocat:secret123@localhost:3000/octocat/repo-cached.git && "
            "git push -u origin main"
        )

        # Push initial content to repo-uncached
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "cd $tmp && "
            "git init -b main && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "echo 'uncached repo' > README.md && "
            "git add README.md && "
            "git commit -m 'Initial commit' && "
            "git remote add origin http://octocat:secret123@localhost:3000/octocat/repo-uncached.git && "
            "git push -u origin main"
        )

        # Add alice as collaborator on both repos (read permission)
        ghe.succeed(
            f"curl -sf"
            f" -X PUT http://localhost:3000/api/v1/repos/octocat/repo-cached/collaborators/alice"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"permission": "read"}}'"""
        )
        ghe.succeed(
            f"curl -sf"
            f" -X PUT http://localhost:3000/api/v1/repos/octocat/repo-uncached/collaborators/alice"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"permission": "read"}}'"""
        )

        # Do NOT add bob to either repo

    # ── Pre-seed KeyDB with fingerprint→username mappings ────────────────
    with subtest("Seed KeyDB with SSH fingerprint mappings"):
        alice_fp = proxy.succeed("cat ${testSshKeys}/alice.fp").strip()
        bob_fp = proxy.succeed("cat ${testSshKeys}/bob.fp").strip()

        proxy.succeed(
            f"redis-cli -h keydb SET 'forgecache:ssh:auth:{alice_fp}' 'alice' EX 3600"
        )
        proxy.succeed(
            f"redis-cli -h keydb SET 'forgecache:ssh:auth:{bob_fp}' 'bob' EX 3600"
        )

    # ── Populate cache for repo-cached only ──────────────────────────────
    with subtest("Populate local cache for repo-cached"):
        proxy.succeed(
            "mkdir -p /var/cache/forgecache/repos/octocat"
        )
        proxy.succeed(
            "git clone --bare http://octocat:secret123@ghe:3000/octocat/repo-cached.git"
            " /var/cache/forgecache/repos/octocat/repo-cached.git"
        )
        proxy.succeed(
            "chown -R forgecache:forgecache /var/cache/forgecache/repos"
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
        proxy.wait_for_open_port(2222)

    # ── Prepare client SSH keys ──────────────────────────────────────────
    with subtest("Prepare client SSH keys"):
        client.succeed(
            "cp ${testSshKeys}/alice /tmp/alice_key && chmod 600 /tmp/alice_key"
        )
        client.succeed(
            "cp ${testSshKeys}/bob /tmp/bob_key && chmod 600 /tmp/bob_key"
        )

    # ── Subtest 1: Privileged user, uncached repo ────────────────────────
    with subtest("Alice can access uncached repo (not denied)"):
        result = client.succeed(
            "GIT_SSH_COMMAND='ssh -i /tmp/alice_key"
            " -o StrictHostKeyChecking=no"
            " -o UserKnownHostsFile=/dev/null"
            " -p 2222'"
            " git ls-remote git@proxy:octocat/repo-uncached.git 2>&1"
            " || true"
        )
        assert "Access denied" not in result, \
            f"Alice should not be denied access to repo-uncached, got: {result}"

    # ── Subtest 2: Privileged user, cached repo ──────────────────────────
    with subtest("Alice can clone cached repo"):
        result = client.succeed(
            "GIT_SSH_COMMAND='ssh -i /tmp/alice_key"
            " -o StrictHostKeyChecking=no"
            " -o UserKnownHostsFile=/dev/null"
            " -p 2222'"
            " git ls-remote git@proxy:octocat/repo-cached.git"
        )
        # ls-remote should return ref lines (e.g. HEAD, refs/heads/main)
        assert "HEAD" in result or "refs/" in result, \
            f"Expected ref lines from ls-remote, got: {result}"

    # ── Subtest 3: Unprivileged user, cached repo ────────────────────────
    with subtest("Bob is denied access to cached repo"):
        result = client.succeed(
            "GIT_SSH_COMMAND='ssh -i /tmp/bob_key"
            " -o StrictHostKeyChecking=no"
            " -o UserKnownHostsFile=/dev/null"
            " -p 2222'"
            " git ls-remote git@proxy:octocat/repo-cached.git 2>&1"
            " || true"
        )
        assert "Access denied" in result, \
            f"Bob should be denied access to repo-cached, got: {result}"

    # ── Subtest 4: Unprivileged user, uncached repo ──────────────────────
    with subtest("Bob is denied access to uncached repo"):
        result = client.succeed(
            "GIT_SSH_COMMAND='ssh -i /tmp/bob_key"
            " -o StrictHostKeyChecking=no"
            " -o UserKnownHostsFile=/dev/null"
            " -p 2222'"
            " git ls-remote git@proxy:octocat/repo-uncached.git 2>&1"
            " || true"
        )
        assert "Access denied" in result, \
            f"Bob should be denied access to repo-uncached, got: {result}"
  '';
}
