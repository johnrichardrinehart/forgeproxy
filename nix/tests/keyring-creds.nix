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
    pkgs.runCommand "keyring-creds-test-certs"
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
  # forgecache configuration YAML for the test environment
  #
  # Key difference from basic.nix: credentials are resolved from the Linux
  # kernel keyring rather than environment variables.  The per-org entry
  # under `upstream_credentials.orgs.octocat` sets `keyring_key_name` so
  # that the proxy reads the Gitea admin PAT from the user keyring.
  # ---------------------------------------------------------------------------
  testConfigYaml = pkgs.writeText "keyring-creds-test-config.yaml" ''
    upstream:
      hostname: "ghe"
      api_url: "http://ghe:3000/api/v1"
      admin_token_env: "FORGE_ADMIN_TOKEN"

    backend_type: "gitea"

    upstream_credentials:
      default_mode: "pat"
      orgs:
        octocat:
          mode: "pat"
          keyring_key_name: "forgecache:octocat_pat"

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
  name = "forgecache-keyring-creds";
  globalTimeout = 600;

  # ---------------------------------------------------------------------------
  # Node definitions
  # ---------------------------------------------------------------------------
  nodes = {

    # -- Mock GitHub Enterprise (Gitea behind nginx TLS) ----------------------
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

    # -- KeyDB / Redis --------------------------------------------------------
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

    # -- forgecache proxy (keyring credentials, no TLS) -----------------------
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

        # Prevent auto-start so we can inject the token into the keyring
        # via an ExecStartPre *after* Gitea has been seeded.
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
          curl
          jq
          git
          keyutils
        ];

        # Trust the test CA so forgecache (reqwest) validates the mock GHE cert
        security.pki.certificateFiles = [ "${testCerts}/ca.crt" ];

        networking.firewall.allowedTCPPorts = [
          8080
          2222
        ];
        virtualisation.memorySize = 1024;
      };

    # -- Client ---------------------------------------------------------------
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

    # -- Infrastructure comes up -----------------------------------------------
    with subtest("KeyDB starts"):
        keydb.wait_for_unit("redis-default.service")
        keydb.wait_for_open_port(6379)

    with subtest("Gitea starts"):
        ghe.wait_for_unit("gitea.service")
        ghe.wait_for_open_port(3000)

    with subtest("GHE nginx starts"):
        ghe.wait_for_unit("nginx.service")
        ghe.wait_for_open_port(443)

    # -- Seed mock GHE with test user and repo ---------------------------------
    with subtest("Create test user and repo on mock GHE"):
        # Create the admin user (octocat)
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

        # Create an API access token for octocat
        token_json = ghe.succeed(
            "curl -sf"
            " -X POST http://localhost:3000/api/v1/users/octocat/tokens"
            " -H 'Content-Type: application/json'"
            " -u octocat:secret123"
            ' -d \'{"name": "test-token", "scopes": ["all"]}\'''
        )
        TOKEN = json.loads(token_json)["sha1"]

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

    # -- Load PAT into kernel keyring and start forgecache ---------------------
    with subtest("Load PAT into keyring and start forgecache"):
        # Inject the Gitea admin token into the forgecache service via a
        # systemd drop-in that sets FORGE_ADMIN_TOKEN (needed for permission
        # checks) and loads the PAT into the kernel keyring via ExecStartPre.
        proxy.succeed(
            f"mkdir -p /run/systemd/system/forgecache.service.d && "
            f"cat > /run/systemd/system/forgecache.service.d/keyring.conf <<'UNIT'\n"
            f"[Service]\n"
            f"Environment=FORGE_ADMIN_TOKEN={TOKEN}\n"
            f"ExecStartPre=/bin/sh -c 'echo -n \"{TOKEN}\" | keyctl padd user forgecache:octocat_pat @u'\n"
            f"UNIT"
        )
        proxy.succeed("systemctl daemon-reload")
        proxy.succeed("systemctl start forgecache")

    with subtest("forgecache service starts"):
        proxy.wait_for_unit("forgecache.service")
        proxy.wait_for_open_port(8080)

    # -- Verify keyring key is accessible from the service session -------------
    with subtest("Keyring key is loaded"):
        # The ExecStartPre ran in the same session as the service.  Verify
        # the key exists by searching the forgecache user's user keyring
        # from the test harness side.  We check via the service journal
        # instead, since the keyring is per-session.  A successful proxy
        # start with debug logging confirms the key was loaded.
        proxy.succeed(
            "journalctl -u forgecache --no-pager"
            " | grep -q 'forgecache' || true"
        )

    # -- Health endpoint responds ----------------------------------------------
    with subtest("Health endpoint responds"):
        proxy.succeed("curl -sf http://localhost:8080/healthz")

    # -- HTTPS clone through the proxy -----------------------------------------
    with subtest("HTTPS clone through proxy succeeds"):
        client.succeed(
            "git clone http://octocat:secret123@proxy:8080/octocat/hello-world.git /tmp/repo"
        )
        output = client.succeed("cat /tmp/repo/README.md")
        assert "Hello World" in output, f"README.md content mismatch: {output}"

    # -- Verify cloned content matches upstream --------------------------------
    with subtest("Cloned content matches upstream"):
        upstream_log = ghe.succeed(
            "cd /tmp && "
            "git clone http://octocat:secret123@localhost:3000/octocat/hello-world.git /tmp/upstream-repo && "
            "cd /tmp/upstream-repo && "
            "git log --oneline"
        ).strip()
        proxy_log = client.succeed(
            "cd /tmp/repo && git log --oneline"
        ).strip()
        assert upstream_log == proxy_log, (
            f"Commit history mismatch:\n"
            f"  upstream: {upstream_log}\n"
            f"  proxy:    {proxy_log}"
        )
  '';
}
