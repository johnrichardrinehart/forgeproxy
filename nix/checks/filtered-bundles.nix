{
  self,
  pkgs,
  lib,
}:

let
  common = import ./common.nix { inherit pkgs lib; };
  cacheLayout = import ../lib/cache-layout.nix {
    inherit lib;
    root = "/var/cache/forgeproxy";
  };

  # ---------------------------------------------------------------------------
  # Test TLS certificates (generated at Nix eval time)
  # ---------------------------------------------------------------------------
  testCerts =
    pkgs.runCommand "filtered-bundles-test-certs"
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
      '';

  # ---------------------------------------------------------------------------
  # forgeproxy configuration YAML – filtered bundles enabled
  # ---------------------------------------------------------------------------
  testConfigYaml = pkgs.writeText "forgeproxy-filtered-bundles-config.yaml" ''
    backend_type: "gitea"

    upstream:
      hostname: "ghe"
      api_url: "http://ghe:3000/api/v1"
      git_url_base: "http://ghe:3000"
      admin_token_env: "FORGE_ADMIN_TOKEN"

    upstream_credentials:
      default_mode: "pat"

    proxy:
      ssh_listen: "0.0.0.0:2222"
      http_listen: "0.0.0.0:8080"
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
      min_clone_count_for_bundles: 0
      bundle_lock_ttl: 300
      generate_filtered_bundles: true

    storage:
      local:
        path: "${cacheLayout.cacheRoot}"
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
  '';

in
pkgs.testers.runNixOSTest {
  name = "forgeproxy-filtered-bundles";
  globalTimeout = 210;

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

    # -- Valkey / Redis ---------------------------------------------------------
    valkey = common.mkValkeyNode { };

    s3 = common.mkS3Node { };

    # -- forgeproxy proxy (no TLS, direct HTTP) --------------------------------
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
        ];

        services.forgeproxy = {
          enable = true;
          package = pkgs.forgeproxy;
          configFile = testConfigYaml;
          logLevel = "debug";
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

        environment.systemPackages = with pkgs; [
          curl
          iptables
          jq
          redis
        ];

        # Trust the test CA so forgeproxy (reqwest) validates the mock GHE cert
        security.pki.certificateFiles = [ "${testCerts}/ca.crt" ];

        networking.firewall.allowedTCPPorts = [
          8080
          2222
        ];
        virtualisation.memorySize = 768;
      };

    # -- Client ----------------------------------------------------------------
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
    ghe.start()
    valkey.start()
    s3.start()

    # -- Infrastructure comes up -----------------------------------------------
    ${common.valkeyStartScript}

    ${common.s3StartScript}

    with subtest("Gitea starts"):
        ghe.wait_for_unit("gitea.service")
        ghe.wait_for_open_port(3000)

    with subtest("GHE nginx starts"):
        ghe.wait_for_unit("nginx.service")
        ghe.wait_for_open_port(443)

    # -- Seed mock GHE with test user and repo ---------------------------------
    with subtest("Create test user and repo on mock GHE"):
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

        ghe.succeed(
            "curl -sf"
            " -X POST http://localhost:3000/api/v1/user/repos"
            " -H 'Content-Type: application/json'"
            " -u ${common.giteaAdminUser}:${common.giteaAdminPassword}"
            ' -d \'{"name": "hello-world", "auto_init": false}\'''
        )

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
            "git remote add origin http://${common.giteaAdminUser}:${common.giteaAdminPassword}@localhost:3000/${common.giteaAdminUser}/hello-world.git && "
            "git push -u origin main"
        )

        ghe.succeed(
            "curl -sf"
            " -u ${common.giteaAdminUser}:${common.giteaAdminPassword}"
            " http://localhost:3000/api/v1/repos/${common.giteaAdminUser}/hello-world"
            " | jq -e '.permissions.pull == true'"
        )

    # -- Proxy comes up with filtered-bundle config ----------------------------
    with subtest("Start proxy and client VMs after upstream is ready"):
        proxy.start()
        client.start()

    with subtest("forgeproxy service starts with generate_filtered_bundles enabled"):
        proxy.wait_for_unit("forgeproxy.service")
        proxy.wait_for_open_port(8080)

    with subtest("Health endpoint responds"):
        proxy.succeed(
            "curl -sf http://localhost:8080/healthz"
            " | jq -e '.checks.valkey.ok == true'"
        )

    # -- Clone through the proxy (HTTP, no TLS) --------------------------------
    with subtest("HTTP clone through proxy succeeds"):
        client.succeed(
            "git clone http://octocat:secret123@proxy:8080/octocat/hello-world.git /tmp/repo"
        )
        output = client.succeed("cat /tmp/repo/README.md")
        assert "Hello World" in output, f"README.md content mismatch: {output}"

    # -- Verify the proxy is still healthy after the clone ---------------------
    with subtest("Proxy remains healthy after clone"):
        proxy.succeed("curl -sf http://localhost:8080/healthz")
        proxy.succeed(
            "systemctl is-active forgeproxy.service"
        )

    with subtest("Delta publish clears hydration guard before blocked bundle upload"):
        ghe.succeed(
            "set -euo pipefail; "
            "tmp=$(mktemp -d); "
            "git clone http://${common.giteaAdminUser}:${common.giteaAdminPassword}@localhost:3000/${common.giteaAdminUser}/hello-world.git $tmp/repo; "
            "cd $tmp/repo; "
            "git config user.email test@test.local; "
            "git config user.name Test; "
            "echo 'Delta content' > delta.txt; "
            "git add delta.txt; "
            "git commit -m 'Delta commit'; "
            "git push origin main"
        )

        proxy.wait_until_succeeds(
            "test \"$(redis-cli -h valkey HGET 'forgeproxy:repo:octocat/hello-world' status)\" = ready "
            "&& test -z \"$(redis-cli -h valkey HGET 'forgeproxy:repo:octocat/hello-world' hydrating_node_id)\""
        )
        proxy.succeed("sleep 2")
        since = proxy.succeed("date --iso-8601=seconds --utc").strip()
        proxy.succeed(
            "for ip in $(getent ahostsv4 s3 | awk '{ print $1 }' | sort -u); do "
            "iptables -I OUTPUT -p tcp -d \"$ip\" --dport 9000 -j DROP; "
            "done; "
            "for ip in $(getent ahostsv6 s3 | awk '{ print $1 }' | sort -u); do "
            "ip6tables -I OUTPUT -p tcp -d \"$ip\" --dport 9000 -j DROP; "
            "done"
        )

        client.succeed(
            "rm -rf /tmp/repo-delta /tmp/repo-delta.log; "
            "git clone http://octocat:secret123@proxy:8080/octocat/hello-world.git /tmp/repo-delta >/tmp/repo-delta.log 2>&1 & "
            "echo $! >/tmp/repo-delta.pid"
        )

        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy.service --since '"
            + since
            + "' --no-pager | grep -F 'creating full bundle' "
            "&& test \"$(redis-cli -h valkey HGET 'forgeproxy:repo:octocat/hello-world' status)\" = ready "
            "&& test -z \"$(redis-cli -h valkey HGET 'forgeproxy:repo:octocat/hello-world' hydrating_node_id)\""
        )
        proxy.fail(
            "journalctl -u forgeproxy.service --since '"
            + since
            + "' --no-pager | grep -F 'bundle uploaded'"
        )
        client.wait_until_succeeds("test -f /tmp/repo-delta/delta.txt")

        proxy.succeed(
            "for ip in $(getent ahostsv4 s3 | awk '{ print $1 }' | sort -u); do "
            "iptables -D OUTPUT -p tcp -d \"$ip\" --dport 9000 -j DROP || true; "
            "done; "
            "for ip in $(getent ahostsv6 s3 | awk '{ print $1 }' | sort -u); do "
            "ip6tables -D OUTPUT -p tcp -d \"$ip\" --dport 9000 -j DROP || true; "
            "done"
        )

        client.succeed("grep -F 'Delta content' /tmp/repo-delta/delta.txt")
        proxy.succeed("systemctl is-active forgeproxy.service")
  '';
}
