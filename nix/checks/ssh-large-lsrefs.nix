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

  testCerts =
    pkgs.runCommand "ssh-large-lsrefs-test-certs"
      {
        nativeBuildInputs = [ pkgs.openssl ];
      }
      ''
        mkdir -p $out

        openssl req -new -x509 -nodes -days 365 \
          -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
          -keyout $out/ca.key -out $out/ca.crt \
          -subj "/CN=ForgeProxy Test CA"

        openssl req -new -nodes \
          -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
          -keyout $out/ghe.key -out $out/ghe.csr \
          -subj "/CN=ghe"
        openssl x509 -req -in $out/ghe.csr \
          -CA $out/ca.crt -CAkey $out/ca.key -CAcreateserial \
          -out $out/ghe.crt -days 365 -sha256 \
          -extfile <(printf "subjectAltName=DNS:ghe")

        openssl req -new -nodes \
          -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
          -keyout $out/proxy.key -out $out/proxy.csr \
          -subj "/CN=proxy"
        openssl x509 -req -in $out/proxy.csr \
          -CA $out/ca.crt -CAkey $out/ca.key -CAcreateserial \
          -out $out/proxy.crt -days 365 -sha256 \
          -extfile <(printf "subjectAltName=DNS:proxy")
      '';

  testSshKeys =
    pkgs.runCommand "ssh-large-lsrefs-test-ssh-keys"
      {
        nativeBuildInputs = [ pkgs.openssh ];
      }
      ''
        mkdir -p $out
        ssh-keygen -t ed25519 -f $out/alice -N "" -C "alice@test"
        ssh-keygen -l -f $out/alice.pub -E sha256 | awk '{print $2}' > $out/alice.fp
      '';

  testConfigYaml = pkgs.writeText "ssh-large-lsrefs-test-config.yaml" ''
    upstream:
      hostname: "ghe"
      api_url: "http://ghe:3000/api/v1"
      git_url_base: "http://ghe:3000"
      admin_token_env: "FORGE_ADMIN_TOKEN"

    upstream_credentials:
      default_mode: "pat"
      orgs:
        octocat:
          mode: "pat"
          keyring_key_name: "FORGE_ADMIN_TOKEN"

    backend_type: "gitea"

    proxy:
      ssh_listen: "0.0.0.0:2222"
      http_listen: "127.0.0.1:8080"
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
      max_concurrent_upstream_clones_per_repo_across_instances: 4
      max_concurrent_upstream_clones_per_repo_per_instance: 4

    fetch_schedule:
      default_interval: 1800
      delta_threshold: 1024
      backoff_factor: 2
      max_interval: 86400
      rolling_window: 1800

    bundles:
      min_clone_count_for_bundles: 2
      bundle_lock_ttl: 300
      generate_filtered_bundles: false

    storage:
      local:
        path: "${cacheLayout.cacheRoot}"
        max_percent: 0.80
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
  name = "forgeproxy-ssh-large-lsrefs";
  # This test boots five VMs, seeds a ref-heavy repo, and then exercises
  # an uncached SSH v2 clone path. Give it enough headroom to absorb slower
  # builders without weakening the large-ls-refs coverage.
  globalTimeout = 900;

  nodes = {
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

    valkey = common.mkValkeyNode { };

    s3 = common.mkS3Node { };

    proxy =
      {
        config,
        pkgs,
        lib,
        ...
      }:
      {
        imports = [ self.nixosModules.forgeproxy ];

        services.forgeproxy = {
          enable = true;
          package = pkgs.forgeproxy;
          configFile = testConfigYaml;
          logLevel = "info";
        };

        systemd.services.forgeproxy.wantedBy = lib.mkForce [ ];
        systemd.services.forgeproxy.serviceConfig.Restart = lib.mkForce "no";
        systemd.services.forgeproxy.unitConfig.ConditionPathExists = "/run/forgeproxy-enable";
        systemd.services.forgeproxy.environment = {
          AWS_ACCESS_KEY_ID = "minioadmin";
          AWS_SECRET_ACCESS_KEY = "minioadmin";
          AWS_DEFAULT_REGION = "us-east-1";
        };

        services.amazon-ssm-agent.enable = lib.mkForce false;

        environment.systemPackages = with pkgs; [
          git
          redis
          curl
          jq
        ];

        security.pki.certificateFiles = [ "${testCerts}/ca.crt" ];

        networking.firewall.allowedTCPPorts = [ 2222 ];
        virtualisation.memorySize = 768;
      };

    client =
      {
        pkgs,
        ...
      }:
      {
        environment.systemPackages = with pkgs; [
          git
          openssh
        ];
      };
  };

  testScript = ''
    import json

    start_all()

    ${common.valkeyStartScript}

    with subtest("Gitea starts"):
        ghe.wait_for_unit("gitea.service")
        ghe.wait_for_open_port(3000)

    with subtest("GHE nginx starts"):
        ghe.wait_for_unit("nginx.service")
        ghe.wait_for_open_port(443)

    ${common.s3StartScript}

    with subtest("Seed Gitea"):
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

        token_json = ghe.succeed(
            "curl -sf"
            " -X POST http://localhost:3000/api/v1/users/octocat/tokens"
            " -H 'Content-Type: application/json'"
            " -u octocat:secret123"
            ' -d \'{"name": "test-token", "scopes": ["all"]}\'''
        )
        TOKEN = json.loads(token_json)["sha1"]

        ghe.succeed(
            f"curl -sf"
            f" -X POST http://localhost:3000/api/v1/admin/users"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"login_name": "alice", "username": "alice", "password": "alice123", "email": "alice@test.local", "must_change_password": false}}'"""
        )

        ghe.succeed(
            f"curl -sf"
            f" -X POST http://localhost:3000/api/v1/user/repos"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"name": "repo-large-lsrefs", "private": true, "auto_init": false}}'"""
        )

        # Seed the bare repo in-place instead of pushing many refs through
        # Gitea's receive-pack path, which is too slow for a VM regression test.
        # 20k tags is still large enough to exercise the uncached ls-refs path
        # without consuming most of the test's startup budget on repo seeding.
        ghe.succeed(
            "su -s /bin/sh gitea -c '"
            "set -e; "
            "tmp=$(mktemp -d); "
            "trap \"rm -rf \\\"$tmp\\\"\" EXIT; "
            "repo=$(find /var/lib/gitea -type d -name repo-large-lsrefs.git -print -quit); "
            "test -n \"$repo\"; "
            "git init -b main \"$tmp/work\"; "
            "cd \"$tmp/work\"; "
            "git config user.email test@test.local; "
            "git config user.name Test; "
            "echo ref-heavy > README; "
            "git add README; "
            "git commit -m initial; "
            "commit=$(git rev-parse HEAD); "
            "git --git-dir=\"$repo\" fetch \"$tmp/work/.git\" refs/heads/main:refs/heads/main; "
            "git --git-dir=\"$repo\" symbolic-ref HEAD refs/heads/main; "
            "for i in $(seq 1 20000); do "
            "  printf \"create refs/tags/tag-%s %s\\\\n\" \"$i\" \"$commit\"; "
            "done | git --git-dir=\"$repo\" update-ref --stdin; "
            "git --git-dir=\"$repo\" pack-refs --all'"
        )

        ghe.succeed(
            f"curl -sf"
            f" -X PUT http://localhost:3000/api/v1/repos/octocat/repo-large-lsrefs/collaborators/alice"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"permission": "read"}}'"""
        )

    with subtest("Seed Valkey with SSH fingerprint mappings"):
        alice_fp = proxy.succeed("cat ${testSshKeys}/alice.fp").strip()
        proxy.succeed(
            f"redis-cli -h valkey SET 'forgeproxy:ssh:auth:{alice_fp}' 'alice' EX 3600"
        )

    with subtest("Start forgeproxy with admin token"):
        proxy.succeed(
            f"mkdir -p /run/systemd/system/forgeproxy.service.d && "
            f"cat > /run/systemd/system/forgeproxy.service.d/token.conf <<'UNIT'\n"
            f"[Service]\n"
            f"ExecStartPre=/bin/sh -c 'echo -n \"{TOKEN}\" | keyctl padd user FORGE_ADMIN_TOKEN @u >/dev/null'\n"
            f"UNIT"
        )
        proxy.succeed("touch /run/forgeproxy-enable")
        proxy.succeed("systemctl daemon-reload")
        proxy.succeed("systemctl start forgeproxy")
        proxy.wait_for_open_port(2222)

    with subtest("Prepare client SSH keys"):
        client.succeed(
            "cp ${testSshKeys}/alice /tmp/alice_key && chmod 600 /tmp/alice_key"
        )

    with subtest("Cache-miss v2 clone survives a large uncached ls-refs response"):
        large_lsrefs_repo = "${cacheLayout.repoPath "octocat/repo-large-lsrefs"}"
        large_lsrefs_generation_dir = "${cacheLayout.generationDir "octocat/repo-large-lsrefs"}"
        large_lsrefs_mirror = "${cacheLayout.mirrorPath "octocat/repo-large-lsrefs"}"
        large_lsrefs_tee_dir = "${cacheLayout.teeDir "octocat/repo-large-lsrefs"}"

        proxy.succeed(
            f"rm -rf {large_lsrefs_repo} {large_lsrefs_generation_dir} "
            f"{large_lsrefs_mirror} {large_lsrefs_tee_dir}"
        )
        client.succeed("rm -rf /tmp/repo-large-lsrefs")
        client.succeed(
            "env "
            "GIT_PROTOCOL=version=2 "
            "GIT_SSH_COMMAND='ssh -i /tmp/alice_key"
            " -o StrictHostKeyChecking=no"
            " -o UserKnownHostsFile=/dev/null"
            " -p 2222' "
            "timeout 20s "
            "git clone git@proxy:octocat/repo-large-lsrefs.git /tmp/repo-large-lsrefs"
        )
        client.succeed("test -d /tmp/repo-large-lsrefs/.git")
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy.service --no-pager"
            " | grep -F '\"request_kind\":\"fetch\"'"
            " | grep -F '\"repo\":\"octocat/repo-large-lsrefs\"'",
            timeout=20,
        )
  '';
}
