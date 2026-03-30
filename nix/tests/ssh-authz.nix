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
    pkgs.runCommand "ssh-authz-test-certs"
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
  # forgeproxy configuration YAML for the test environment
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
      request_wait_for_local_catch_up_secs: 60
      ssh_upload_pack_close_grace_secs: 5
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
  '';

in
pkgs.testers.runNixOSTest {
  name = "forgeproxy-ssh-authz";
  globalTimeout = 390;

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
        virtualisation.memorySize = 1536;
      };

    # ── Valkey / Redis ───────────────────────────────────────────────────
    valkey = common.mkValkeyNode { };

    s3 = common.mkS3Node { };

    # ── forgeproxy (SSH only — no nginx needed) ──────────────────────────
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
          logLevel = "info";
          allowEnvSecretFallback = true;
        };

        # Keep the unit available, but block startup until the test script
        # writes the admin token and explicitly allows the service to start.
        systemd.services.forgeproxy.wantedBy = lib.mkForce [ ];
        systemd.services.forgeproxy.serviceConfig.Restart = lib.mkForce "no";
        systemd.services.forgeproxy.unitConfig.ConditionPathExists = "/run/forgeproxy-enable";

        # Dummy AWS credentials to prevent SDK timeout reaching IMDS
        systemd.services.forgeproxy.environment = {
          AWS_ACCESS_KEY_ID = "minioadmin";
          AWS_SECRET_ACCESS_KEY = "minioadmin";
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

        # Trust the test CA so forgeproxy (reqwest) validates the mock GHE cert
        security.pki.certificateFiles = [ "${testCerts}/ca.crt" ];

        networking.firewall.allowedTCPPorts = [
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
          openssh
        ];
      };
  };

  # ---------------------------------------------------------------------------
  # Test script
  # ---------------------------------------------------------------------------
  testScript = ''
    import json
    import shlex

    start_all()

    def ssh_cmd_words(*, key_path="/tmp/alice_key"):
        return " ".join(
            [
                "ssh",
                "-oServerAliveInterval=5",
                "-oServerAliveCountMax=12",
                f"-i {key_path}",
                "-o StrictHostKeyChecking=no",
                "-o UserKnownHostsFile=/dev/null",
                "-p 2222",
            ]
        )

    def ssh_clone_env_words(trace_name, key_path="/tmp/alice_key"):
        return f"GIT_SSH_COMMAND={shlex.quote(ssh_cmd_words(key_path=key_path))}"

    def ssh_clone_cmd(trace_name, repo, dest, *, key_path="/tmp/alice_key", extra_args=""):
        extra = f"{extra_args} " if extra_args else ""
        return (
            f"env {ssh_clone_env_words(trace_name, key_path=key_path)} "
            f"git clone {extra}git@proxy:{repo}.git {dest}"
        )

    def ssh_clone_plain_env_words(key_path="/tmp/alice_key"):
        return f"GIT_SSH_COMMAND={shlex.quote(ssh_cmd_words(key_path=key_path))}"

    def dump_clone_debug(trace_name):
        print(
            client.succeed(
                "set -eu; "
                f"trace_base=/tmp/{trace_name}; "
                "echo '==== clone debug artifacts ===='; "
                "echo '(normal ssh-authz mode keeps clone tracing disabled)'; "
                "for suffix in "
                ".git.trace.log "
                ".packet.trace.log "
                ".trace2.json "
                ".ssh.log; do "
                "  file=\"''${trace_base}''${suffix}\"; "
                "  echo \"---- ''${file} ----\"; "
                "  if [ -f \"$file\" ]; then "
                "    tail -n 200 \"$file\"; "
                "  else "
                "    echo '(missing)'; "
                "  fi; "
                "done; "
                "pack_file=\"''${trace_base}.pack.trace\"; "
                "echo \"---- ''${pack_file} ----\"; "
                "if [ -f \"$pack_file\" ]; then "
                "  wc -c \"$pack_file\"; "
                "  sha256sum \"$pack_file\"; "
                "else "
                "  echo '(missing)'; "
                "fi"
            )
        )

    def dump_file_tail(path, label, lines=200):
        print(
            client.succeed(
                "set -eu; "
                f"file={shlex.quote(path)}; "
                f"echo '---- {label} ({path}) ----'; "
                "if [ -f \"$file\" ]; then "
                f"  tail -n {lines} \"$file\"; "
                "else "
                "  echo '(missing)'; "
                "fi"
            )
        )

    def wait_for_close_handshake(repo):
        repo_match = f'"repo":"{repo}"'
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy --since '5m ago' --no-pager "
            f"| grep -F {shlex.quote(repo_match)} "
            "| grep -F 'awaiting SSH client channel close before sending server close'"
        )
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy --since '5m ago' --no-pager "
            f"| grep -F {shlex.quote(repo_match)} "
            "| grep -E '\"close_reason\":\"(client-close|grace-timeout)\"' "
            "| grep -F 'SSH upload-pack close sent'"
        )
        handshake_log = proxy.succeed(
            "journalctl -u forgeproxy --since '5m ago' --no-pager "
            f"| grep -F {shlex.quote(repo_match)} "
            "| grep -E 'SSH upload-pack exit-status sent|SSH upload-pack EOF sent|awaiting SSH client channel close before sending server close|SSH client channel close observed|SSH upload-pack close sent'"
        )
        lines = handshake_log.splitlines()

        def find_index(fragment):
            for index, line in enumerate(lines):
                if fragment in line:
                    return index
            raise Exception(f"missing log fragment for {repo}: {fragment}\n{handshake_log}")

        exit_status_index = find_index("SSH upload-pack exit-status sent")
        eof_index = find_index("SSH upload-pack EOF sent")
        await_index = find_index("awaiting SSH client channel close before sending server close")
        close_index = find_index("SSH upload-pack close sent")
        assert exit_status_index < eof_index < await_index < close_index, handshake_log

        client_close_indices = [
            index
            for index, line in enumerate(lines)
            if "SSH client channel close observed" in line
        ]
        if client_close_indices:
            client_close_index = client_close_indices[0]
            if client_close_index > close_index:
                assert '"close_reason":"grace-timeout"' in lines[close_index], handshake_log
            else:
                assert await_index < client_close_index <= close_index, handshake_log

    def ssh_clone_succeed(trace_name, repo, dest, *, key_path="/tmp/alice_key", extra_args=""):
        try:
            client.succeed(
                ssh_clone_cmd(
                    trace_name,
                    repo,
                    dest,
                    key_path=key_path,
                    extra_args=extra_args,
                )
            )
        except Exception:
            dump_clone_debug(trace_name)
            raise

    # ── Infrastructure comes up ───────────────────────────────────────────
    ${common.valkeyStartScript}

    ${common.s3StartScript}

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

        # Create private repo: octocat/repo-stream (uncached full-clone regression)
        ghe.succeed(
            f"curl -sf"
            f" -X POST http://localhost:3000/api/v1/user/repos"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"name": "repo-stream", "private": true, "auto_init": false}}'"""
        )

        # Create private repo: octocat/repo-stream-live (stream-before-hydration regression)
        ghe.succeed(
            f"curl -sf"
            f" -X POST http://localhost:3000/api/v1/user/repos"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"name": "repo-stream-live", "private": true, "auto_init": false}}'"""
        )

        # Create private repo: octocat/repo-generations (generation publish/GC regression)
        ghe.succeed(
            f"curl -sf"
            f" -X POST http://localhost:3000/api/v1/user/repos"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"name": "repo-generations", "private": true, "auto_init": false}}'"""
        )

        # Create private repo: octocat/repo-many-wants (large stale-fetch regression)
        ghe.succeed(
            f"curl -sf"
            f" -X POST http://localhost:3000/api/v1/user/repos"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"name": "repo-many-wants", "private": true, "auto_init": false}}'"""
        )

        # Create private repo: octocat/repo-mirror-serve (mirror-vs-published regression)
        ghe.succeed(
            f"curl -sf"
            f" -X POST http://localhost:3000/api/v1/user/repos"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"name": "repo-mirror-serve", "private": true, "auto_init": false}}'"""
        )

        # Create public repo used to validate anonymous HTTP clone behaviour.
        ghe.succeed(
            f"curl -sf"
            f" -X POST http://localhost:3000/api/v1/user/repos"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"name": "repo-public-http", "private": false, "auto_init": false}}'"""
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

        # Push pack-heavy content to repo-stream to exercise uncached upload-pack streaming.
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "cd $tmp && "
            "git init -b main && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "for i in $(seq 1 24); do "
            "  head -c 262144 /dev/urandom > blob-$i.bin && "
            "  git add blob-$i.bin && "
            "  git commit -m \"blob-$i\"; "
            "done && "
            "git remote add origin http://octocat:secret123@localhost:3000/octocat/repo-stream.git && "
            "git push -u origin main"
        )

        # Push a larger history to repo-stream-live so the test can observe
        # client-side progress before hydration publishes the local cache.
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "cd $tmp && "
            "git init -b main && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "for i in $(seq 1 32); do "
            "  head -c 1048576 /dev/urandom > blob-$i.bin && "
            "  git add blob-$i.bin && "
            "  git commit -m \"live-$i\"; "
            "done && "
            "git remote add origin http://octocat:secret123@localhost:3000/octocat/repo-stream-live.git && "
            "git push -u origin main"
        )

        # Push initial content to repo-generations to exercise published generation swaps.
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "cd $tmp && "
            "git init -b main && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "for i in $(seq 1 3); do "
            "  echo generation-$i > file-$i.txt && "
            "  git add file-$i.txt && "
            "  git commit -m \"generation-$i\"; "
            "done && "
            "git remote add origin http://octocat:secret123@localhost:3000/octocat/repo-generations.git && "
            "git push -u origin main"
        )

        # Push initial content to repo-many-wants to exercise large ref advertisements.
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "cd $tmp && "
            "git init -b main && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "echo initial > README.md && "
            "git add README.md && "
            "git commit -m 'Initial commit' && "
            "git remote add origin http://octocat:secret123@localhost:3000/octocat/repo-many-wants.git && "
            "git push -u origin main"
        )

        # Push initial content to repo-mirror-serve to exercise serving from a fresher mirror.
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "cd $tmp && "
            "git init -b main && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "for i in $(seq 1 4); do "
            "  echo mirror-$i > file-$i.txt && "
            "  git add file-$i.txt && "
            "  git commit -m \"mirror-$i\"; "
            "done && "
            "git remote add origin http://octocat:secret123@localhost:3000/octocat/repo-mirror-serve.git && "
            "git push -u origin main"
        )

        # Push initial content to public repo for anonymous HTTP clone checks.
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "cd $tmp && "
            "git init -b main && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "echo 'public repo' > README.md && "
            "git add README.md && "
            "git commit -m 'Initial commit' && "
            "git remote add origin http://octocat:secret123@localhost:3000/octocat/repo-public-http.git && "
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
            f" -X PUT http://localhost:3000/api/v1/repos/octocat/repo-stream/collaborators/alice"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"permission": "read"}}'"""
        )
        ghe.succeed(
            f"curl -sf"
            f" -X PUT http://localhost:3000/api/v1/repos/octocat/repo-stream-live/collaborators/alice"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"permission": "read"}}'"""
        )
        ghe.succeed(
            f"curl -sf"
            f" -X PUT http://localhost:3000/api/v1/repos/octocat/repo-generations/collaborators/alice"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"permission": "read"}}'"""
        )
        ghe.succeed(
            f"curl -sf"
            f" -X PUT http://localhost:3000/api/v1/repos/octocat/repo-many-wants/collaborators/alice"
            f" -H 'Content-Type: application/json'"
            f" -H 'Authorization: token {TOKEN}'"
            f""" -d '{{"permission": "read"}}'"""
        )
        ghe.succeed(
            f"curl -sf"
            f" -X PUT http://localhost:3000/api/v1/repos/octocat/repo-mirror-serve/collaborators/alice"
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

    # ── Pre-seed Valkey with fingerprint→username mappings ────────────────
    with subtest("Seed Valkey with SSH fingerprint mappings"):
        alice_fp = proxy.succeed("cat ${testSshKeys}/alice.fp").strip()
        bob_fp = proxy.succeed("cat ${testSshKeys}/bob.fp").strip()

        proxy.succeed(
            f"redis-cli -h valkey SET 'forgeproxy:ssh:auth:{alice_fp}' 'alice' EX 3600"
        )
        proxy.succeed(
            f"redis-cli -h valkey SET 'forgeproxy:ssh:auth:{bob_fp}' 'bob' EX 3600"
        )

    # ── Start forgeproxy with admin token ────────────────────────────────
    # The ExecStartPre also pre-seeds the local cache for repo-cached so
    # the authz tests can distinguish cached vs uncached paths. We keep the
    # admin token in the service environment so it survives systemctl restarts
    # during drain tests.
    with subtest("Start forgeproxy with admin token"):
        proxy.succeed(
            f"mkdir -p /run/systemd/system/forgeproxy.service.d && "
            f"touch /run/forgeproxy-enable && "
            f"cat > /run/forgeproxy-admin-token.env <<'ENV'\n"
            f"FORGE_ADMIN_TOKEN={TOKEN}\n"
            f"ENV\n"
            f"cat > /run/systemd/system/forgeproxy.service.d/token.conf <<'UNIT'\n"
            f"[Service]\n"
            f"EnvironmentFile=/run/forgeproxy-admin-token.env\n"
            f"ExecStartPre=/bin/sh -c 'test -n \"$FORGE_ADMIN_TOKEN\"'\n"
            f"ExecStartPre=/bin/sh -c 'mkdir -p /var/cache/forgeproxy/repos/octocat && test -d /var/cache/forgeproxy/repos/octocat/repo-cached.git || git clone --bare http://octocat:secret123@ghe:3000/octocat/repo-cached.git /var/cache/forgeproxy/repos/octocat/repo-cached.git'\n"
            f"UNIT"
        )
        proxy.succeed(
            "systemctl daemon-reload && "
            "systemctl reset-failed forgeproxy && "
            "systemctl start forgeproxy"
        )
        proxy.succeed(
            "systemctl show forgeproxy -p EnvironmentFiles --no-pager | "
            "grep -F '/run/forgeproxy-admin-token.env'"
        )
        proxy.succeed(
            "systemctl show forgeproxy -p Environment --no-pager | "
            "grep -F 'FORGEPROXY_ALLOW_ENV_SECRET_FALLBACK=true'"
        )
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy.service --no-pager | "
            "grep -F 'startup init probe succeeded for upstream'"
        )
        proxy.wait_for_open_port(2222)

    # ── Prepare client SSH keys ──────────────────────────────────────────
    with subtest("Prepare client SSH keys"):
        client.succeed(
            "cp ${testSshKeys}/alice /tmp/alice_key && chmod 600 /tmp/alice_key"
        )
        client.succeed(
            "cp ${testSshKeys}/bob /tmp/bob_key && chmod 600 /tmp/bob_key"
        )

    # ── Subtest 0: Anonymous HTTP clone parity ───────────────────────────
    with subtest("Anonymous HTTP clone allows public repo and denies private repo"):
        proxy.succeed("rm -rf /tmp/http-public")
        proxy.succeed(
            "GIT_TERMINAL_PROMPT=0 "
            "git clone http://localhost:8080/octocat/repo-public-http.git /tmp/http-public"
        )
        proxy.succeed("test -f /tmp/http-public/README.md")
        proxy.succeed(
            "sh -c 'GIT_TERMINAL_PROMPT=0 "
            "git ls-remote http://localhost:8080/octocat/repo-uncached.git "
            "> /tmp/http-private.log 2>&1; test $? -ne 0'"
        )
        proxy.succeed(
            "grep -E 'Access denied|could not read Username|Authentication failed|401' "
            "/tmp/http-private.log"
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

    # ── Subtest 1b: Uncached SSH access populates local cache ──────────────
    with subtest("Uncached SSH access triggers background cache clone"):
        proxy.wait_until_succeeds("test -L /var/cache/forgeproxy/repos/octocat/repo-uncached.git")
        proxy.wait_until_succeeds(
            "redis-cli -h valkey HGET 'forgeproxy:repo:octocat/repo-uncached' status"
            " | grep -qx ready"
        )

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

    # ── Subtest 5: Uncached full clone via upstream proxy stream ─────────
    with subtest("Cache-miss full clone succeeds and populates local repo"):
        # Force a cache miss. Depending on the commit under test, forgeproxy may
        # either proxy upstream directly or pre-clone before serving SSH. At
        # this point in history, successful full-clone transport is the
        # regression we care about; local cache publication is covered later.
        proxy.succeed(
            "rm -rf /var/cache/forgeproxy/repos/octocat/repo-stream.git && "
            "mkdir -p /var/cache/forgeproxy/repos/octocat/repo-stream.git"
        )
        client.succeed("rm -rf /tmp/repo-stream")
        ssh_clone_succeed("repo-stream-full", "octocat/repo-stream", "/tmp/repo-stream")
        client.succeed("test -f /tmp/repo-stream/blob-24.bin")
        client.succeed("git -C /tmp/repo-stream rev-parse HEAD")
        client.succeed("git -C /tmp/repo-stream fsck --no-dangling")
        wait_for_close_handshake("octocat/repo-stream")

    # ── Subtest 5b: Uncached shallow clone via upstream proxy stream ───────
    with subtest("Uncached shallow clone succeeds via upstream proxy stream"):
        proxy.succeed(
            "rm -rf /var/cache/forgeproxy/repos/octocat/repo-stream.git && "
            "mkdir -p /var/cache/forgeproxy/repos/octocat/repo-stream.git"
        )
        client.succeed("rm -rf /tmp/repo-stream-shallow")
        ssh_clone_succeed(
            "repo-stream-shallow",
            "octocat/repo-stream",
            "/tmp/repo-stream-shallow",
            extra_args="--depth 1",
        )
        client.succeed("test -f /tmp/repo-stream-shallow/blob-24.bin")
        client.succeed("git -C /tmp/repo-stream-shallow rev-parse --is-shallow-repository | grep -qx true")
        client.succeed("git -C /tmp/repo-stream-shallow rev-parse HEAD")
        client.succeed("git -C /tmp/repo-stream-shallow fsck --no-dangling")

    # ── Subtest 5c: Subsequent clone succeeds after hydration/cache fill ───
    with subtest("Second clone succeeds after upstream proxy hydration"):
        client.succeed("rm -rf /tmp/repo-stream-second")
        ssh_clone_succeed(
            "repo-stream-second",
            "octocat/repo-stream",
            "/tmp/repo-stream-second",
            extra_args="--depth 1",
        )
        client.succeed("test -f /tmp/repo-stream-second/blob-24.bin")
        client.succeed("git -C /tmp/repo-stream-second rev-parse HEAD")
        client.succeed("git -C /tmp/repo-stream-second fsck --no-dangling")
        wait_for_close_handshake("octocat/repo-stream")

    # ── Subtest 5d: Client receives streamed data before hydration publishes ──
    with subtest("Cache-miss clone streams to client before local hydration publishes"):
        live_repo = "/var/cache/forgeproxy/repos/octocat/repo-stream-live.git"
        live_generation_dir = "/var/cache/forgeproxy/repos/.generations/octocat/repo-stream-live.git"
        live_tee_dir = "/var/cache/forgeproxy/repos/_tee/octocat/repo-stream-live"

        proxy.succeed(f"rm -rf {live_repo} {live_generation_dir} {live_tee_dir}")
        client.succeed("rm -rf /tmp/repo-stream-live /tmp/repo-stream-live.log /tmp/repo-stream-live.pid")
        client.succeed(
            f"env {ssh_clone_plain_env_words()} "
            "sh -c '"
            "set -e; "
            "git clone --progress git@proxy:octocat/repo-stream-live.git /tmp/repo-stream-live "
            "> /tmp/repo-stream-live.log 2>&1 & "
            "pid=$!; "
            "echo \"$pid\" > /tmp/repo-stream-live.pid'"
        )
        client.wait_until_succeeds(
            "grep -E 'Receiving objects:|Resolving deltas:|remote: Enumerating objects:' "
            "/tmp/repo-stream-live.log"
        )
        proxy.succeed(f"! test -e {live_repo}")
        client.succeed("kill -0 $(cat /tmp/repo-stream-live.pid)")
        try:
            client.wait_until_succeeds(
                "! kill -0 $(cat /tmp/repo-stream-live.pid) 2>/dev/null",
                timeout=120,
            )
        except Exception:
            dump_file_tail("/tmp/repo-stream-live.log", "repo-stream-live clone log")
            raise
        client.succeed("test -f /tmp/repo-stream-live/blob-32.bin")
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy.service --no-pager "
            "| grep -F '\"repo\":\"octocat/repo-stream-live\"' "
            "| grep -F 'starting tee hydration from captured pack'"
        )
        proxy.wait_until_succeeds(
            f"test -L {live_repo} && test -f $(readlink -f {live_repo})/HEAD"
        )
        proxy.wait_until_succeeds(
            f"! test -d {live_tee_dir} || "
            f"find {live_tee_dir} -mindepth 1 -maxdepth 1 -type d | wc -l | grep -qx 0"
        )

    # ── Subtest 5e: Restart drains an in-flight SSH clone cleanly ───────────
    with subtest("systemctl restart drains an in-flight SSH clone"):
        drain_repo = "/var/cache/forgeproxy/repos/octocat/repo-stream-live.git"
        drain_generation_dir = "/var/cache/forgeproxy/repos/.generations/octocat/repo-stream-live.git"
        drain_tee_dir = "/var/cache/forgeproxy/repos/_tee/octocat/repo-stream-live"

        proxy.succeed(f"rm -rf {drain_repo} {drain_generation_dir} {drain_tee_dir}")
        client.succeed(
            "rm -rf "
            "/tmp/repo-stream-live-drain "
            "/tmp/repo-stream-live-drain.log "
            "/tmp/repo-stream-live-drain.pid"
        )

        since = proxy.succeed("date --iso-8601=seconds --utc").strip()
        client.succeed(
            f"env {ssh_clone_env_words('repo-stream-live-drain')} "
            "sh -c '"
            "set -e; "
            "git clone --progress git@proxy:octocat/repo-stream-live.git /tmp/repo-stream-live-drain "
            "> /tmp/repo-stream-live-drain.log 2>&1 & "
            "pid=$!; "
            "echo \"$pid\" > /tmp/repo-stream-live-drain.pid'"
        )
        client.wait_until_succeeds(
            "grep -Eq "
            "'Enumerating objects:|Counting objects:|Compressing objects:|Receiving objects:|Resolving deltas:' "
            "/tmp/repo-stream-live-drain.log"
        )
        client.succeed("kill -0 $(cat /tmp/repo-stream-live-drain.pid)")
        proxy.succeed(
            "sh -c '"
            "systemctl restart forgeproxy >/tmp/forgeproxy-restart.log 2>&1 & "
            "echo \"$!\" > /tmp/forgeproxy-restart.pid'"
        )
        proxy.succeed("test -s /tmp/forgeproxy-restart.pid && kill -0 $(cat /tmp/forgeproxy-restart.pid)")
        proxy.succeed(
            "sh -c '"
            "set -eu; "
            "for _ in $(seq 1 20); do "
            "  if journalctl -u forgeproxy.service"
            f" --since '{since}' --no-pager"
            "    | grep -Fq \"forgeproxy entering drain mode\"; then "
            "    exit 0; "
            "  fi; "
            "  sleep 1; "
            "done; "
            "echo \"==== forgeproxy restart log ====\"; "
            "cat /tmp/forgeproxy-restart.log || true; "
            "echo \"==== forgeproxy restart pid ====\"; "
            "cat /tmp/forgeproxy-restart.pid || true; "
            "echo \"==== systemctl show forgeproxy ====\"; "
            "systemctl show forgeproxy -p ActiveState -p SubState -p Job -p MainPID -p ExecMainPID -p ExecMainStatus || true; "
            "echo \"==== systemctl status forgeproxy ====\"; "
            "systemctl status forgeproxy --no-pager || true; "
            "echo \"==== recent forgeproxy journal ====\"; "
            "journalctl -u forgeproxy.service"
            f" --since '{since}' --no-pager || true; "
            "exit 1'"
        )
        proxy.succeed(
            "sh -c '"
            "for _ in $(seq 1 50); do "
            "  health_code=$(curl -s -o /tmp/healthz.out -w \"%{http_code}\" http://127.0.0.1:8080/healthz || true); "
            "  ready_code=$(curl -s -o /tmp/readyz.out -w \"%{http_code}\" http://127.0.0.1:8080/readyz || true); "
            "  if [ \"$health_code\" = 200 ] && [ \"$ready_code\" = 503 ]; then "
            "    exit 0; "
            "  fi; "
            "  sleep 0.1; "
            "done; "
            "echo \"expected /healthz=200 and /readyz=503 during drain\"; "
            "echo \"last health_code=$health_code ready_code=$ready_code\"; "
            "exit 1'"
        )
        proxy.succeed("grep -Fqx 'forgeproxy is draining and not accepting new requests' /tmp/readyz.out")
        client.wait_until_succeeds("! kill -0 $(cat /tmp/repo-stream-live-drain.pid) 2>/dev/null")
        client.succeed("test -f /tmp/repo-stream-live-drain/blob-32.bin")
        client.succeed("git -C /tmp/repo-stream-live-drain fsck --no-dangling")
        proxy.wait_until_succeeds("! kill -0 $(cat /tmp/forgeproxy-restart.pid) 2>/dev/null")
        proxy.succeed("systemctl is-active forgeproxy | grep -qx active")
        proxy.wait_until_succeeds("curl -sf http://127.0.0.1:8080/healthz >/dev/null")
        proxy.wait_for_open_port(2222)

    # ── Subtest 5f: Uncached clone publishes a symlinked generation cleanly ──
    with subtest("Uncached clone publishes a generation symlink and cleans tee capture"):
        stream_repo = "/var/cache/forgeproxy/repos/octocat/repo-stream.git"
        stream_generation_dir = "/var/cache/forgeproxy/repos/.generations/octocat/repo-stream.git"
        stream_mirror = "/var/cache/forgeproxy/repos/.mirrors/octocat/repo-stream.git"
        stream_tee_dir = "/var/cache/forgeproxy/repos/_tee/octocat/repo-stream"

        proxy.succeed(
            f"rm -rf {stream_repo} {stream_generation_dir} {stream_mirror} {stream_tee_dir}"
        )
        client.succeed("rm -rf /tmp/repo-stream-published")
        ssh_clone_succeed(
            "repo-stream-published",
            "octocat/repo-stream",
            "/tmp/repo-stream-published",
        )
        proxy.wait_until_succeeds(
            f"test -L {stream_repo} && test -f $(readlink -f {stream_repo})/HEAD"
        )
        proxy.wait_until_succeeds(
            f"test $(find {stream_generation_dir} -mindepth 1 -maxdepth 1 -type d | wc -l) -ge 1"
        )
        proxy.wait_until_succeeds(
            f"test -d {stream_mirror} && test -f {stream_mirror}/HEAD"
        )
        proxy.wait_until_succeeds(
            f"! test -d {stream_tee_dir} || "
            f"find {stream_tee_dir} -mindepth 1 -maxdepth 1 -type d | wc -l | grep -qx 0"
        )

    # ── Subtest 5g: Generations converge after concurrent uncached clones ──
    with subtest("Concurrent uncached clones fold into one published generation"):
        generation_repo = "/var/cache/forgeproxy/repos/octocat/repo-generations.git"
        generation_dir = "/var/cache/forgeproxy/repos/.generations/octocat/repo-generations.git"
        generation_mirror = "/var/cache/forgeproxy/repos/.mirrors/octocat/repo-generations.git"
        generation_tee_dir = "/var/cache/forgeproxy/repos/_tee/octocat/repo-generations"

        proxy.succeed(
            f"rm -rf {generation_repo} {generation_dir} {generation_mirror} {generation_tee_dir}"
        )

        client.succeed("rm -rf /tmp/repo-generations-1 /tmp/repo-generations-2 /tmp/repo-generations-3")

        client.succeed(
            "set -euo pipefail; "
            f"env {ssh_clone_env_words('repo-generations-1')} "
            "git clone --depth 1 git@proxy:octocat/repo-generations.git /tmp/repo-generations-1 >/tmp/repo-generations-1.log 2>&1 & "
            "pid1=$!; "
            f"env {ssh_clone_env_words('repo-generations-2')} "
            "git clone --depth 1 git@proxy:octocat/repo-generations.git /tmp/repo-generations-2 >/tmp/repo-generations-2.log 2>&1 & "
            "pid2=$!; "
            f"env {ssh_clone_env_words('repo-generations-3')} "
            "git clone --depth 1 git@proxy:octocat/repo-generations.git /tmp/repo-generations-3 >/tmp/repo-generations-3.log 2>&1 & "
            "pid3=$!; "
            "wait $pid1 $pid2 $pid3"
        )

        proxy.wait_until_succeeds(
            f"test -L {generation_repo} && test -f $(readlink -f {generation_repo})/HEAD"
        )
        proxy.wait_until_succeeds(
            f"test $(find {generation_dir} -mindepth 1 -maxdepth 1 -type d | wc -l) -ge 1"
        )
        proxy.wait_until_succeeds(
            f"test -d {generation_mirror} && test -f {generation_mirror}/HEAD"
        )
        proxy.wait_until_succeeds(
            f"! test -d {generation_tee_dir} || "
            f"find {generation_tee_dir} -mindepth 1 -maxdepth 1 -type d | wc -l | grep -qx 0"
        )
        client.succeed("test -f /tmp/repo-generations-1/file-3.txt")
        client.succeed("test -f /tmp/repo-generations-2/file-3.txt")
        client.succeed("test -f /tmp/repo-generations-3/file-3.txt")

    # ── Subtest 5h: Published snapshots are invalid without a mirror ──────
    with subtest("Published generations are scrubbed when the mirror is missing"):
        invariant_repo = "/var/cache/forgeproxy/repos/octocat/repo-generations.git"
        invariant_generation_dir = "/var/cache/forgeproxy/repos/.generations/octocat/repo-generations.git"
        invariant_mirror = "/var/cache/forgeproxy/repos/.mirrors/octocat/repo-generations.git"

        client.succeed("rm -rf /tmp/repo-generations-invariant")
        proxy.wait_until_succeeds(
            f"test -L {invariant_repo} && test -f $(readlink -f {invariant_repo})/HEAD"
        )
        proxy.wait_until_succeeds(
            f"test -d {invariant_mirror} && test -f {invariant_mirror}/HEAD"
        )
        proxy.wait_until_succeeds(
            "test \"$(redis-cli -h valkey HGET 'forgeproxy:repo:octocat/repo-generations' status)\" = ready "
            "&& test -z \"$(redis-cli -h valkey HGET 'forgeproxy:repo:octocat/repo-generations' hydrating_node_id)\""
        )
        proxy.succeed(f"rm -rf {invariant_mirror}")
        proxy.succeed(
            f"test -L {invariant_repo} && "
            f"test $(find {invariant_generation_dir} -mindepth 1 -maxdepth 1 -type d | wc -l) -ge 1 && "
            f"! test -e {invariant_mirror}"
        )

        since = proxy.succeed("date --iso-8601=seconds --utc").strip()
        ssh_clone_succeed(
            "repo-generations-invariant",
            "octocat/repo-generations",
            "/tmp/repo-generations-invariant",
            extra_args="--depth 1",
        )
        client.succeed("test -f /tmp/repo-generations-invariant/file-3.txt")

        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy.service"
            f" --since '{since}' --no-pager"
            " | grep -F '\"repo\":\"octocat/repo-generations\"'"
            " | grep -F 'published repo invariant violated; removing published snapshots because the writer-owned mirror is missing'"
        )
        proxy.wait_until_succeeds(
            f"test -L {invariant_repo} && test -f $(readlink -f {invariant_repo})/HEAD"
        )
        proxy.wait_until_succeeds(
            f"test $(find {invariant_generation_dir} -mindepth 1 -maxdepth 1 -type d | wc -l) -ge 1"
        )
        proxy.wait_until_succeeds(
            f"test -d {invariant_mirror} && test -f {invariant_mirror}/HEAD"
        )

    # ── Subtest 5i: Large stale want sets catch up locally before timeout ──
    with subtest("Large stale fetch resolves many missing wants locally before timeout"):
        many_wants_repo = "/var/cache/forgeproxy/repos/octocat/repo-many-wants.git"
        many_wants_generation_dir = "/var/cache/forgeproxy/repos/.generations/octocat/repo-many-wants.git"
        many_wants_mirror = "/var/cache/forgeproxy/repos/.mirrors/octocat/repo-many-wants.git"

        proxy.succeed(
            f"rm -rf {many_wants_repo} {many_wants_generation_dir} {many_wants_mirror}"
        )
        client.succeed("rm -rf /tmp/repo-many-wants-seed /tmp/repo-many-wants-final")
        ssh_clone_succeed(
            "repo-many-wants-seed",
            "octocat/repo-many-wants",
            "/tmp/repo-many-wants-seed",
            extra_args="--depth 1",
        )
        proxy.wait_until_succeeds(
            f"test -L {many_wants_repo} && test -f $(readlink -f {many_wants_repo})/HEAD"
        )
        proxy.wait_until_succeeds(
            f"test -d {many_wants_mirror} && test -f {many_wants_mirror}/HEAD"
        )

        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "git clone http://octocat:secret123@localhost:3000/octocat/repo-many-wants.git $tmp/repo && "
            "cd $tmp/repo && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "tree=$(git rev-parse HEAD^{tree}) && "
            "parent=$(git rev-parse HEAD) && "
            "for i in $(seq 1 2048); do "
            "  commit=$(printf 'want-%s\\n' \"$i\" | git commit-tree \"$tree\" -p \"$parent\") && "
            "  git tag \"tag-$i\" \"$commit\" && "
            "  parent=\"$commit\"; "
            "done && "
            "git update-ref refs/heads/main \"$parent\" && "
            "git push origin main --tags"
        )

        since = proxy.succeed("date --iso-8601=seconds --utc").strip()
        ssh_clone_succeed(
            "repo-many-wants-final",
            "octocat/repo-many-wants",
            "/tmp/repo-many-wants-final",
        )
        client.succeed("git -C /tmp/repo-many-wants-final rev-parse HEAD")
        client.succeed("git -C /tmp/repo-many-wants-final rev-parse refs/tags/tag-2048")

        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy.service"
            f" --since '{since}' --no-pager"
            " | grep -F '\"repo\":\"octocat/repo-many-wants\"'"
            " | grep -F 'request-time SSH catch-up will fetch only advertised refs that match the missing wants'"
        )
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy.service"
            f" --since '{since}' --no-pager"
            " | grep -F '\"repo\":\"/var/cache/forgeproxy/repos/.delta-work/octocat/repo-many-wants.git'"
            " | grep -F '\"refspec_mode\":\"selected\"'"
        )
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy.service"
            f" --since '{since}' --no-pager"
            " | grep -F '\"repo\":\"octocat/repo-many-wants\"'"
            " | grep -F 'local published-generation catch-up completed before request timeout'"
        )
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy.service"
            f" --since '{since}' --no-pager"
            " | grep -F '\"repo\":\"octocat/repo-many-wants\"'"
            " | grep -F 'serving SSH fetch directly from local disk after want resolution'"
        )
        proxy.succeed(
            "! journalctl -u forgeproxy.service"
            f" --since '{since}' --no-pager"
            " | grep -F '\"repo\":\"octocat/repo-many-wants\"'"
            " | grep -F 'local published-generation catch-up timed out; falling back to upstream proxy'"
        )

    # ── Subtest 5j: Requests must not serve directly from the mutable mirror ──
    with subtest("SSH fetch does not serve directly from a fresher mirror when publish lags"):
        mirror_serve_repo = "/var/cache/forgeproxy/repos/octocat/repo-mirror-serve.git"
        mirror_serve_generation_dir = "/var/cache/forgeproxy/repos/.generations/octocat/repo-mirror-serve.git"
        mirror_serve_mirror = "/var/cache/forgeproxy/repos/.mirrors/octocat/repo-mirror-serve.git"

        proxy.succeed(
            f"rm -rf {mirror_serve_repo} {mirror_serve_generation_dir} {mirror_serve_mirror}"
        )
        client.succeed("rm -rf /tmp/repo-mirror-serve-seed /tmp/repo-mirror-serve-final")
        ssh_clone_succeed(
            "repo-mirror-serve-seed",
            "octocat/repo-mirror-serve",
            "/tmp/repo-mirror-serve-seed",
            extra_args="--depth 1",
        )
        proxy.wait_until_succeeds(
            f"test -L {mirror_serve_repo} && test -f $(readlink -f {mirror_serve_repo})/HEAD"
        )
        proxy.wait_until_succeeds(
            f"test -d {mirror_serve_mirror} && test -f {mirror_serve_mirror}/HEAD"
        )

        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "git clone http://octocat:secret123@localhost:3000/octocat/repo-mirror-serve.git $tmp/repo && "
            "cd $tmp/repo && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "echo fresh-mirror > file-5.txt && "
            "git add file-5.txt && "
            "git commit -m 'mirror-5' && "
            "git push origin main"
        )
        fresh_main = ghe.succeed(
            "git ls-remote http://octocat:secret123@localhost:3000/octocat/repo-mirror-serve.git refs/heads/main | cut -f1"
        ).strip()

        proxy.succeed(
            f"git config --global --add safe.directory {mirror_serve_mirror}"
        )
        proxy.succeed(
            f"git -C {mirror_serve_mirror} fetch --prune --force "
            "http://octocat:secret123@ghe:3000/octocat/repo-mirror-serve.git "
            "'+refs/*:refs/*'"
        )
        proxy.succeed(
            f"test \"$(git -C {mirror_serve_mirror} rev-parse refs/heads/main)\" = '{fresh_main}'"
        )
        proxy.succeed(
            f"test \"$(git -C {mirror_serve_repo} rev-parse refs/heads/main)\" != '{fresh_main}'"
        )

        since = proxy.succeed("date --iso-8601=seconds --utc").strip()
        ssh_clone_succeed(
            "repo-mirror-serve-final",
            "octocat/repo-mirror-serve",
            "/tmp/repo-mirror-serve-final",
            extra_args="--depth 1",
        )
        client.succeed("test -f /tmp/repo-mirror-serve-final/file-5.txt")

        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy.service"
            f" --since '{since}' --no-pager"
            " | grep -F '\"repo\":\"octocat/repo-mirror-serve\"'"
            " | grep -F 'waiting for local published-generation catch-up before deciding whether to proxy upstream'"
        )
        proxy.succeed(
            "! journalctl -u forgeproxy.service"
            f" --since '{since}' --no-pager"
            " | grep -F '\"repo\":\"octocat/repo-mirror-serve\"'"
            " | grep -F '\"serve_from\":\"Mirror\"'"
        )

    # ── Subtest 5k: Concurrent uncached hydrations complete and drain semaphore ──
    with subtest("Concurrent uncached clones release the repo semaphore"):
        semaphore_repo = "/var/cache/forgeproxy/repos/octocat/repo-stream-live.git"
        semaphore_generation_dir = "/var/cache/forgeproxy/repos/.generations/octocat/repo-stream-live.git"
        semaphore_tee_dir = "/var/cache/forgeproxy/repos/_tee/octocat/repo-stream-live"
        semaphore_key = "forgeproxy:semaphore:clone:octocat/repo-stream-live"
        proxy.succeed(
            f"rm -rf {semaphore_repo} {semaphore_generation_dir} {semaphore_tee_dir} && "
            f"redis-cli -h valkey DEL '{semaphore_key}' >/dev/null"
        )

        client.succeed(
            "rm -rf "
            "/tmp/repo-stream-live-semaphore-1 /tmp/repo-stream-live-semaphore-2 "
            "/tmp/repo-stream-live-semaphore-3 /tmp/repo-stream-live-semaphore-4 "
            "/tmp/repo-stream-live-semaphore-1.log /tmp/repo-stream-live-semaphore-2.log "
            "/tmp/repo-stream-live-semaphore-3.log /tmp/repo-stream-live-semaphore-4.log "
            "/tmp/repo-stream-live-semaphore.pids"
        )
        client.succeed(
            f"env {ssh_clone_env_words('repo-stream-live-semaphore')} "
            "sh -c '"
            "set -eu; "
            ": > /tmp/repo-stream-live-semaphore.pids; "
            "for i in 1 2 3 4; do "
            "  git clone --progress git@proxy:octocat/repo-stream-live.git "
            "    /tmp/repo-stream-live-semaphore-$i "
            "    >/tmp/repo-stream-live-semaphore-$i.log 2>&1 & "
            "  echo \"$!\" >> /tmp/repo-stream-live-semaphore.pids; "
            "done'"
        )

        client.succeed("test $(wc -l < /tmp/repo-stream-live-semaphore.pids) -eq 4")
        client.wait_until_succeeds(
            "while read -r pid; do "
            "  if kill -0 \"$pid\" 2>/dev/null; then exit 1; fi; "
            "done < /tmp/repo-stream-live-semaphore.pids"
        )
        client.succeed("test -f /tmp/repo-stream-live-semaphore-1/blob-32.bin")
        client.succeed("test -f /tmp/repo-stream-live-semaphore-2/blob-32.bin")
        client.succeed("test -f /tmp/repo-stream-live-semaphore-3/blob-32.bin")
        client.succeed("test -f /tmp/repo-stream-live-semaphore-4/blob-32.bin")
        proxy.wait_until_succeeds(
            f"! redis-cli -h valkey EXISTS '{semaphore_key}' | grep -qx 1"
        )

    # ── Subtest 5l: External scrubber handles published generation layout ──
    with subtest("External scrubber succeeds and keeps generation-backed repos"):
        proxy.succeed("systemctl start forgeproxy-cache-scrub.service")
        proxy.succeed(
            "systemctl show forgeproxy-cache-scrub.service"
            " -p Result --value | grep -qx success"
        )
        proxy.succeed("systemctl is-active forgeproxy-cache-scrub.timer | grep -qx active")
        proxy.succeed(
            "! test -d /var/cache/forgeproxy/repos/_tee/octocat/repo-generations || "
            "find /var/cache/forgeproxy/repos/_tee/octocat/repo-generations -mindepth 1 -maxdepth 1 -type d | wc -l | grep -qx 0"
        )
        client.succeed("rm -rf /tmp/repo-generations-scrubbed")
        ssh_clone_succeed(
            "repo-generations-scrubbed",
            "octocat/repo-generations",
            "/tmp/repo-generations-scrubbed",
            extra_args="--depth 1",
        )
        client.succeed("test -f /tmp/repo-generations-scrubbed/file-3.txt")
  '';
}
