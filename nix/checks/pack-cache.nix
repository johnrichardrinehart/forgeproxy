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
    pkgs.runCommand "forgeproxy-pack-cache-test-certs"
      {
        nativeBuildInputs = [ pkgs.openssl ];
      }
      ''
        mkdir -p $out

        openssl req -new -x509 -nodes -days 365 \
          -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
          -keyout $out/ca.key -out $out/ca.crt \
          -subj "/CN=ForgeProxy Pack Cache Test CA"

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
    pkgs.runCommand "forgeproxy-pack-cache-test-ssh-keys"
      {
        nativeBuildInputs = [ pkgs.openssh ];
      }
      ''
        mkdir -p $out
        ssh-keygen -t ed25519 -f $out/alice -N "" -C "alice@pack-cache-test"
        ssh-keygen -l -f $out/alice.pub -E sha256 | awk '{print $2}' > $out/alice.fp
      '';

  testConfigYaml = pkgs.writeText "forgeproxy-pack-cache-test-config.yaml" ''
    backend_type: "gitea"

    upstream:
      hostname: "ghe"
      api_url: "http://ghe:3000/api/v1"
      git_url_base: "https://ghe"
      admin_token_env: "FORGE_ADMIN_TOKEN"

    upstream_credentials:
      default_mode: "pat"
      orgs:
        octocat:
          mode: "pat"
          keyring_key_name: "FORGE_ADMIN_TOKEN"

    proxy:
      ssh_listen: "0.0.0.0:2222"
      http_listen: "127.0.0.1:8080"

    valkey:
      endpoint: "valkey:6379"
      tls: false
      auth_token_env: "VALKEY_AUTH_TOKEN"

    auth:
      ssh_user_lookup_cache_ttl: 30
      ssh_repo_access_cache_ttl: 30
      http_cache_ttl: 120
      negative_cache_ttl: 60

    clone:
      lock_ttl: 60
      lock_wait_timeout: 120
      ssh_upload_pack_close_grace_secs: 5
      max_concurrent_upstream_clones: 5
      max_concurrent_upstream_fetches: 10
      max_concurrent_local_upload_packs: 2
      max_concurrent_local_upload_packs_per_repo: 1

    pack_cache:
      enabled: true
      max_percent: 0.25
      high_water_mark: 0.90
      low_water_mark: 0.75
      eviction_policy: "lru"
      wait_for_inflight_secs: 120
      min_response_bytes: 1

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

    observability:
      metrics:
        prometheus:
          enabled: true
      logs:
        journald:
          enabled: true
      traces:
        enabled: false
  '';
in
pkgs.testers.runNixOSTest {
  name = "forgeproxy-pack-cache";
  # This scenario seeds a fanout repository with hundreds of MiB of random pack
  # data before exercising HTTP/SSH cache reuse. Parallel flake checks on slower
  # builders can spend most of the old timeout in git push compression.
  globalTimeout = 60 * 20;

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
            service.DISABLE_REGISTRATION = true;
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
        virtualisation.memorySize = 1024;
      };

    valkey = common.mkValkeyNode { };
    s3 = common.mkS3Node { };

    proxy =
      {
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
          logLevel = "info";
        };

        services.forgeproxy.backend.type = "gitea";

        services.forgeproxy-nginx = {
          enable = true;
          serverName = "proxy";
        };

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

        systemd.services.forgeproxy.environment = {
          AWS_ACCESS_KEY_ID = "minioadmin";
          AWS_SECRET_ACCESS_KEY = "minioadmin";
          AWS_DEFAULT_REGION = "us-east-1";
          FORGEPROXY_ALLOW_ENV_SECRET_FALLBACK = lib.mkForce "true";
          FORGE_ADMIN_TOKEN = lib.mkForce common.giteaAdminToken;
        };

        services.amazon-ssm-agent.enable = lib.mkForce false;

        environment.systemPackages = with pkgs; [
          curl
          jq
          git
        ];

        security.pki.certificateFiles = [ "${testCerts}/ca.crt" ];
        networking.firewall.allowedTCPPorts = [
          443
          2222
        ];
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
          curl
          jq
          openssh
        ];
        security.pki.certificateFiles = [ "${testCerts}/ca.crt" ];
      };
  };

  testScript = ''
    import re
    import shlex
    import time

    def pack_cache_counts():
        return {
            "entries": int(proxy.succeed(
                "find /var/cache/forgeproxy/.state/pack-cache -name '*.pack-entry.json' | wc -l"
            ).strip()),
            "delta": int(proxy.succeed(
                "find /var/cache/forgeproxy/.state/pack-cache/packstore/objects/pack -name '*-delta.pack' | wc -l"
            ).strip()),
            "base": int(proxy.succeed(
                "find /var/cache/forgeproxy/.state/pack-cache/packstore/objects/pack -name 'pack-*.pack' ! -name '*-delta.pack' | wc -l"
            ).strip()),
        }

    def wait_for_metric_regex(machine, pattern: str, timeout: int = 20):
        compiled = re.compile(pattern, re.MULTILINE)
        deadline = time.time() + timeout
        last_metrics = ""
        while time.time() < deadline:
            last_metrics = machine.succeed("curl -sf http://localhost:8080/metrics")
            if compiled.search(last_metrics):
                return last_metrics
            time.sleep(1)
        recent_logs = machine.succeed(
            "journalctl -u forgeproxy --since '2m ago' --no-pager -o cat || true"
        )
        raise Exception(
            f"timed out waiting for metric pattern {pattern!r}\n"
            f"recent forgeproxy logs:\n{recent_logs}\n"
            f"metrics tail:\n{last_metrics[-4000:]}"
        )

    def wait_for_count_growth(kind: str, previous: int):
        if kind == "entries":
            command = (
                "test $(find /var/cache/forgeproxy/.state/pack-cache -name '*.pack-entry.json' | wc -l) "
                f"-gt {previous}"
            )
        elif kind == "delta":
            command = (
                "test $(find /var/cache/forgeproxy/.state/pack-cache/packstore/objects/pack -name '*-delta.pack' | wc -l) "
                f"-gt {previous}"
            )
        elif kind == "base":
            command = (
                "test $(find /var/cache/forgeproxy/.state/pack-cache/packstore/objects/pack -name 'pack-*.pack' ! -name '*-delta.pack' | wc -l) "
                f"-gt {previous}"
            )
        else:
            raise Exception(f"unknown count kind {kind}")
        proxy.wait_until_succeeds(command)

    def wait_for_count_same(kind: str, expected: int):
        if kind == "delta":
            command = (
                "test $(find /var/cache/forgeproxy/.state/pack-cache/packstore/objects/pack -name '*-delta.pack' | wc -l) "
                f"-eq {expected}"
            )
        elif kind == "base":
            command = (
                "test $(find /var/cache/forgeproxy/.state/pack-cache/packstore/objects/pack -name 'pack-*.pack' ! -name '*-delta.pack' | wc -l) "
                f"-eq {expected}"
            )
        else:
            raise Exception(f"unknown count kind {kind}")
        proxy.wait_until_succeeds(command)

    def assert_no_pack_corruption_logs():
        proxy.succeed(
            "! journalctl -u forgeproxy --no-pager -o cat "
            "| grep -E 'same object .* appears twice|REF_DELTA .* already resolved|invalid index-pack output'"
        )

    def live_subscription_count(protocol: str):
        metrics = proxy.succeed("curl -sf http://localhost:8080/metrics")
        total = 0.0
        for line in metrics.splitlines():
            if (
                line.startswith("forgeproxy_pack_cache_live_subscriptions_total{")
                and f'protocol="{protocol}"' in line
                and 'result="success"' in line
            ):
                total += float(line.rsplit(" ", 1)[1])
        return total

    def wait_for_live_subscription_growth(protocol: str, previous: float, timeout: int = 30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            current = live_subscription_count(protocol)
            if current > previous:
                return
            time.sleep(1)
        recent_logs = proxy.succeed(
            "journalctl -u forgeproxy --since '2m ago' --no-pager -o cat || true"
        )
        raise Exception(
            f"timed out waiting for {protocol} live subscription growth above {previous}\n"
            f"recent forgeproxy logs:\n{recent_logs}"
        )

    def clone_command(protocol: str, branch: str, dest: str):
        if protocol == "https":
            return (
                "git -c protocol.version=2 clone --single-branch "
                f"--branch {branch} "
                f"https://${common.giteaAdminUser}:${common.giteaAdminPassword}@proxy/"
                f"${common.giteaAdminUser}/pack-cache-fanout.git {dest}"
            )
        if protocol == "ssh":
            return (
                "GIT_SSH_COMMAND='ssh -i /tmp/alice_key "
                "-o StrictHostKeyChecking=no "
                "-o UserKnownHostsFile=/dev/null "
                "-p 2222' "
                "git -c protocol.version=2 clone --single-branch "
                f"--branch {branch} "
                f"git@proxy:${common.giteaAdminUser}/pack-cache-fanout.git {dest}"
            )
        raise Exception(f"unknown clone protocol {protocol}")

    def clone_background_command(protocol: str, branch: str, dest: str, log: str, status: str):
        command = (
            f"{clone_command(protocol, branch, dest)} >{log} 2>&1; "
            f"printf '%s' \"$?\" >{status}"
        )
        return f"nohup sh -c {shlex.quote(command)} >/dev/null 2>&1 </dev/null &"

    def start_clone_background(protocol: str, branch: str, dest: str, log: str, status: str):
        client.succeed(clone_background_command(protocol, branch, dest, log, status))

    def forgeproxy_journal_cursor():
        return proxy.succeed(
            "journalctl -u forgeproxy -n 0 --show-cursor --no-pager "
            "| sed -n 's/^-- cursor: //p'"
        ).strip()

    def wait_for_producer_fetch_reached_proxy(protocol: str, cursor: str, timeout: int = 30):
        if protocol == "https":
            needles = [
                '"message":"received git-upload-pack request"',
                '"repo":"octocat/pack-cache-fanout"',
                '"git_phase":"v2-fetch"',
            ]
        elif protocol == "ssh":
            needles = [
                '"message":"SSH exec request"',
                "pack-cache-fanout",
            ]
        else:
            raise Exception(f"unknown clone protocol {protocol}")

        deadline = time.time() + timeout
        while time.time() < deadline:
            logs = proxy.succeed(
                f"journalctl -u forgeproxy --after-cursor {shlex.quote(cursor)} --no-pager -o cat || true"
            )
            if any(all(needle in line for needle in needles) for line in logs.splitlines()):
                return
            time.sleep(0.2)
        raise Exception(
            f"timed out waiting for {protocol} producer fetch to reach forgeproxy\n"
            f"recent forgeproxy logs:\n{logs}"
        )

    def run_fanout_clone_pair(
        name: str,
        first_protocol: str,
        second_protocol: str,
        branch: str,
    ):
        first_dest = f"/tmp/{name}-first"
        second_dest = f"/tmp/{name}-second"
        first_status = f"/tmp/{name}-first.status"
        second_status = f"/tmp/{name}-second.status"
        first_log = f"/tmp/{name}-first.log"
        second_log = f"/tmp/{name}-second.log"
        subscriber_before = live_subscription_count(second_protocol)

        client.succeed(
            f"rm -rf {first_dest} {second_dest} "
            f"{first_status} {second_status} {first_log} {second_log}"
        )
        cursor = forgeproxy_journal_cursor()
        start_clone_background(first_protocol, branch, first_dest, first_log, first_status)
        wait_for_producer_fetch_reached_proxy(first_protocol, cursor)
        start_clone_background(second_protocol, branch, second_dest, second_log, second_status)
        wait_for_live_subscription_growth(second_protocol, subscriber_before)
        client.wait_until_succeeds(
            f"test -f {first_status} && test -f {second_status}",
            timeout=120,
        )
        client.succeed(
            f"test \"$(cat {first_status})\" = 0 && test \"$(cat {second_status})\" = 0 || "
            f"(cat {first_log}; cat {second_log}; false)"
        )
        client.succeed(
            f"git -C {first_dest} rev-parse HEAD >/dev/null && "
            f"git -C {second_dest} rev-parse HEAD >/dev/null"
        )
        client.succeed(
            f"rm -rf {first_dest} {second_dest} "
            f"{first_status} {second_status} {first_log} {second_log}"
        )

    ghe.start()
    valkey.start()
    s3.start()

    ${common.valkeyStartScript}

    ${common.s3StartScript}

    with subtest("Gitea starts"):
        ghe.wait_for_unit("gitea.service")
        ghe.wait_for_open_port(3000)

    with subtest("GHE nginx starts"):
        ghe.wait_for_unit("nginx.service")
        ghe.wait_for_open_port(443)

    with subtest("Create pack-cache test repo on mock GHE"):
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
            ' -d \'{"name": "pack-cache", "auto_init": false}\'''
        )
        ghe.succeed(
            "curl -sf"
            " -X POST http://localhost:3000/api/v1/user/repos"
            " -H 'Content-Type: application/json'"
            " -u ${common.giteaAdminUser}:${common.giteaAdminPassword}"
            ' -d \'{"name": "pack-cache-fanout", "auto_init": false}\'''
        )

        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "cd $tmp && "
            "git init -b main && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "echo 'Pack cache repo' > README.md && "
            "git add README.md && "
            "git commit -m 'Initial commit' && "
            "git checkout -b side && "
            "echo 'Pack cache side branch' > side.txt && "
            "git add side.txt && "
            "git commit -m 'Side branch commit' && "
            "git checkout --orphan unrelated && "
            "git rm -rf . && "
            "echo 'Pack cache unrelated branch' > unrelated.txt && "
            "git add unrelated.txt && "
            "git commit -m 'Unrelated branch commit' && "
            "git checkout main && "
            "git remote add origin http://${common.giteaAdminUser}:${common.giteaAdminPassword}@localhost:3000/${common.giteaAdminUser}/pack-cache.git && "
            "git push -u origin main side unrelated"
        )
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "cd $tmp && "
            "git init -b main && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "echo 'Pack cache fanout repo' > README.md && "
            "git add README.md && "
            "git commit -m 'Initial commit' && "
            "for branch in fanout-http-ssh fanout-ssh-http fanout-http-http fanout-ssh-ssh; do "
            "  git checkout -B $branch main && "
            "  mkdir -p payload-$branch && "
            "  for i in $(seq 1 64); do "
            "    head -c 1048576 /dev/urandom > payload-$branch/blob-$i.bin; "
            "  done && "
            "  git add payload-$branch && "
            "  git commit -m \"payload $branch\"; "
            "done && "
            "git remote add origin http://${common.giteaAdminUser}:${common.giteaAdminPassword}@localhost:3000/${common.giteaAdminUser}/pack-cache-fanout.git && "
            "git push -u origin main fanout-http-ssh fanout-ssh-http fanout-http-http fanout-ssh-ssh"
        )
    with subtest("Start proxy and client VMs after upstream is ready"):
        proxy.start()
        client.start()

    with subtest("forgeproxy service starts"):
        proxy.wait_for_unit("forgeproxy.service")
        proxy.wait_for_open_port(8080)
        proxy.wait_for_open_port(2222)

    with subtest("Proxy nginx starts"):
        proxy.wait_for_unit("nginx.service")
        proxy.wait_for_open_port(443)

    with subtest("Prepare SSH identity for pack-cache fanout clones"):
        client.succeed(
            "cp ${testSshKeys}/alice /tmp/alice_key && chmod 600 /tmp/alice_key"
        )
        alice_fp = valkey.succeed("cat ${testSshKeys}/alice.fp").strip()
        valkey.succeed(
            f"redis-cli SET 'forgeproxy:ssh:auth:{alice_fp}' '${common.giteaAdminUser}' EX 3600"
        )
        valkey.succeed(
            f"redis-cli SET 'forgeproxy:ssh:access:{alice_fp}:${common.giteaAdminUser}/pack-cache-fanout' 'read' EX 3600"
        )

    with subtest("Repeated warm HTTPS clone uses the full pack cache"):
        client.succeed(
            "rm -rf /tmp/pack-cache-warm /tmp/pack-cache-miss /tmp/pack-cache-hit && "
            "git clone https://octocat:secret123@proxy/octocat/pack-cache.git /tmp/pack-cache-warm"
        )
        proxy.wait_until_succeeds(
            "test -L ${cacheLayout.repoPath "octocat/pack-cache"}"
        )
        proxy.wait_until_succeeds(
            "find ${cacheLayout.generationDir "octocat/pack-cache"} -mindepth 1 -maxdepth 1 -type d | grep -q ."
        )
        client.succeed(
            "git clone https://octocat:secret123@proxy/octocat/pack-cache.git /tmp/pack-cache-miss"
        )
        wait_for_metric_regex(proxy, r"^forgeproxy_pack_cache_physical_usage_bytes [1-9][0-9]*$")
        client.succeed(
            "git clone https://octocat:secret123@proxy/octocat/pack-cache.git /tmp/pack-cache-hit"
        )
        client.succeed("grep -Fx 'Pack cache repo' /tmp/pack-cache-hit/README.md")
        proxy.wait_until_succeeds(
            "test $(find /var/cache/forgeproxy/.state/pack-cache -name '*.pack-entry.json' | wc -l) -ge 1"
        )

    with subtest("Fast-forwarded main branch reuses the cached base through a delta pack"):
        client.succeed(
            "rm -rf /tmp/pack-cache-main-base /tmp/pack-cache-main-hit && "
            "git clone --single-branch --branch main https://octocat:secret123@proxy/octocat/pack-cache.git /tmp/pack-cache-main-base && "
            "git clone --single-branch --branch main https://octocat:secret123@proxy/octocat/pack-cache.git /tmp/pack-cache-main-hit"
        )
        counts_before = pack_cache_counts()
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "git clone http://octocat:secret123@localhost:3000/octocat/pack-cache.git $tmp && "
            "cd $tmp && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "git checkout main && "
            "printf '\\nmain fast-forward\\n' >> README.md && "
            "git add README.md && "
            "git commit -m 'Main fast-forward' && "
            "git push origin main"
        )
        client.succeed(
            "rm -rf /tmp/pack-cache-main-delta && "
            "git clone --single-branch --branch main https://octocat:secret123@proxy/octocat/pack-cache.git /tmp/pack-cache-main-delta"
        )
        client.succeed("grep -Fx 'main fast-forward' /tmp/pack-cache-main-delta/README.md")
        wait_for_count_growth("entries", counts_before["entries"])
        proxy.succeed(
            "test -f /var/cache/forgeproxy/.state/pack-cache/packstore/objects/pack/multi-pack-index"
        )
        assert_no_pack_corruption_logs()

    with subtest("Shared-history branch tips amortize through exact object overlap"):
        counts_before = pack_cache_counts()
        client.succeed(
            "rm -rf /tmp/pack-cache-side && "
            "git clone --single-branch --branch side https://octocat:secret123@proxy/octocat/pack-cache.git /tmp/pack-cache-side"
        )
        client.succeed("grep -Fx 'Pack cache side branch' /tmp/pack-cache-side/side.txt")
        wait_for_count_growth("entries", counts_before["entries"])
        assert_no_pack_corruption_logs()

    with subtest("Low-overlap newly unrelated history falls back to a new full pack"):
        counts_before = pack_cache_counts()
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "git clone http://octocat:secret123@localhost:3000/octocat/pack-cache.git $tmp && "
            "cd $tmp && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "git checkout --orphan late-unrelated && "
            "git rm -rf . && "
            "echo 'Pack cache late unrelated branch' > late-unrelated.txt && "
            "git add late-unrelated.txt && "
            "git commit -m 'Late unrelated branch commit' && "
            "git push origin late-unrelated"
        )
        client.succeed(
            "rm -rf /tmp/pack-cache-late-unrelated /tmp/pack-cache-late-unrelated-hit && "
            "git clone --single-branch --branch late-unrelated https://octocat:secret123@proxy/octocat/pack-cache.git /tmp/pack-cache-late-unrelated && "
            "git clone --single-branch --branch late-unrelated https://octocat:secret123@proxy/octocat/pack-cache.git /tmp/pack-cache-late-unrelated-hit"
        )
        client.succeed("grep -Fx 'Pack cache late unrelated branch' /tmp/pack-cache-late-unrelated-hit/late-unrelated.txt")
        wait_for_count_growth("entries", counts_before["entries"])
        wait_for_count_same("delta", counts_before["delta"])
        wait_for_count_growth("base", counts_before["base"])
        assert_no_pack_corruption_logs()

    with subtest("Force-pushed main branch still clones cleanly and reuses shared objects"):
        counts_before = pack_cache_counts()
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "git clone http://octocat:secret123@localhost:3000/octocat/pack-cache.git $tmp && "
            "cd $tmp && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "git checkout main && "
            "git reset --hard HEAD~1 && "
            "echo 'rewritten main branch' > rewritten.txt && "
            "git add rewritten.txt && "
            "git commit -m 'Rewrite main history' && "
            "git push --force origin main"
        )
        for index in range(1, 4):
            client.succeed(
                f"rm -rf /tmp/pack-cache-rewrite-{index} && "
                f"git clone --single-branch --branch main https://octocat:secret123@proxy/octocat/pack-cache.git /tmp/pack-cache-rewrite-{index}"
            )
            client.succeed(
                f"grep -Fx 'rewritten main branch' /tmp/pack-cache-rewrite-{index}/rewritten.txt"
            )
            client.succeed(
                f"! grep -Fqx 'main fast-forward' /tmp/pack-cache-rewrite-{index}/README.md"
            )
        wait_for_count_growth("entries", counts_before["entries"])
        assert_no_pack_corruption_logs()

    with subtest("Blobless and treeless clones are served by local upload-pack"):
        client.succeed(
            "rm -rf /tmp/pack-cache-blobless /tmp/pack-cache-treeless && "
            "git clone --filter=blob:none --no-checkout https://octocat:secret123@proxy/octocat/pack-cache.git /tmp/pack-cache-blobless && "
            "git -C /tmp/pack-cache-blobless rev-parse HEAD >/dev/null && "
            "git clone --filter=tree:0 --no-checkout https://octocat:secret123@proxy/octocat/pack-cache.git /tmp/pack-cache-treeless && "
            "git -C /tmp/pack-cache-treeless rev-parse HEAD >/dev/null"
        )

        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy --no-pager | "
            "grep -F '\"message\":\"clone served\"' | "
            "grep -F '\"path\":\"local_upload_pack\"'"
        )

    with subtest("Warm fanout repo mirror without caching full branch responses"):
        client.succeed(
            "rm -rf /tmp/pack-cache-fanout-warm && "
            "git -c protocol.version=2 clone --filter=blob:none --no-checkout "
            "https://octocat:secret123@proxy/octocat/pack-cache-fanout.git "
            "/tmp/pack-cache-fanout-warm"
        )
        proxy.wait_until_succeeds(
            "test -L ${cacheLayout.repoPath "octocat/pack-cache-fanout"}"
        )

    with subtest("HTTPS producer live-fanouts to concurrent SSH clone"):
        run_fanout_clone_pair(
            "fanout-http-ssh",
            "https",
            "ssh",
            "fanout-http-ssh",
        )

    with subtest("SSH producer live-fanouts to concurrent HTTPS clone"):
        run_fanout_clone_pair(
            "fanout-ssh-http",
            "ssh",
            "https",
            "fanout-ssh-http",
        )

    with subtest("HTTPS producer live-fanouts to concurrent HTTPS clone"):
        run_fanout_clone_pair(
            "fanout-http-http",
            "https",
            "https",
            "fanout-http-http",
        )

    with subtest("SSH producer live-fanouts to concurrent SSH clone"):
        run_fanout_clone_pair(
            "fanout-ssh-ssh",
            "ssh",
            "ssh",
            "fanout-ssh-ssh",
        )
  '';
}
