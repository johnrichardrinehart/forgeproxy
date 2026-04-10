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
  otlpMetricsUser = "metrics-user";
  otlpMetricsPassword = "metrics-password";
  otlpLogsUser = "logs-user";
  otlpLogsPassword = "logs-password";
  otlpTracesUser = "traces-user";
  otlpTracesPassword = "traces-password";
  otlpMetricsIngressPort = 4318;
  otlpLogsIngressPort = 4319;
  otlpTracesIngressPort = 4320;
  otlpMetricsSinkPort = 14318;
  otlpLogsSinkPort = 14319;
  otlpTracesSinkPort = 14320;
  otlpBasicAuthFiles =
    pkgs.runCommand "forgeproxy-test-otlp-basic-auth"
      {
        nativeBuildInputs = [ pkgs.apacheHttpd ];
      }
      ''
        mkdir -p $out
        htpasswd -nbB ${otlpMetricsUser} ${otlpMetricsPassword} > $out/metrics.htpasswd
        htpasswd -nbB ${otlpLogsUser} ${otlpLogsPassword} > $out/logs.htpasswd
        htpasswd -nbB ${otlpTracesUser} ${otlpTracesPassword} > $out/traces.htpasswd
      '';
  otlpTestSinkConfig = pkgs.writeText "forgeproxy-test-otlp-sink.yaml" ''
    receivers:
      otlp/metrics:
        protocols:
          http:
            endpoint: 127.0.0.1:${toString otlpMetricsSinkPort}
      otlp/logs:
        protocols:
          http:
            endpoint: 127.0.0.1:${toString otlpLogsSinkPort}
      otlp/traces:
        protocols:
          http:
            endpoint: 127.0.0.1:${toString otlpTracesSinkPort}

    processors:
      batch: {}

    exporters:
      debug:
        verbosity: normal

    service:
      telemetry:
        metrics:
          level: none
      pipelines:
        traces:
          receivers: [otlp/traces]
          processors: [batch]
          exporters: [debug]
        logs:
          receivers: [otlp/logs]
          processors: [batch]
          exporters: [debug]
        metrics:
          receivers: [otlp/metrics]
          processors: [batch]
          exporters: [debug]
  '';

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
    backend_type: "gitea"

    upstream:
      hostname: "ghe"
      api_url: "http://ghe:3000/api/v1"
      git_url_base: "https://ghe"
      admin_token_env: "FORGE_ADMIN_TOKEN"

    upstream_credentials:
      default_mode: "pat"

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
      ssh_upload_pack_close_grace_secs: 5
      max_concurrent_upstream_clones: 5
      max_concurrent_upstream_fetches: 10

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
      logs:
        journald:
          enabled: true
      traces:
        enabled: true
        sample_ratio: 1.0
  '';

  otelCollectorConfigYaml = pkgs.writeText "forgeproxy-test-otel-collector-config.yaml" ''
    metrics:
      host:
        enabled: true
    exporters:
      otlp:
        metrics:
          enabled: true
          endpoint: "http://127.0.0.1:${toString otlpMetricsIngressPort}/v1/metrics"
          protocol: "http/protobuf"
          export_interval_secs: 15
          auth:
            basic:
              username: "${otlpMetricsUser}"
              password: "${otlpMetricsPassword}"
        logs:
          enabled: true
          endpoint: "http://127.0.0.1:${toString otlpLogsIngressPort}/v1/logs"
          protocol: "http/protobuf"
          export_interval_secs: 15
          auth:
            basic:
              username: "${otlpLogsUser}"
              password: "${otlpLogsPassword}"
        traces:
          enabled: true
          endpoint: "http://127.0.0.1:${toString otlpTracesIngressPort}/v1/traces"
          protocol: "http/protobuf"
          export_interval_secs: 15
          auth:
            basic:
              username: "${otlpTracesUser}"
              password: "${otlpTracesPassword}"
  '';

in
pkgs.testers.runNixOSTest {
  name = "forgeproxy-basic";
  # This scenario now exercises full OTLP wiring plus late-stage generation
  # lease assertions. Give it enough headroom to reach the final subtests on
  # slower builders without weakening the behavior being checked.
  globalTimeout = 420;

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
          logLevel = "info";
        };

        services.forgeproxy-otel-collector.sourceConfigFile = otelCollectorConfigYaml;

        services.forgeproxy.backend.type = "gitea";

        systemd.services.otlp-test-sink = {
          description = "OTLP sink for forgeproxy VM test assertions";
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          serviceConfig = {
            Type = "simple";
            ExecStart = "${lib.getExe' pkgs.opentelemetry-collector-contrib "otelcol-contrib"} --config=${otlpTestSinkConfig}";
            Restart = "on-failure";
            RestartSec = 2;
          };
        };

        services.nginx.appendHttpConfig = lib.mkAfter ''
          server {
            listen 127.0.0.1:${toString otlpMetricsIngressPort};
            auth_basic "forgeproxy otlp metrics";
            auth_basic_user_file ${otlpBasicAuthFiles}/metrics.htpasswd;

            location = /v1/metrics {
              proxy_pass http://127.0.0.1:${toString otlpMetricsSinkPort};
            }
          }

          server {
            listen 127.0.0.1:${toString otlpLogsIngressPort};
            auth_basic "forgeproxy otlp logs";
            auth_basic_user_file ${otlpBasicAuthFiles}/logs.htpasswd;

            location = /v1/logs {
              proxy_pass http://127.0.0.1:${toString otlpLogsSinkPort};
            }
          }

          server {
            listen 127.0.0.1:${toString otlpTracesIngressPort};
            auth_basic "forgeproxy otlp traces";
            auth_basic_user_file ${otlpBasicAuthFiles}/traces.htpasswd;

            location = /v1/traces {
              proxy_pass http://127.0.0.1:${toString otlpTracesSinkPort};
            }
          }
        '';

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

    with subtest("forgeproxy writes runtime resource attributes at startup"):
        proxy.succeed("test -s /run/forgeproxy/runtime-resource-attributes.json")
        machine_id = proxy.succeed("cat /etc/machine-id").strip()
        runtime_attrs = proxy.succeed("cat /run/forgeproxy/runtime-resource-attributes.json")
        assert '"service_name": "forgeproxy"' in runtime_attrs, runtime_attrs
        assert f'"service_instance_id": "{machine_id}"' in runtime_attrs, runtime_attrs
        assert f'"service_machine_id": "{machine_id}"' in runtime_attrs, runtime_attrs

    with subtest("Forgeproxy and collector configs enable the on-host OTLP collector"):
        proxy.wait_for_unit("otlp-test-sink.service")
        proxy.wait_for_unit("forgeproxy-otlp-collector.service")
        proxy.wait_until_succeeds(
            "systemctl is-active forgeproxy-otlp-collector.service | grep -qx active"
        )
        rendered = proxy.succeed("cat /run/forgeproxy-otelcol/config.yaml")
        assert "resource/common:" in rendered, rendered
        assert "key: service.instance.id" in rendered, rendered
        assert "key: service.machine_id" in rendered, rendered
        assert "key: service.ip_address" in rendered, rendered
        assert 'targets: ["127.0.0.1:8080"]' in rendered, rendered
        assert "hostmetrics:" in rendered, rendered
        assert 'receivers: ["prometheus", "hostmetrics"]' in rendered, rendered
        assert 'endpoint: "http://127.0.0.1:4318/v1/metrics"' in rendered, rendered
        assert 'endpoint: "http://127.0.0.1:4319/v1/logs"' in rendered, rendered
        assert 'endpoint: "http://127.0.0.1:4320/v1/traces"' in rendered, rendered
        assert 'endpoint: "127.0.0.1:4317"' in rendered, rendered
        assert 'units: ["forgeproxy.service"]' in rendered, rendered
        assert "logs:" in rendered, rendered
        assert "traces:" in rendered, rendered
        assert "transform/resource_to_labels:" in rendered, rendered
        assert "processors: [resource/common, transform/resource_to_labels, batch/metrics]" in rendered, rendered
        assert "processors: [resource/common, batch/logs]" in rendered, rendered
        assert "processors: [resource/common, batch/traces]" in rendered, rendered
        assert "basicauth/client-metrics" in rendered, rendered
        assert "basicauth/client-logs" in rendered, rendered
        assert "basicauth/client-traces" in rendered, rendered
        proxy.succeed(
            "! journalctl -u forgeproxy-otlp-collector.service --no-pager -o cat"
            " | grep -Eiq 'permission denied|executable file not found|Failed to get journal file list'"
        )

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

    with subtest("Forgeproxy traces egress over OTLP"):
        proxy.wait_until_succeeds(
            "journalctl -u otlp-test-sink.service --no-pager -o cat"
            " | grep -F 'tick_with_summary'"
        )

    # ── HTTPS clone through the proxy ─────────────────────────────────────
    with subtest("HTTPS clone through proxy succeeds"):
        client.succeed(
            "git clone https://octocat:secret123@proxy/octocat/hello-world.git /tmp/repo"
        )
        output = client.succeed("cat /tmp/repo/README.md")
        assert "Hello World" in output, f"README.md content mismatch: {output}"

    with subtest("Initial clone publishes a generation"):
        proxy.wait_until_succeeds(
            "test -L ${cacheLayout.repoPath "octocat/hello-world"}"
        )
        proxy.wait_until_succeeds(
            "find ${cacheLayout.generationDir "octocat/hello-world"} -mindepth 1 -maxdepth 1 -type d | grep -q ."
        )

    with subtest("Web root through proxy reaches upstream UI"):
        client.succeed(
            "curl -sf https://proxy/ > /tmp/proxy-root.html && "
            "grep -qi '<html' /tmp/proxy-root.html"
        )

    with subtest("Repository web page through proxy reaches upstream UI"):
        client.succeed(
            "curl -sf https://proxy/octocat/hello-world > /tmp/proxy-repo.html && "
            "grep -qi 'hello-world' /tmp/proxy-repo.html"
        )

    with subtest("API POST through proxy reaches upstream"):
        status = client.succeed(
            "curl -sS"
            " -o /tmp/proxy-api-created.body"
            " -w '%{http_code}'"
            " -u octocat:secret123"
            " -X POST"
            " -H 'Content-Type: application/json'"
            " https://proxy/api/v1/user/repos"
            " -d '{\"name\":\"proxy-api-created\",\"auto_init\":false}'"
        ).strip()
        if status != "201":
            body = client.succeed("cat /tmp/proxy-api-created.body || true")
            raise Exception(f"expected 201 from proxy API POST, got {status}: {body}")
        ghe.wait_until_succeeds(
            "curl -sf"
            " -u octocat:secret123"
            " http://localhost:3000/api/v1/repos/octocat/proxy-api-created"
            " | jq -e '.name == \"proxy-api-created\"'"
        )

    with subtest("git push through proxy updates upstream refs"):
        client.succeed(
            "set -e && "
            "cd /tmp/repo && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "git checkout -b proxy-write-branch && "
            "echo 'proxy write branch' >> README.md && "
            "git add README.md && "
            "git commit -m 'proxy write branch' && "
            "git tag proxy-write-tag && "
            "git push origin proxy-write-branch refs/tags/proxy-write-tag"
        )
        ghe.wait_until_succeeds(
            "git ls-remote http://octocat:secret123@localhost:3000/octocat/hello-world.git refs/heads/proxy-write-branch"
            " | grep -Eq '^[0-9a-f]{40}[[:space:]]+refs/heads/proxy-write-branch$'"
        )
        ghe.wait_until_succeeds(
            "git ls-remote http://octocat:secret123@localhost:3000/octocat/hello-world.git refs/tags/proxy-write-tag"
            " | grep -Eq '^[0-9a-f]{40}[[:space:]]+refs/tags/proxy-write-tag$'"
        )
        proxy.succeed(
            "! git --git-dir ${cacheLayout.repoPath "octocat/hello-world"} rev-parse --verify refs/heads/proxy-write-branch"
        )
        proxy.succeed(
            "! git --git-dir ${cacheLayout.repoPath "octocat/hello-world"} rev-parse --verify refs/tags/proxy-write-tag"
        )

    with subtest("git push through proxy does not update the local mirror or published generation"):
        proxy.succeed(
            "! git --git-dir ${cacheLayout.mirrorPath "octocat/hello-world"} rev-parse --verify refs/heads/proxy-write-branch >/dev/null 2>&1"
        )
        proxy.succeed(
            "! git --git-dir ${cacheLayout.mirrorPath "octocat/hello-world"} rev-parse --verify refs/tags/proxy-write-tag >/dev/null 2>&1"
        )
        proxy.succeed(
            "! git --git-dir $(readlink -f ${cacheLayout.repoPath "octocat/hello-world"}) rev-parse --verify refs/heads/proxy-write-branch >/dev/null 2>&1"
        )
        proxy.succeed(
            "! git --git-dir $(readlink -f ${cacheLayout.repoPath "octocat/hello-world"}) rev-parse --verify refs/tags/proxy-write-tag >/dev/null 2>&1"
        )

    with subtest("Forgeproxy journald logs proxied git-receive-pack over OTLP"):
        proxy.wait_until_succeeds(
            "journalctl -u otlp-test-sink.service --no-pager -o cat"
            " | grep -F 'proxying git-receive-pack to upstream forge'"
        )

    with subtest("Forgeproxy metrics are exported at /metrics"):
        metrics = proxy.succeed("curl -sf http://localhost:8080/metrics")
        assert "forgeproxy_bundle_generation_total " in metrics, metrics
        assert "forgeproxy_archive_cache_misses_total " in metrics, metrics
        assert "forgeproxy_clone_total{" in metrics, metrics
        assert "forgeproxy_clone_upstream_bytes_total{" in metrics, metrics
        assert "forgeproxy_clone_downstream_bytes_total{" in metrics, metrics
        assert "forgeproxy_cache_repos_total " in metrics, metrics

    with subtest("Forgeproxy metrics egress over OTLP with basic auth"):
        proxy.wait_until_succeeds(
            "journalctl -u otlp-test-sink.service --no-pager -o cat"
            " | grep -F 'forgeproxy_bundle_generation_total'"
        )
        proxy.wait_until_succeeds(
            "journalctl -u otlp-test-sink.service --no-pager -o cat"
            " | grep -F 'forgeproxy_clone_total'"
        )

    with subtest("Host metrics egress over OTLP with basic auth"):
        proxy.wait_until_succeeds(
            "journalctl -u otlp-test-sink.service --no-pager -o cat"
            " | grep -F 'system.cpu.time'"
        )
        metrics = proxy.succeed("curl -sf http://localhost:8080/metrics")
        assert "forgeproxy_clone_total{" in metrics, metrics
        assert "forgeproxy_clone_upstream_bytes_total{" in metrics, metrics
        assert "forgeproxy_clone_downstream_bytes_total{" in metrics, metrics
        assert "forgeproxy_cache_repos_total " in metrics, metrics

    with subtest("Pinned fetch still uses cache after waiting"):
        client.succeed("sleep 6")
        client.succeed(
            "rm -rf /tmp/pinnedfetch && "
            "git init /tmp/pinnedfetch && "
            "git -C /tmp/pinnedfetch remote add origin https://octocat:secret123@proxy/octocat/hello-world.git && "
            "git -C /tmp/pinnedfetch fetch origin main"
        )
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy --no-pager | grep -F 'serving upload-pack directly from local disk' | grep -F '\"protocol\":\"http\"' >/dev/null"
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
            " | pv -qL 2097152 > /tmp/slow-upload-pack.out"
            " 2> /tmp/slow-upload-pack.err; "
            "echo $? > /tmp/slow-upload-pack.status"
            "' &"
        )
        proxy.wait_until_succeeds(
            "pgrep -af 'git upload-pack --stateless-rpc --strict .*/hello-world' >/dev/null"
        )
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy --no-pager | grep -F 'serving upload-pack directly from local disk' | grep -F '\"protocol\":\"http\"' >/dev/null"
        )
        old_generation = proxy.succeed(
            "readlink -f ${cacheLayout.repoPath "octocat/hello-world"}"
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
            f"test \"$(readlink -f ${cacheLayout.repoPath "octocat/hello-world"})\" != '{old_generation}'"
        )
        proxy.wait_until_succeeds(
            f"git --git-dir ${cacheLayout.repoPath "octocat/hello-world"} rev-parse refs/heads/main | grep -Fx '{updated_rev}'"
        )
        client.wait_until_succeeds("test -f /tmp/slow-upload-pack.status")
        client.succeed("grep -qx 0 /tmp/slow-upload-pack.status")
        proxy.wait_until_succeeds(f"! test -d '{old_generation}'")
        proxy.wait_until_succeeds(
            "test $(find ${cacheLayout.generationDir "octocat/hello-world"} -mindepth 1 -maxdepth 1 -type d | wc -l) -eq 1"
        )

    with subtest("Shallow-first clone still results in a stored generation"):
        client.succeed(
            "rm -rf /tmp/shallow-only && "
            "git clone --depth=1 https://octocat:secret123@proxy/octocat/shallow-only.git /tmp/shallow-only"
        )
        proxy.wait_until_succeeds(
            "test -L ${cacheLayout.repoPath "octocat/shallow-only"}"
        )
        proxy.wait_until_succeeds(
            "find ${cacheLayout.generationDir "octocat/shallow-only"} -mindepth 1 -maxdepth 1 -type d | grep -q ."
        )

    with subtest("Successful clone cleans tee capture"):
        proxy.wait_until_succeeds(
            "! test -d ${cacheLayout.teeDir "octocat/hello-world"} || "
            "find ${cacheLayout.teeDir "octocat/hello-world"} -mindepth 1 -maxdepth 1 -type d | wc -l | grep -qx 0"
        )
  '';
}
