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

  testConfigYaml = pkgs.writeText "forgeproxy-adaptive-tuning-test-config.yaml" ''
    backend_type: "gitea"

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

    proxy:
      ssh_listen: "0.0.0.0:2222"
      http_listen: "0.0.0.0:8080"

    valkey:
      endpoint: "valkey:6379"
      tls: false
      auth_token_env: "VALKEY_AUTH_TOKEN"

    auth:
      ssh_user_lookup_cache_ttl: 30
      ssh_repo_access_cache_ttl: 30
      http_cache_ttl: 120
      negative_cache_ttl: 60

    adaptive_tuning:
      enabled: true
      mode: "active"
      controller: "demand_resource"
      min_sample_count: 20
      recommendation_ttl_secs: 300
      recommendation_max_staleness_secs: 300
      slo:
        clone_latency_secs: 30.0
        first_byte_latency_secs: 5.0
        fallback_rate: 0.05
      slo_policy:
        enabled: true
        min_sample_count: 1
        near_miss_grace_fraction: 0.10
        near_miss_grace_secs: 1.0
        early_abort_overrun_fraction: 0.25
      resource_pressure:
        cpu_busy_high_watermark: 0.85
        disk_busy_high_watermark: 0.85
        memory_available_min_percent: 1.0
      demand_resource:
        cpu_provisioning_fraction: 2.0
        cpu_provisioning_fraction_when_memory_constrained: 1.0
      bounds:
        upstream_clone_concurrency: { min: 1, max: 8, max_increase_step: 1, max_decrease_step: 2 }
        upstream_fetch_concurrency: { min: 1, max: 8, max_increase_step: 1, max_decrease_step: 2 }
        upstream_clone_per_repo_per_instance: { min: 1, max: 4, max_increase_step: 1, max_decrease_step: 2 }
        upstream_clone_per_repo_across_instances: { min: 1, max: 8, max_increase_step: 1, max_decrease_step: 2 }
        tee_capture_concurrency: { min: 1, max: 8, max_increase_step: 1, max_decrease_step: 2 }
        tee_capture_per_repo: { min: 1, max: 4, max_increase_step: 1, max_decrease_step: 1 }
        local_upload_pack_concurrency: { min: 1, max: 8, max_increase_step: 1, max_decrease_step: 2 }
        local_upload_pack_per_repo: { min: 1, max: 4, max_increase_step: 1, max_decrease_step: 1 }
        deep_validation_concurrency: { min: 1, max: 4, max_increase_step: 1, max_decrease_step: 1 }
        prewarm_concurrency: { min: 1, max: 8, max_increase_step: 1, max_decrease_step: 2 }
        bundle_generation_concurrency: { min: 1, max: 8, max_increase_step: 1, max_decrease_step: 2 }
        pack_cache_request_delta_concurrency: { min: 1, max: 8, max_increase_step: 1, max_decrease_step: 2 }
        pack_cache_background_warming_concurrency: { min: 1, max: 8, max_increase_step: 1, max_decrease_step: 2 }
        bundle_pack_threads: { min: 1, max: 16, max_increase_step: 1, max_decrease_step: 2 }
        local_upload_pack_threads: { min: 1, max: 16, max_increase_step: 1, max_decrease_step: 2 }
        index_pack_threads: { min: 1, max: 16, max_increase_step: 1, max_decrease_step: 2 }
        request_wait_for_local_catch_up_secs: { min: 0, max: 120, max_increase_step: 5, max_decrease_step: 10 }
        request_time_s3_restore_secs: { min: 0, max: 120, max_increase_step: 5, max_decrease_step: 10 }
        generation_publish_secs: { min: 0, max: 120, max_increase_step: 5, max_decrease_step: 10 }
        local_upload_pack_first_byte_secs: { min: 0, max: 120, max_increase_step: 2, max_decrease_step: 5 }

    clone:
      lock_ttl: 60
      lock_wait_timeout: 120
      ssh_upload_pack_close_grace_secs: 5
      max_concurrent_upstream_clones: 1
      max_concurrent_upstream_fetches: 1
      reserved_request_time_upstream_fetches: 0
      max_concurrent_upstream_clones_per_repo_across_instances: 1
      max_concurrent_upstream_clones_per_repo_per_instance: 1
      max_concurrent_local_upload_packs: 1
      max_concurrent_local_upload_packs_per_repo: 1
      local_upload_pack_threads: 1
      index_pack_threads: 1
      max_concurrent_tee_captures: 1
      max_concurrent_tee_captures_per_repo_per_instance: 1
      max_concurrent_deep_validations: 1
      hydration_mode: "publish_from_capture"
      prepare_published_generation_midx: false
      published_generation_bitmap_policy: "never"

    pack_cache:
      enabled: false
      max_percent: 0.25
      high_water_mark: 0.90
      low_water_mark: 0.75
      eviction_policy: "lru"
      wait_for_inflight_secs: 0
      min_response_bytes: 1

    fetch_schedule:
      enabled: false

    bundles:
      min_clone_count_for_bundles: 1000
      bundle_lock_ttl: 300
      pack_threads: 1
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
  name = "forgeproxy-adaptive-tuning";
  globalTimeout = 60 * 8;

  nodes = {
    ghe =
      {
        config,
        pkgs,
        ...
      }:
      {
        services.gitea = {
          enable = true;
          settings = {
            server = {
              HTTP_PORT = 3000;
              ROOT_URL = "http://ghe:3000/";
              DOMAIN = "ghe";
            };
            service.DISABLE_REGISTRATION = true;
          };
        };

        environment.systemPackages = with pkgs; [
          config.services.gitea.package
          curl
          git
          jq
          sqlite
        ];

        networking.firewall.allowedTCPPorts = [ 3000 ];
        virtualisation.memorySize = 1536;
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
        imports = [ self.nixosModules.forgeproxy ];

        services.forgeproxy = {
          enable = true;
          package = pkgs.forgeproxy;
          configFile = testConfigYaml;
          logLevel = "debug";
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
        ];

        networking.firewall.allowedTCPPorts = [ 8080 ];
        virtualisation.cores = 4;
        virtualisation.memorySize = 1536;
      };

    client =
      { pkgs, ... }:
      {
        environment.systemPackages = with pkgs; [
          curl
          git
        ];
      };
  };

  testScript = ''
    import time

    def metrics_text():
        return proxy.succeed("curl -sf http://localhost:8080/metrics")

    def wait_for_metric_value(metric_name, fragments, predicate, timeout=60):
        deadline = time.time() + timeout
        last_metrics = ""
        while time.time() < deadline:
            last_metrics = metrics_text()
            for line in last_metrics.splitlines():
                if not line.startswith(metric_name):
                    continue
                if all(fragment in line for fragment in fragments):
                    try:
                        value = float(line.rsplit(" ", 1)[1])
                    except Exception:
                        continue
                    if predicate(value):
                        return value, line, last_metrics
            time.sleep(1)
        recent_logs = proxy.succeed(
            "journalctl -u forgeproxy --since '3m ago' --no-pager -o cat || true"
        )
        raise Exception(
            f"timed out waiting for {metric_name} with {fragments}; "
            f"recent logs:\n{recent_logs}\nmetrics tail:\n{last_metrics[-4000:]}"
        )

    def wait_for_metric_line(metric_name, fragments, timeout=60):
        return wait_for_metric_value(metric_name, fragments, lambda value: value > 0, timeout)

    ghe.start()
    valkey.start()
    s3.start()

    ${common.valkeyStartScript}
    ${common.s3StartScript}

    with subtest("Gitea starts"):
        ghe.wait_for_unit("gitea.service")
        ghe.wait_for_open_port(3000)

    with subtest("seed upstream repository with enough data to keep clone work observable"):
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
            ' -d \'{"name": "adaptive-large", "auto_init": false}\'''
        )
        ghe.succeed(
            "set -e && "
            "tmp=$(mktemp -d) && "
            "cd $tmp && "
            "git init -b main && "
            "git config user.email test@test.local && "
            "git config user.name Test && "
            "echo adaptive > README.md && "
            "head -c 67108864 /dev/urandom > payload.bin && "
            "git add README.md payload.bin && "
            "git commit -m adaptive-large && "
            "git remote add origin http://${common.giteaAdminUser}:${common.giteaAdminPassword}@localhost:3000/${common.giteaAdminUser}/adaptive-large.git && "
            "git push -u origin main"
        )

    with subtest("start forgeproxy with demand_resource adaptive tuning"):
        proxy.start()
        client.start()
        proxy.wait_for_unit("forgeproxy.service")
        proxy.wait_for_open_port(8080)
        proxy.succeed("test $(nproc) -ge 4")
        rendered = proxy.succeed("cat ${testConfigYaml}")
        assert 'controller: "demand_resource"' in rendered, rendered
        assert 'mode: "active"' in rendered, rendered

    with subtest("initial clone triggers event-driven demand_resource recommendations"):
        client.succeed(
            "git clone http://octocat:secret123@proxy:8080/octocat/adaptive-large.git /tmp/adaptive-prime"
        )
        proxy.wait_until_succeeds(
            "test -L ${cacheLayout.repoPath "octocat/adaptive-large"}"
        )
        _, decision_line, _ = wait_for_metric_line(
            "forgeproxy_adaptive_decisions_total",
            [
                'controller="demand_resource"',
                'mode="active"',
                'decision="rebalance"',
                'reason="event_demand"',
            ],
        )
        assert "demand_resource" in decision_line, decision_line

    with subtest("controller allocates above static startup limits from active demand and vCPU budget"):
        upstream_value, upstream_line, _ = wait_for_metric_value(
            "forgeproxy_adaptive_effective_value",
            ['knob="upstream_clone_concurrency"'],
            lambda value: value >= 2,
        )
        thread_value, thread_line, _ = wait_for_metric_value(
            "forgeproxy_adaptive_recommended_value",
            [
                'controller="demand_resource"',
                'mode="active"',
                'knob="bundle_pack_threads"',
            ],
            lambda value: value >= 2,
        )
        assert upstream_value >= 2, upstream_line
        assert thread_value >= 2, thread_line

    with subtest("warm local clone records demand-resource TTFB stage observations"):
        client.succeed(
            "git clone http://octocat:secret123@proxy:8080/octocat/adaptive-large.git /tmp/adaptive-local"
        )
        readme = client.succeed("cat /tmp/adaptive-local/README.md")
        assert "adaptive" in readme, readme
        wait_for_metric_line(
            "forgeproxy_upload_pack_ttfb_stage_seconds_sum",
            [
                'protocol="https"',
                'result="success"',
                'stage="local_upload_pack_first_byte_wait"',
            ],
        )
  '';
}
