{
  self,
  pkgs,
  lib,
}:

let
  cacheLayout = import ../lib/cache-layout.nix {
    inherit lib;
    root = "/var/cache/forgeproxy";
  };
  testConfigYaml = pkgs.writeText "forgeproxy-startup-init-failure-config.yaml" ''
    upstream:
      hostname: "dead-upstream"
      api_url: "http://127.0.0.1:3999/api/v1"
      admin_token_env: "FORGE_ADMIN_TOKEN"

    upstream_credentials:
      default_mode: "pat"

    proxy:
      ssh_listen: "0.0.0.0:2222"
      http_listen: "127.0.0.1:8080"
    valkey:
      endpoint: "127.0.0.1:6399"
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
        bucket: "missing-bucket"
        prefix: ""
        region: "us-east-1"
        endpoint: "http://127.0.0.1:9999"
        use_fips: false
        presigned_url_ttl: 60
  '';
in
pkgs.testers.runNixOSTest {
  name = "forgeproxy-startup-init-failure";
  globalTimeout = 210;

  nodes.proxy =
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
        logLevel = "debug";
      };

      services.amazon-ssm-agent.enable = lib.mkForce false;

      systemd.services.forgeproxy = {
        environment = lib.mkForce {
          AWS_ACCESS_KEY_ID = "testing";
          AWS_SECRET_ACCESS_KEY = "testing";
          AWS_DEFAULT_REGION = "us-east-1";
          FORGEPROXY_ALLOW_ENV_SECRET_FALLBACK = "1";
          FORGE_ADMIN_TOKEN = "dead-token";
          VALKEY_AUTH_TOKEN = "dead-token";
        };
        serviceConfig.Restart = lib.mkForce "no";
      };

      virtualisation.memorySize = 1024;
    };

  testScript = ''
    start_all()

    with subtest("XFAIL: forgeproxy startup init fails when all dependencies are unreachable"):
        proxy.wait_for_unit("multi-user.target")
        proxy.wait_until_succeeds("test \"$(systemctl show -p ActiveState --value forgeproxy.service)\" = failed")
        proxy.succeed("test \"$(systemctl show -p Result --value forgeproxy.service)\" = exit-code")
        proxy.succeed("test \"$(systemctl show -p ExecMainStatus --value forgeproxy.service)\" = 3")

        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy.service --no-pager -o cat | "
            "grep -F 'starting startup dependency init probes'"
        )
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy.service --no-pager -o cat | "
            "grep -F 'startup init probe failed for Valkey'"
        )
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy.service --no-pager -o cat | "
            "grep -F 'startup init probe failed for upstream'"
        )
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy.service --no-pager -o cat | "
            "grep -F 'startup init probe failed for S3'"
        )
        proxy.wait_until_succeeds(
            "journalctl -u forgeproxy.service --no-pager -o cat | "
            "grep -F 'startup dependency init probes failed'"
        )
        proxy.fail(
            "journalctl -u forgeproxy.service --no-pager -o cat | "
            "grep -F 'startup init probe succeeded'"
        )
  '';
}
