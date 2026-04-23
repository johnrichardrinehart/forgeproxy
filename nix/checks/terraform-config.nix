{
  self,
  pkgs,
}:

let
  renderConfig = pkgs.writeText "forgeproxy-terraform-config-render.tf" ''
    output "service_config" {
      value = templatefile("${../../terraform/templates/service-config.yaml.tpl}", {
        upstream_hostname                          = "ghe.example.com"
        upstream_api_url                           = "https://ghe.example.com/api/v3"
        upstream_git_url_base                      = "https://ghe.example.com"
        backend_type                               = "github-enterprise"
        delegated_repositories                     = []
        config_reload_enabled                      = true
        config_reload_interval_secs                = 60
        valkey_private_ip                          = "10.0.0.10"
        valkey_enable_tls                          = false
        backend_port                               = 8080
        bundle_bucket                              = "forgeproxy-bundles"
        s3_bundle_prefix                           = "forgeproxy/"
        aws_region                                 = "us-east-1"
        s3_use_fips                                = false
        s3_presigned_url_ttl                       = 60
        local_cache_max_percent                    = 0.80
        eviction_policy                            = "lfu"
        prepare_published_generation_indexes       = false
        generation_coalescing_window_secs          = 60
        global_short_circuit_upstream_secs         = 0
        request_wait_for_local_catch_up_secs       = 30
        request_wait_for_active_local_catch_up_secs = 300
        request_time_s3_restore_secs               = 0
        generation_publish_secs                    = 0
        local_upload_pack_first_byte_secs          = 0
        max_concurrent_local_upload_packs          = 4
        max_concurrent_local_upload_packs_per_repo = 1
        index_pack_threads                         = 2
        pack_cache_enabled                         = true
        pack_cache_max_percent                     = 0.20
        pack_cache_high_water_mark                 = 0.90
        pack_cache_low_water_mark                  = 0.75
        pack_cache_eviction_policy                 = "lru"
        pack_cache_wait_for_inflight_secs          = 120
        pack_cache_on_demand_composite_total_secs  = 0
        pack_cache_request_delta_pack_secs         = 0
        pack_cache_max_concurrent_request_deltas   = 1
        pack_cache_min_response_bytes              = 67108864
        prewarm_enabled                            = false
        prewarm_repos                              = []
        prewarm_max_concurrent                     = 2
        bundle_pack_threads                        = 4
        bundle_max_incremental_bundles             = 1
        metrics_enabled                            = true
        metrics_refresh_interval_secs              = 60
        logs_enabled                               = true
        traces_enabled                             = false
        traces_sample_ratio                        = 1.0
        log_level                                  = "info"
        name_prefix                                = "forgeproxy"
        org_creds = [
          {
            name = "octocat"
            mode = "pat"
          }
        ]
        ghe_key_lookup_enabled = false
        ghe_key_lookup_url     = ""
      })
    }
  '';
in
pkgs.runCommand "forgeproxy-terraform-config-sync"
  {
    nativeBuildInputs = [ pkgs.terraform ];
  }
  ''
    cp ${renderConfig} main.tf
    terraform init -backend=false -input=false -no-color
    terraform apply -auto-approve -input=false -no-color
    terraform output -raw service_config > rendered-config.yaml
    ${self.packages.${pkgs.system}.forgeproxy}/bin/forgeproxy \
      --config rendered-config.yaml \
      validate-config
    cp rendered-config.yaml "$out"
  ''
