variable "flake_ref" {
  type        = string
  default     = "github:johnrichardrinehart/forgeproxy"
  description = "Nix flake reference for building AMIs (e.g., github:owner/repo, path:./local)"
}

variable "closure_variant" {
  type        = string
  default     = "hardened"
  description = "NixOS closure variant: 'hardened' or 'dev'."
}

variable "disallow_local_nix_builds" {
  type        = bool
  default     = false
  description = "Disallow nix build from building anything locally. Set to true to pass --max-jobs 0."
}

variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region for deployment"
}

variable "aws_profile" {
  type        = string
  default     = ""
  description = "Optional AWS profile for provider auth and module local-exec AWS CLI fallback."
}

variable "name_prefix" {
  type        = string
  default     = "forgeproxy"
  description = "Prefix for resource names"
}

variable "upstream_hostname" {
  type        = string
  description = "Hostname of the upstream Git forge server (e.g., ghe.example.com)"
}

variable "upstream_port" {
  type        = number
  default     = 443
  description = "Port of the upstream Git forge server"
}

variable "upstream_api_url" {
  type        = string
  description = "API URL of the upstream forge (e.g., https://ghe.example.com/api/v3)"
}

variable "upstream_git_url_base" {
  type        = string
  default     = null
  description = "Base URL for upstream Git smart HTTP traffic. Defaults to https://upstream_hostname when null."
}

variable "backend_type" {
  type        = string
  default     = "github-enterprise"
  description = "Type of backend forge (github-enterprise, gitea, etc.)"
}

variable "bundle_bucket_name" {
  type        = string
  description = "S3 bucket name for bundle storage (must be globally unique)"
}

variable "force_destroy" {
  type        = bool
  default     = false
  description = "When true, allow Terraform to destroy non-empty S3 buckets."
}

variable "forgeproxy_instance_type" {
  type        = string
  default     = "t3.large"
  description = "EC2 instance type for forgeproxy instances"
}

variable "forgeproxy_count" {
  type        = number
  default     = 1
  description = "Number of forgeproxy instances"
}

variable "forgeproxy_ssh_host_key_secret_arn" {
  type        = string
  default     = null
  description = "Optional ARN of an existing AWS Secrets Manager secret that stores the shared forgeproxy SSH host private key."
}

variable "forgeproxy_ssh_host_key_kms_key_arn" {
  type        = string
  default     = null
  description = "Optional customer-managed KMS key ARN used to encrypt forgeproxy_ssh_host_key_secret_arn."
}

variable "valkey_instance_type" {
  type        = string
  default     = "r6i.large"
  description = "EC2 instance type for Valkey instance"
}

variable "forgeproxy_root_volume_gb" {
  type        = number
  default     = 50
  description = "Root volume size (GB) for forgeproxy instances"
}

variable "forgeproxy_root_volume_iops" {
  type        = number
  default     = 3000
  description = "gp3 IOPS for forgeproxy root volumes"
}

variable "forgeproxy_root_volume_throughput_mbps" {
  type        = number
  default     = 125
  description = "gp3 throughput in MiB/s for forgeproxy root volumes"
}

variable "valkey_root_volume_gb" {
  type        = number
  default     = 50
  description = "Root volume size (GB) for Valkey instance"
}

variable "enable_ghe_key_lookup" {
  type        = bool
  default     = false
  description = "Enable deployment of ghe-key-lookup sidecar instances and AMI."
}

variable "ghe_key_lookup_instance_type" {
  type        = string
  default     = "t3.small"
  description = "EC2 instance type for ghe-key-lookup sidecar instances"
}

variable "ghe_key_lookup_count" {
  type        = number
  default     = 1
  description = "Number of ghe-key-lookup sidecar instances"
}

variable "ghe_key_lookup_root_volume_gb" {
  type        = number
  default     = 20
  description = "Root volume size (GB) for ghe-key-lookup sidecar instances"
}

variable "ghe_key_lookup_vpc_id" {
  type        = string
  default     = null
  description = "Optional VPC ID override for ghe-key-lookup resources."
}

variable "ghe_key_lookup_subnet_ids" {
  type        = list(string)
  default     = []
  description = "Subnet IDs for ghe-key-lookup instances and internal NLB."
}

variable "ghe_key_lookup_security_group_ids" {
  type        = list(string)
  default     = []
  description = "Security groups to attach to ghe-key-lookup instances."
}

variable "ghe_key_lookup_listen_ports" {
  type        = list(number)
  default     = [3000]
  description = "Listen ports exposed by ghe-key-lookup."
}

variable "ghe_key_lookup_allowed_cidrs" {
  type        = list(string)
  default     = []
  description = "Additional CIDR blocks allowed to reach ghe-key-lookup listen ports when module-managed SG is used."
}

variable "ghe_key_lookup_ssh_target_endpoint" {
  type        = string
  default     = ""
  description = "SSH admin endpoint for GHE queried by ghe-key-lookup (e.g., ghe.example.com)."
}

variable "ghe_key_lookup_ghe_url" {
  type        = string
  default     = ""
  description = "Optional HTTPS base URL for GHE (e.g., https://ghe.example.com)."
}

variable "ghe_key_lookup_ssh_user" {
  type        = string
  default     = "admin"
  description = "SSH username used by ghe-key-lookup to query GHE admin console."
}

variable "ghe_key_lookup_ssh_port" {
  type        = number
  default     = 122
  description = "SSH port used by ghe-key-lookup to query GHE admin console."
}

variable "ghe_key_lookup_cache_ttl_pos" {
  type        = number
  default     = 300
  description = "Positive lookup cache TTL in seconds for ghe-key-lookup."
}

variable "ghe_key_lookup_cache_ttl_neg" {
  type        = number
  default     = 30
  description = "Negative lookup cache TTL in seconds for ghe-key-lookup."
}


variable "vpc_cidr" {
  type        = string
  default     = "10.0.0.0/16"
  description = "CIDR block for the VPC"
}

variable "public_subnet_cidr" {
  type        = string
  default     = "10.0.1.0/24"
  description = "CIDR block for the public subnet (NLB placement)"
}

variable "private_subnet_cidr" {
  type        = string
  default     = "10.0.2.0/24"
  description = "CIDR block for the private subnet (instances)"
}

variable "allowed_client_cidrs" {
  type        = list(string)
  default     = ["0.0.0.0/0"]
  description = "CIDR blocks allowed to connect to NLB (ports 443/2222)"
}

variable "nlb_internal" {
  type        = bool
  default     = true
  description = "Whether NLB should be internal (private) vs internet-facing"
}

variable "nlb_tls_cert_arns_by_hostname" {
  type        = map(string)
  description = "Map of client-facing DNS hostnames to ACM/IAM certificate ARNs for the NLB TLS listener."
}

variable "nlb_tls_ssl_policy" {
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  description = "TLS policy exposed to clients by the NLB HTTPS listener."
}

variable "metrics_scrape_cidrs" {
  type        = list(string)
  default     = []
  description = "CIDR blocks allowed to scrape Prometheus metrics (port 9090)"
}

variable "ec2_key_pair_name" {
  type        = string
  default     = ""
  description = "EC2 key pair name for SSH access (optional; SSM access always available)"
}

variable "local_cache_max_percent" {
  type        = number
  default     = 0.80
  description = "Fraction of the cache filesystem capacity usable by forgeproxy local cache state."

  validation {
    condition     = var.local_cache_max_percent > 0 && var.local_cache_max_percent <= 1
    error_message = "local_cache_max_percent must be in range (0, 1]."
  }
}

variable "max_concurrent_local_upload_packs" {
  type        = number
  default     = 4
  description = "Request path: maximum concurrent local git upload-pack subprocesses per forgeproxy instance."
}

variable "generation_coalescing_window_secs" {
  type        = number
  default     = 60
  description = "Seconds lower-priority refreshes may keep serving the current published generation before publishing a newer one."
}

variable "global_short_circuit_upstream_secs" {
  type        = number
  default     = 0
  description = "Coarse request-path seconds budget before forgeproxy proxies upstream while local work continues in the background. Zero disables the global budget."
}

variable "request_wait_for_local_catch_up_secs" {
  type        = number
  default     = 30
  description = "Request path: seconds a client may wait for quick local catch-up before proxying upstream."
}

variable "request_wait_for_active_local_catch_up_secs" {
  type        = number
  default     = 300
  description = "Request path: seconds a client may wait for an active same-repo local catch-up before proxying upstream."
}

variable "request_time_s3_restore_secs" {
  type        = number
  default     = 0
  description = "Request path: seconds a client may wait for request-triggered S3 restore before proxying upstream. Zero disables this stage budget."
}

variable "generation_publish_secs" {
  type        = number
  default     = 0
  description = "Request path: seconds a client may wait for request-triggered generation publication before proxying upstream. Zero disables this stage budget."
}

variable "local_upload_pack_first_byte_secs" {
  type        = number
  default     = 0
  description = "Request path: seconds a client may wait for first byte from local git upload-pack before proxying upstream. Zero disables this stage budget."
}

variable "max_concurrent_local_upload_packs_per_repo" {
  type        = number
  default     = 1
  description = "Request path: maximum concurrent local git upload-pack subprocesses per repository per forgeproxy instance."
}

variable "index_pack_threads" {
  type        = number
  default     = 2
  description = "Request-adjacent CPU: git index-pack thread limit used for tee imports and pack-cache indexing."

  validation {
    condition     = var.index_pack_threads > 0
    error_message = "index_pack_threads must be greater than 0."
  }
}

variable "pack_cache_enabled" {
  type        = bool
  default     = true
  description = "Enable disk-backed local upload-pack response caching for safe fresh clone requests."
}

variable "pack_cache_max_percent" {
  type        = number
  default     = 0.20
  description = "Fraction of the forgeproxy local cache budget usable by the local pack response cache."
}

variable "pack_cache_high_water_mark" {
  type        = number
  default     = 0.90
  description = "Pack-cache eviction starts when usage exceeds this fraction of the pack-cache budget."

  validation {
    condition     = var.pack_cache_high_water_mark > 0 && var.pack_cache_high_water_mark <= 1
    error_message = "pack_cache_high_water_mark must be in range (0, 1]."
  }
}

variable "pack_cache_low_water_mark" {
  type        = number
  default     = 0.75
  description = "Pack-cache eviction stops when usage drops to or below this fraction of the pack-cache budget."

  validation {
    condition     = var.pack_cache_low_water_mark >= 0 && var.pack_cache_low_water_mark < 1
    error_message = "pack_cache_low_water_mark must be in range [0, 1)."
  }
}

variable "pack_cache_eviction_policy" {
  type        = string
  default     = "lru"
  description = "Pack-cache eviction policy (lru or lfu)."

  validation {
    condition     = contains(["lru", "lfu"], var.pack_cache_eviction_policy)
    error_message = "pack_cache_eviction_policy must be either lru or lfu."
  }
}

variable "pack_cache_wait_for_inflight_secs" {
  type        = number
  default     = 120
  description = "Seconds a same-key clone waits for an in-flight cached pack artifact."
}

variable "pack_cache_on_demand_composite_total_secs" {
  type        = number
  default     = 0
  description = "Request path: seconds a client may wait for on-demand pack-cache composite generation before proxying upstream. Zero disables this stage budget."
}

variable "pack_cache_request_delta_pack_secs" {
  type        = number
  default     = 0
  description = "Request path: seconds a client may wait for request-time delta pack generation during on-demand composite construction. Zero disables this stage budget."
}

variable "pack_cache_max_concurrent_request_deltas" {
  type        = number
  default     = 1
  description = "Request path: maximum request-time pack-cache composite delta builds per forgeproxy instance."

  validation {
    condition     = var.pack_cache_max_concurrent_request_deltas > 0
    error_message = "pack_cache_max_concurrent_request_deltas must be greater than 0."
  }
}

variable "pack_cache_min_response_bytes" {
  type        = number
  default     = 67108864
  description = "Minimum upload-pack response size to store in the pack response cache."
}

variable "prewarm_enabled" {
  type        = bool
  default     = false
  description = "Gate /readyz on startup pre-warming of configured repositories."
}

variable "prewarm_repos" {
  type        = list(string)
  default     = []
  description = "Canonical owner/repo repositories to restore or verify locally before /readyz reports ready."
}

variable "prewarm_max_concurrent" {
  type        = number
  default     = 2
  description = "Maximum repositories to pre-warm concurrently during startup."

  validation {
    condition     = var.prewarm_max_concurrent > 0
    error_message = "prewarm_max_concurrent must be greater than 0."
  }
}

variable "eviction_policy" {
  type        = string
  default     = "lfu"
  description = "Cache eviction policy (lfu or lru)"
}

variable "s3_bundle_prefix" {
  type        = string
  default     = "forgeproxy/"
  description = "S3 prefix for bundle storage"
}

variable "s3_use_fips" {
  type        = bool
  default     = false
  description = "Use FIPS-compliant S3 endpoints when required by your deployment."
}

variable "s3_presigned_url_ttl" {
  type        = number
  default     = 3600
  description = "TTL for S3 presigned URLs (seconds)"
}

variable "log_level" {
  type        = string
  default     = "info"
  description = "Log level for forgeproxy (RUST_LOG)"
}

variable "org_creds" {
  type = list(object({
    name = string
    mode = string
  }))
  default = [
    {
      name = "example-org"
      mode = "pat"
    }
  ]
  description = "List of organization credentials configurations"
}

variable "metrics_enabled" {
  type        = bool
  default     = true
  description = "Expose forgeproxy application metrics locally at /metrics for scraping."
}

variable "metrics_refresh_interval_secs" {
  type        = number
  default     = 60
  description = "Refresh interval in seconds for forgeproxy cache usage gauges."
}

variable "config_reload_enabled" {
  type        = bool
  default     = true
  description = "Periodically hot reload compatible forgeproxy config.yaml changes from the rendered service secret."
}

variable "config_reload_interval_secs" {
  type        = number
  default     = 60
  description = "Maximum delay in seconds before forgeproxy observes a compatible rendered config.yaml change."

  validation {
    condition     = var.config_reload_interval_secs > 0
    error_message = "config_reload_interval_secs must be greater than 0"
  }
}

variable "prepare_published_generation_indexes" {
  type        = bool
  default     = false
  description = "Prepare published generation bitmap and multi-pack-index support in the background after exposing them to clone readers."
}

variable "bundle_pack_threads" {
  type        = number
  default     = 4
  description = "Git pack.threads value used for bundle generation, published-generation bitmap/MIDX preparation, and request-time pack-cache composite deltas."

  validation {
    condition     = var.bundle_pack_threads > 0
    error_message = "bundle_pack_threads must be greater than 0."
  }
}

variable "bundle_max_incremental_bundles" {
  type        = number
  default     = 1
  description = "Maximum incremental bundle entries retained per repo-global bundle manifest."
}

variable "logs_enabled" {
  type        = bool
  default     = true
  description = "Allow the on-instance OTEL collector to tail forgeproxy journald logs."
}

variable "traces_enabled" {
  type        = bool
  default     = false
  description = "Emit forgeproxy tracing spans to the local OTEL collector receiver."
}

variable "traces_sample_ratio" {
  type        = number
  default     = 1.0
  description = "Trace sampling ratio in the range [0.0, 1.0]."
}

variable "otlp_metrics" {
  type = object({
    endpoint             = string
    protocol             = string
    export_interval_secs = number
    basic_auth_username  = string
    basic_auth_password  = string
  })
  default = {
    endpoint             = ""
    protocol             = "grpc"
    export_interval_secs = 60
    basic_auth_username  = ""
    basic_auth_password  = ""
  }
  description = "OTLP metrics exporter settings written into the collector runtime config."
  sensitive   = true
}

variable "host_metrics_enabled" {
  type        = bool
  default     = false
  description = "Enable host-level CPU, memory, filesystem, disk, network, load, and paging metrics in the on-instance OTLP collector."
}

variable "otlp_logs" {
  type = object({
    endpoint             = string
    protocol             = string
    export_interval_secs = number
    basic_auth_username  = string
    basic_auth_password  = string
  })
  default = {
    endpoint             = ""
    protocol             = "grpc"
    export_interval_secs = 60
    basic_auth_username  = ""
    basic_auth_password  = ""
  }
  description = "OTLP log exporter settings written into the collector runtime config."
  sensitive   = true
}

variable "otlp_traces" {
  type = object({
    endpoint             = string
    protocol             = string
    export_interval_secs = number
    basic_auth_username  = string
    basic_auth_password  = string
  })
  default = {
    endpoint             = ""
    protocol             = "grpc"
    export_interval_secs = 60
    basic_auth_username  = ""
    basic_auth_password  = ""
  }
  description = "OTLP trace exporter settings written into the collector runtime config."
  sensitive   = true
}
