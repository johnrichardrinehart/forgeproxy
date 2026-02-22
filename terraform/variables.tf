variable "closure_variant" {
  type        = string
  default     = "prod"
  description = "NixOS closure variant: 'prod' (hardened) or 'dev' (root SSH + console logs)."

  validation {
    condition     = contains(["prod", "dev"], var.closure_variant)
    error_message = "closure_variant must be 'prod' or 'dev'."
  }
}

variable "flake_ref" {
  type        = string
  default     = "github:johnrichardrinehart/forgeproxy"
  description = "Nix flake reference for building AMIs (e.g., github:owner/repo, path:./local)"
}

variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region for deployment"

  validation {
    condition     = can(regex("^(us-gov-|us-|eu-|ap-|ca-|me-|af-|sa-|il-)", var.aws_region))
    error_message = "Must be a valid AWS region identifier."
  }
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

variable "backend_type" {
  type        = string
  default     = "github-enterprise"
  description = "Type of backend forge (github-enterprise, gitea, etc.)"
}

variable "proxy_fqdn" {
  type        = string
  description = "FQDN of the proxy (for certificate SAN and config)"
}

variable "bundle_bucket_name" {
  type        = string
  description = "S3 bucket name for bundle storage (must be globally unique)"
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

  validation {
    condition     = var.forgeproxy_count >= 1
    error_message = "forgeproxy_count must be at least 1"
  }
}

variable "keydb_instance_type" {
  type        = string
  default     = "r6i.large"
  description = "EC2 instance type for KeyDB instance"
}

variable "forgeproxy_root_volume_gb" {
  type        = number
  default     = 50
  description = "Root volume size (GB) for forgeproxy instances"
}

variable "keydb_root_volume_gb" {
  type        = number
  default     = 50
  description = "Root volume size (GB) for KeyDB instance"
}


variable "vpc_id" {
  type        = string
  default     = null
  description = "ID of an existing VPC to use. When set, private_subnet_id must also be provided and the module will not create any networking resources (VPC, subnets, IGW, NAT, route tables)."
}

variable "public_subnet_id" {
  type        = string
  default     = null
  description = "ID of an existing public subnet for NLB placement. Required when vpc_id is provided and nlb_internal is false. When vpc_id is provided and nlb_internal is true, this is optional; the NLB will be placed in the private subnet if omitted."
}

variable "private_subnet_id" {
  type        = string
  default     = null
  description = "ID of an existing private subnet for EC2 instances. Must be set when vpc_id is provided."
}


variable "vpc_cidr" {
  type        = string
  default     = "10.0.0.0/16"
  description = "CIDR block for the VPC. Ignored when vpc_id is provided."
}

variable "public_subnet_cidr" {
  type        = string
  default     = "10.0.1.0/24"
  description = "CIDR block for the public subnet (NLB placement). Ignored when vpc_id is provided."
}

variable "private_subnet_cidr" {
  type        = string
  default     = "10.0.2.0/24"
  description = "CIDR block for the private subnet (instances). Ignored when vpc_id is provided."
}

variable "forgeproxy_security_group_id" {
  type        = string
  default     = null
  description = "ID of an existing security group to attach to forgeproxy instances. When set, keydb_security_group_id must also be provided and the module will not create security groups. The caller is responsible for ensuring the keydb SG allows ingress from the forgeproxy SG."
}

variable "keydb_security_group_id" {
  type        = string
  default     = null
  description = "ID of an existing security group to attach to the KeyDB instance. Must be set when forgeproxy_security_group_id is provided."
}

variable "allowed_client_cidrs" {
  type        = list(string)
  default     = ["0.0.0.0/0"]
  description = "CIDR blocks allowed to connect to NLB (ports 443/2222)"
}

variable "nlb_internal" {
  type        = bool
  default     = true
  description = "Whether NLB should be internal (private) vs internet-facing. Set to false to expose via public EIP (corporate internal traffic only, not internet-routable)"
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

variable "local_cache_max_bytes" {
  type        = number
  default     = 53687091200 # 50 GiB
  description = "Maximum size of local cache in bytes"
}

variable "eviction_policy" {
  type        = string
  default     = "lfu"
  description = "Cache eviction policy (lfu or lru)"

  validation {
    condition     = contains(["lfu", "lru"], var.eviction_policy)
    error_message = "eviction_policy must be 'lfu' or 'lru'"
  }
}

variable "s3_bundle_prefix" {
  type        = string
  default     = "forgeproxy/"
  description = "S3 prefix for bundle storage"
}

variable "s3_use_fips" {
  type        = bool
  default     = false
  description = "Use FIPS-compliant S3 endpoints (set to true for GovCloud)"
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

  validation {
    condition     = contains(["trace", "debug", "info", "warn", "error"], var.log_level)
    error_message = "log_level must be one of: trace, debug, info, warn, error"
  }
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

variable "otlp_endpoint" {
  type        = string
  default     = ""
  description = "OpenTelemetry (OTLP) endpoint (optional; leave empty to disable)"
}
