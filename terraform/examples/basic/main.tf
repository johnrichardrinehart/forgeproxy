# To consume from git instead of a local path, use:
#   source = "git::https://github.com/johnrichardrinehart/forgeproxy.git//terraform?ref=main"
module "forgeproxy" {
  source = "../../"

  flake_ref       = var.flake_ref
  closure_variant = var.closure_variant

  aws_region  = var.aws_region
  aws_profile = var.aws_profile
  name_prefix = var.name_prefix

  upstream_hostname     = var.upstream_hostname
  upstream_port         = var.upstream_port
  upstream_api_url      = var.upstream_api_url
  upstream_git_url_base = var.upstream_git_url_base
  backend_type          = var.backend_type

  bundle_bucket_name = var.bundle_bucket_name
  force_destroy      = var.force_destroy

  forgeproxy_instance_type            = var.forgeproxy_instance_type
  forgeproxy_count                    = var.forgeproxy_count
  forgeproxy_root_volume_gb           = var.forgeproxy_root_volume_gb
  forgeproxy_ssh_host_key_secret_arn  = var.forgeproxy_ssh_host_key_secret_arn
  forgeproxy_ssh_host_key_kms_key_arn = var.forgeproxy_ssh_host_key_kms_key_arn

  valkey_instance_type  = var.valkey_instance_type
  valkey_root_volume_gb = var.valkey_root_volume_gb

  enable_ghe_key_lookup              = var.enable_ghe_key_lookup
  ghe_key_lookup_instance_type       = var.ghe_key_lookup_instance_type
  ghe_key_lookup_count               = var.ghe_key_lookup_count
  ghe_key_lookup_root_volume_gb      = var.ghe_key_lookup_root_volume_gb
  ghe_key_lookup_vpc_id              = var.ghe_key_lookup_vpc_id
  ghe_key_lookup_subnet_ids          = var.ghe_key_lookup_subnet_ids
  ghe_key_lookup_security_group_ids  = var.ghe_key_lookup_security_group_ids
  ghe_key_lookup_listen_ports        = var.ghe_key_lookup_listen_ports
  ghe_key_lookup_allowed_cidrs       = var.ghe_key_lookup_allowed_cidrs
  ghe_key_lookup_ssh_target_endpoint = var.ghe_key_lookup_ssh_target_endpoint
  ghe_key_lookup_ghe_url             = var.ghe_key_lookup_ghe_url
  ghe_key_lookup_ssh_user            = var.ghe_key_lookup_ssh_user
  ghe_key_lookup_ssh_port            = var.ghe_key_lookup_ssh_port
  ghe_key_lookup_cache_ttl_pos       = var.ghe_key_lookup_cache_ttl_pos
  ghe_key_lookup_cache_ttl_neg       = var.ghe_key_lookup_cache_ttl_neg

  vpc_cidr            = var.vpc_cidr
  public_subnet_cidr  = var.public_subnet_cidr
  private_subnet_cidr = var.private_subnet_cidr

  allowed_client_cidrs          = var.allowed_client_cidrs
  nlb_internal                  = var.nlb_internal
  nlb_tls_cert_arns_by_hostname = var.nlb_tls_cert_arns_by_hostname
  nlb_tls_ssl_policy            = var.nlb_tls_ssl_policy
  metrics_scrape_cidrs          = var.metrics_scrape_cidrs
  ec2_key_pair_name             = var.ec2_key_pair_name

  local_cache_max_bytes = var.local_cache_max_bytes
  eviction_policy       = var.eviction_policy

  s3_bundle_prefix     = var.s3_bundle_prefix
  s3_use_fips          = var.s3_use_fips
  s3_presigned_url_ttl = var.s3_presigned_url_ttl

  log_level            = var.log_level
  org_creds            = var.org_creds
  otlp_metrics         = var.otlp_metrics
  host_metrics_enabled = var.host_metrics_enabled
  otlp_logs            = var.otlp_logs
  otlp_traces          = var.otlp_traces
}
