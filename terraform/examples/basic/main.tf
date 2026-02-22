# To consume from git instead of a local path, use:
#   source = "git::https://github.com/johnrichardrinehart/forgeproxy.git//terraform?ref=main"
module "forgeproxy" {
  source = "../../"

  flake_ref = var.flake_ref

  aws_region  = var.aws_region
  name_prefix = var.name_prefix

  upstream_hostname = var.upstream_hostname
  upstream_port     = var.upstream_port
  upstream_api_url  = var.upstream_api_url
  backend_type      = var.backend_type

  proxy_fqdn         = var.proxy_fqdn
  bundle_bucket_name = var.bundle_bucket_name

  forgeproxy_instance_type  = var.forgeproxy_instance_type
  forgeproxy_count          = var.forgeproxy_count
  forgeproxy_root_volume_gb = var.forgeproxy_root_volume_gb

  keydb_instance_type  = var.keydb_instance_type
  keydb_root_volume_gb = var.keydb_root_volume_gb
  vpc_cidr             = var.vpc_cidr
  public_subnet_cidr   = var.public_subnet_cidr
  private_subnet_cidr  = var.private_subnet_cidr

  allowed_client_cidrs = var.allowed_client_cidrs
  nlb_internal         = var.nlb_internal
  metrics_scrape_cidrs = var.metrics_scrape_cidrs
  ec2_key_pair_name    = var.ec2_key_pair_name

  local_cache_max_bytes = var.local_cache_max_bytes
  eviction_policy       = var.eviction_policy

  s3_bundle_prefix     = var.s3_bundle_prefix
  s3_use_fips          = var.s3_use_fips
  s3_presigned_url_ttl = var.s3_presigned_url_ttl

  log_level     = var.log_level
  org_creds     = var.org_creds
  otlp_endpoint = var.otlp_endpoint
}
