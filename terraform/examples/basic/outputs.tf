output "nlb_dns_name" {
  value       = module.forgeproxy.nlb_dns_name
  description = "DNS name of the Network Load Balancer for use with your DNS provider, such as MarkMonitor, Infoblox, Route 53, Google Cloud DNS, Azure DNS, etc."
}

output "nlb_eip" {
  value       = module.forgeproxy.nlb_eip
  description = "Elastic IP address of the Network Load Balancer"
}

output "forgeproxy_instance_ids" {
  value       = module.forgeproxy.forgeproxy_instance_ids
  description = "List of forgeproxy instance IDs"
}

output "valkey_instance_id" {
  value       = module.forgeproxy.valkey_instance_id
  description = "Valkey instance ID"
}

output "valkey_private_ip" {
  value       = module.forgeproxy.valkey_private_ip
  description = "Private IP address of the Valkey instance"
}

output "bundle_bucket_name" {
  value       = module.forgeproxy.bundle_bucket_name
  description = "S3 bucket name for bundle storage"
}

output "forgeproxy_ami_id" {
  value       = module.forgeproxy.forgeproxy_ami_id
  description = "AMI ID of the forgeproxy image"
}

output "valkey_ami_id" {
  value       = module.forgeproxy.valkey_ami_id
  description = "AMI ID of the valkey image"
}

output "ghe_key_lookup_ami_id" {
  value       = module.forgeproxy.ghe_key_lookup_ami_id
  description = "AMI ID of the ghe-key-lookup image"
}

output "ghe_key_lookup_instance_ids" {
  value       = module.forgeproxy.ghe_key_lookup_instance_ids
  description = "List of ghe-key-lookup instance IDs"
}

output "ghe_key_lookup_nlb_dns_name" {
  value       = module.forgeproxy.ghe_key_lookup_nlb_dns_name
  description = "Internal NLB DNS name for ghe-key-lookup"
}

output "secrets_to_populate" {
  value       = module.forgeproxy.secrets_to_populate
  description = "List of Secrets Manager secrets that must be populated before first use"
}

output "configured_proxy_hostnames" {
  value       = module.forgeproxy.configured_proxy_hostnames
  description = "Configured client-facing DNS hostnames for the forgeproxy NLB TLS listener"
}

output "https_connection_strings" {
  value       = module.forgeproxy.https_connection_strings
  description = "HTTPS clone base URLs keyed by configured client-facing hostname"
}

output "ssh_connection_strings" {
  value       = module.forgeproxy.ssh_connection_strings
  description = "SSH clone connection strings keyed by configured client-facing hostname"
}
