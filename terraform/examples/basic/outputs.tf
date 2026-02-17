output "nlb_dns_name" {
  value       = module.forgecache.nlb_dns_name
  description = "DNS name of the Network Load Balancer"
}

output "nlb_eip" {
  value       = module.forgecache.nlb_eip
  description = "Elastic IP address of the Network Load Balancer"
}

output "forgeproxy_instance_ids" {
  value       = module.forgecache.forgeproxy_instance_ids
  description = "List of forgeproxy instance IDs"
}

output "keydb_instance_id" {
  value       = module.forgecache.keydb_instance_id
  description = "KeyDB instance ID"
}

output "keydb_private_ip" {
  value       = module.forgecache.keydb_private_ip
  description = "Private IP address of the KeyDB instance"
}

output "bundle_bucket_name" {
  value       = module.forgecache.bundle_bucket_name
  description = "S3 bucket name for bundle storage"
}

output "forgeproxy_ami_id" {
  value       = module.forgecache.forgeproxy_ami_id
  description = "AMI ID of the forgecache image"
}

output "keydb_ami_id" {
  value       = module.forgecache.keydb_ami_id
  description = "AMI ID of the keydb image"
}

output "secrets_to_populate" {
  value       = module.forgecache.secrets_to_populate
  description = "List of Secrets Manager secrets that must be populated before first use"
}

output "connection_string" {
  value       = module.forgecache.connection_string
  description = "Connection string for the forgecache proxy"
}

output "ssh_connection_string" {
  value       = module.forgecache.ssh_connection_string
  description = "SSH connection information"
}
