output "nlb_dns_name" {
  value       = aws_lb.nlb.dns_name
  description = "DNS name of the Network Load Balancer (use with CNAME to proxy_fqdn)"
}

output "nlb_eip" {
  value       = var.nlb_internal ? null : aws_eip.nlb[0].public_ip
  description = "Elastic IP address of the Network Load Balancer (only set if nlb_internal=false)"
}

output "forgeproxy_instance_ids" {
  value       = aws_instance.forgeproxy[*].id
  description = "List of forgeproxy instance IDs"
}

output "keydb_instance_id" {
  value       = aws_instance.keydb.id
  description = "KeyDB instance ID"
}

output "keydb_private_ip" {
  value       = aws_instance.keydb.private_ip
  description = "Private IP address of the KeyDB instance"
}

output "bundle_bucket_name" {
  value       = aws_s3_bucket.bundle.id
  description = "S3 bucket name for bundle storage"
}

output "forgeproxy_ami_id" {
  value       = data.aws_ami.forgeproxy.id
  description = "AMI ID of the forgeproxy image"
}

output "keydb_ami_id" {
  value       = data.aws_ami.keydb.id
  description = "AMI ID of the keydb image"
}

output "secrets_to_populate" {
  value = concat([
    "forgeproxy/forge-admin-token",
    "forgeproxy/webhook-secret",
    "forgeproxy/otlp-config",
  ], [for org in var.org_creds : "forgeproxy/creds/${org.name}"])
  description = "List of Secrets Manager secrets that must be populated before first use"
}

output "connection_string" {
  value       = "https://${var.proxy_fqdn}/"
  description = "Connection string for the forgeproxy proxy"
}

output "ssh_connection_string" {
  value       = "git@${var.proxy_fqdn}:22"
  description = "SSH connection information (port 2222 is proxied through NLB)"
}
