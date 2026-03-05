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

output "valkey_instance_id" {
  value       = aws_instance.valkey.id
  description = "Valkey instance ID"
}

output "valkey_private_ip" {
  value       = aws_instance.valkey.private_ip
  description = "Private IP address of the Valkey instance"
}

output "bundle_bucket_name" {
  value       = aws_s3_bucket.bundle.id
  description = "S3 bucket name for bundle storage"
}

output "forgeproxy_ami_id" {
  value       = data.aws_ami.forgeproxy.id
  description = "AMI ID of the forgeproxy image"
}

output "valkey_ami_id" {
  value       = data.aws_ami.valkey.id
  description = "AMI ID of the valkey image"
}

output "ghe_key_lookup_ami_id" {
  value       = local.ghe_key_lookup_enabled ? data.aws_ami.ghe_key_lookup[0].id : null
  description = "AMI ID of the ghe-key-lookup image (null when disabled)"
}

output "ghe_key_lookup_instance_ids" {
  value       = aws_instance.ghe_key_lookup[*].id
  description = "List of ghe-key-lookup instance IDs"
}

output "ghe_key_lookup_private_ips" {
  value       = aws_instance.ghe_key_lookup[*].private_ip
  description = "Private IP addresses of ghe-key-lookup instances"
}

output "ghe_key_lookup_nlb_dns_name" {
  value       = local.ghe_key_lookup_enabled ? aws_lb.ghe_key_lookup[0].dns_name : null
  description = "Internal NLB DNS name for ghe-key-lookup (null when disabled)"
}

output "secrets_to_populate" {
  value = concat(
    [
      aws_secretsmanager_secret.forge_admin_token.name,
      aws_secretsmanager_secret.webhook_secret.name,
      aws_secretsmanager_secret.otlp_config.name,
    ],
    [for _, secret in aws_secretsmanager_secret.org_creds : secret.name],
    local.ghe_key_lookup_enabled ? [
      aws_secretsmanager_secret.ghe_key_lookup_admin_key[0].name,
    ] : []
  )
  description = "List of actual Secrets Manager secret names that must be populated before first use"
}

output "connection_string" {
  value       = "https://${var.proxy_fqdn}/"
  description = "Connection string for the forgeproxy proxy"
}

output "ssh_connection_string" {
  value       = var.nlb_ssh_listen_port == 22 ? "git@${var.proxy_fqdn}" : "ssh://git@${var.proxy_fqdn}:${var.nlb_ssh_listen_port}"
  description = "SSH connection string for Git cloning"
}
