output "nlb_dns_name" {
  value       = aws_lb.nlb.dns_name
  description = "DNS name of the Network Load Balancer for use when configuring your DNS provider, such as MarkMonitor, Infoblox, Route 53, Google Cloud DNS, Azure DNS, etc."
}

output "nlb_zone_id" {
  value       = aws_lb.nlb.zone_id
  description = "Hosted zone ID of the Network Load Balancer for DNS alias records."
}

output "nlb_eip" {
  value       = var.nlb_internal ? null : aws_eip.nlb[0].public_ip
  description = "Elastic IP address of the Network Load Balancer (only set if nlb_internal=false)"
}

output "forgeproxy_instance_ids" {
  value = sort(
    local.forgeproxy_target_slot == "blue" ? data.aws_instances.forgeproxy_blue.ids : data.aws_instances.forgeproxy_green.ids
  )
  description = "List of current forgeproxy instance IDs in the active deployment slot"
}

output "forgeproxy_active_slot" {
  value       = local.forgeproxy_target_slot
  description = "Blue/green deployment slot configured to receive production traffic after apply"
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
  value       = [aws_secretsmanager_secret.bootstrap_secrets.name]
  description = "Backing Secrets Manager secret that stores the structured bootstrap secrets JSON consumed by Terraform"
}

output "bootstrap_secrets_secret_name" {
  value       = aws_secretsmanager_secret.bootstrap_secrets.name
  description = "Stable Secrets Manager secret name used to store structured bootstrap secrets for this deployment"
}

output "configured_proxy_hostnames" {
  value       = local.configured_proxy_hostnames
  description = "Configured client-facing DNS hostnames for the forgeproxy NLB TLS listener"
}

output "https_connection_strings" {
  value       = { for hostname in local.configured_proxy_hostnames : hostname => "https://${hostname}/" }
  description = "HTTPS clone base URLs keyed by configured client-facing hostname"
}

output "ssh_connection_strings" {
  value = {
    for hostname in local.configured_proxy_hostnames :
    hostname => (var.nlb_ssh_listen_port == 22 ? "git@${hostname}" : "ssh://git@${hostname}:${var.nlb_ssh_listen_port}")
  }
  description = "SSH clone connection strings keyed by configured client-facing hostname"
}
