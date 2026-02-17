# Terraform Reference Deployment for forgecache

This directory contains Terraform infrastructure-as-code for a fully dynamic, runtime-configured deployment of forgecache with:
- Network Load Balancer for multi-instance support (TCP passthrough on ports 443/2222)
- Scalable forgeproxy instances (count-based)
- KeyDB instance for distributed caching
- Automatic NixOS AMI building and registration
- Runtime-configurable upstream and secrets via AWS Secrets Manager
- No hardcoded hostnames, API URLs, or credentials in AMIs

## Quick Start

### 1. Copy and customize variables

```bash
cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars  # Edit with your values
```

**Required variables:**
- `upstream_hostname` - Git forge hostname (e.g., `ghe.example.com`)
- `upstream_api_url` - Forge API endpoint (e.g., `https://ghe.example.com/api/v3`)
- `proxy_fqdn` - Fully-qualified domain name for the forgecache proxy
- `bundle_bucket_name` - Globally unique S3 bucket name for bundles

### 2. Initialize Terraform

```bash
terraform init
```

### 3. Review the plan

```bash
terraform plan
```

This will:
1. Build NixOS AMIs for forgecache and keydb
2. Create VPC, subnets, Internet Gateway, NAT Gateway
3. Create security groups and NLB
4. Generate self-signed TLS certificates
5. Create all AWS Secrets Manager secrets
6. Launch KeyDB and forgeproxy instances
7. Attach instances to NLB target groups

### 4. Apply the configuration

```bash
terraform apply
```

The build step for AMIs may take 10-15 minutes. Snapshot import can take 5-10 additional minutes.

### 5. Populate required secrets

After `terraform apply` completes, populate these Secrets Manager secrets with actual values:

```bash
aws secretsmanager put-secret-value \
  --secret-id forgecache/forge-admin-token \
  --secret-string "your-forge-admin-pat"

aws secretsmanager put-secret-value \
  --secret-id forgecache/webhook-secret \
  --secret-string "your-webhook-hmac-secret"
```

For each organization in `org_creds`, populate:
```bash
aws secretsmanager put-secret-value \
  --secret-id forgecache/creds/example-org \
  --secret-string "org-specific-credentials-or-pat"
```

### 6. Verify the deployment

```bash
# Get NLB DNS name and EIP
terraform output nlb_dns_name
terraform output nlb_eip

# Health check
curl -k https://$(terraform output -raw nlb_eip)/healthz

# SSH to instance via SSM
aws ssm start-session --target $(terraform output -raw forgeproxy_instance_ids | jq -r '.[0]')

# Check logs
sudo journalctl -u forgecache -f
sudo journalctl -u nginx -f
```

## File Structure

```
terraform/
├── .gitignore                      # Git ignore rules
├── README.md                       # This file
├── terraform.tfvars.example        # Example variables
├── versions.tf                     # Required Terraform version and providers
├── providers.tf                    # Provider configuration
├── variables.tf                    # Input variables
├── outputs.tf                      # Output values
├── s3.tf                          # S3 buckets (AMI staging, bundles)
├── iam.tf                         # IAM roles and policies
├── networking.tf                  # VPC, subnets, IGW, NAT, NLB, SGs
├── tls.tf                         # Self-signed TLS certificates
├── secrets.tf                     # Secrets Manager secrets
├── ami.tf                         # NixOS AMI build and registration
├── ec2.tf                         # EC2 instances and NLB attachments
└── templates/
    └── service-config.yaml.tpl    # forgecache config.yaml template
```

## Key Design Decisions

### 1. Provider Pattern
All secrets and runtime configuration come from AWS Secrets Manager. The forgecache and keydb AMIs are completely generic:
- No hardcoded hostnames
- No hardcoded credentials
- No organization lists

Configuration is fetched at boot time via `ExecStartPre` scripts in systemd services. To change config, update the secret and restart the service — no AMI rebuild needed.

### 2. Upstream and Credentials
- **Upstream hostname/port**: Stored in `forgecache/nginx-upstream-hostname` and `forgecache/nginx-upstream-port`
  - Changes require restarting nginx: `systemctl restart nginx`
- **Service config**: Complete `config.yaml` in `forgecache/service-config`
  - Changes require restarting forgecache: `systemctl restart forgecache`
- **Organization credentials**: One secret per org under `forgecache/creds/<org-name>`
  - Dynamic discovery at startup; no hardcoded org list
  - Add org: create SM secret, update config, restart forgecache

### 3. TLS Configuration
- **nginx**: Uses self-signed cert from Terraform; suitable for internal deployments
  - For production: replace with real certs in Secrets Manager
- **KeyDB**: TLS disabled in reference deployment (plaintext on port 6379 in private subnet)
  - Network isolation via security groups provides security
  - For production: set `services.keydb.tls.enable = true` in flake.nix

### 4. Single `terraform apply`
Proper `depends_on` ordering ensures:
1. IAM roles → S3 bucket
2. S3 bucket → AMI build
3. AMI build → TLS cert request (needs KeyDB private IP)
4. TLS resources → Secrets Manager secrets
5. Secrets → EC2 instances
6. EC2 instances → NLB attachments

No manual steps required.

## Operational Changes

### Scale forgeproxy instances
```bash
terraform apply -var='forgeproxy_count=3'
```
No AMI rebuild; existing instances unaffected.

### Change upstream Git forge
```bash
aws secretsmanager put-secret-value \
  --secret-id forgecache/nginx-upstream-hostname \
  --secret-string "new-ghe.example.com"

aws secretsmanager put-secret-value \
  --secret-id forgecache/nginx-upstream-port \
  --secret-string "443"

# Restart nginx on all instances (via SSM)
aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["systemctl restart nginx"]' \
  --targets "Key=tag:Role,Values=forgeproxy"
```

### Add new organization
1. Create the Secrets Manager secret:
   ```bash
   aws secretsmanager create-secret \
     --name forgecache/creds/new-org \
     --secret-string "org-pat-token"
   ```

2. Update the forgecache config secret to add the org:
   ```bash
   # (manually via AWS console or aws cli put-secret-value)
   ```

3. Restart forgecache:
   ```bash
   aws ssm send-command \
     --document-name "AWS-RunShellScript" \
     --parameters 'commands=["systemctl restart forgecache"]' \
     --targets "Key=tag:Role,Values=forgeproxy"
   ```

### Rotate KeyDB password
```bash
# Generate new password
NEW_PASS=$(openssl rand -base64 32)

# Update the secret
aws secretsmanager put-secret-value \
  --secret-id forgecache/keydb-auth-token \
  --secret-string "$NEW_PASS"

# Restart keydb and forgecache
aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["systemctl restart keydb && systemctl restart forgecache"]' \
  --targets "Key=tag:Name,Values=forgecache-keydb"
```

## Multi-Partition Support

This Terraform module supports both AWS commercial and GovCloud deployments.

### Commercial AWS
```bash
terraform apply \
  -var='aws_region=us-east-1' \
  -var='s3_use_fips=false'
```

### GovCloud
```bash
terraform apply \
  -var='aws_region=us-gov-west-1' \
  -var='s3_use_fips=true'
```

**Note**: NixOS AMI building requires internet access to nixpkgs. In air-gapped GovCloud environments, either:
1. Build the AMIs in an environment with internet access and upload to S3
2. Use pre-built AMI IDs with a `data.aws_ami` data source

## Cleanup

To destroy all resources:

```bash
terraform destroy
```

This will:
1. Terminate all instances
2. Delete NLB and target groups
3. Delete S3 buckets
4. Delete Secrets Manager secrets
5. Delete VPC and all networking resources
6. Deregister AMIs and delete snapshots

**Note**: S3 bucket lifecycle policies will manage deletion of old AMI uploads automatically (30-day retention).

## Troubleshooting

### AMI build fails
Check the nix flake and ensure:
- `flake.lock` is up to date: `nix flake update`
- Dependencies are available: `nix flake check`
- Sufficient disk space for build outputs

### Secrets Manager secrets not found
Verify the secrets exist and the IAM roles have `secretsmanager:GetSecretValue` permission:
```bash
aws secretsmanager list-secrets --filters Key=name,Values=forgecache/
```

### Instances fail to start
Check systemd logs on the instance:
```bash
aws ssm start-session --target <instance-id>
sudo journalctl -u forgecache -n 50
sudo journalctl -u nginx -n 50
sudo journalctl -u keydb -n 50
```

### NLB health checks failing
Ensure the healthz endpoint is available:
```bash
curl -k http://127.0.0.1:8080/healthz
```

## Next Steps

1. **DNS**: Create CNAME records pointing `var.proxy_fqdn` to the NLB DNS name
   ```bash
   terraform output nlb_dns_name
   ```

2. **TLS for production**: Replace self-signed certificates with real certs
   - Update `terraform/tls.tf` or
   - Update Secrets Manager secrets `forgecache/nginx-tls-cert` and `forgecache/nginx-tls-key`

3. **Monitoring**: Set up Prometheus scraping
   - Forgeproxy metrics: `http://<instance-ip>:9090/metrics`
   - Add CIDRs to `metrics_scrape_cidrs` variable for direct access
   - Or use VPC Endpoints to reach instances via private network

4. **Backup**: Enable automated EBS snapshots and RDS backups (if applicable)

## Support and Documentation

- Forgecache docs: See the main repository README
- Terraform docs: https://www.terraform.io/docs
- AWS Secrets Manager: https://docs.aws.amazon.com/secretsmanager/
- NixOS: https://nixos.org/manual/
