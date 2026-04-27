# Terraform Reference Deployment for forgeproxy

This directory contains Terraform infrastructure-as-code for a fully dynamic, runtime-configured deployment of forgeproxy with:
- Network Load Balancer for multi-instance support (TLS termination with SNI on 443, TCP on 2222)
- Scalable forgeproxy instances managed by a launch template and Auto Scaling Group
- Valkey instance for distributed caching
- Optional ghe-key-lookup sidecar fleet (AMI + internal NLB + runtime config via Secrets Manager)
- Automatic NixOS AMI building and registration
- Runtime-configurable upstream and secrets via AWS Secrets Manager
- No hardcoded hostnames, API URLs, or credentials in AMIs

Grafana dashboard management now lives in the sibling [`terraform/grafana`](./grafana)
directory so dashboard state and datasource wiring can be versioned in-repo
without coupling Grafana provider state to the AWS deployment root.

## Quick Start

### 1. Copy and customize variables

```bash
cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars  # Edit with your values
```

**Required variables:**
- `upstream_hostname` - Git forge hostname (e.g., `ghe.example.com`)
- `upstream_api_url` - Forge API endpoint (e.g., `https://ghe.example.com/api/v3`)
- `bundle_bucket_name` - Globally unique S3 bucket name for bundles
- `nlb_tls_cert_arns_by_hostname` - Map of client-facing hostnames to ACM/IAM certificate ARNs for the NLB HTTPS listener

**Optional bucket deletion behavior:**
- `force_destroy` - Defaults to `false`; set to `true` to allow Terraform to destroy non-empty S3 buckets

**Bring-your-own LB TLS configuration:**
- Set `nlb_tls_cert_arns_by_hostname` to the full set of client-facing DNS names the NLB should accept
- Each map key is a DNS hostname and each map value is the ACM/IAM certificate ARN to attach for that hostname
- The module derives the listener's default certificate and additional SNI certificates from that map
- Use `nlb_tls_ssl_policy` to choose the NLB TLS policy exposed to clients

**Optional shared SSH host identity:**
- Set `forgeproxy_ssh_host_key_secret_arn` to the ARN of an existing Secrets Manager secret whose `SecretString` is the forgeproxy SSH host private key
- If that secret uses a customer-managed KMS key, also set `forgeproxy_ssh_host_key_kms_key_arn`
- Every forgeproxy instance will load that same key, so the SSH server fingerprint stays stable across instance replacements and horizontal scaling
- Leave it unset to keep the current fallback behavior where each instance generates an ephemeral host key at runtime

**Closure variants:**
- `closure_variant = "hardened"`: locked-down baseline (default)
- `closure_variant = "dev"`: debugging-friendly profile (SSH/console enabled, env secret fallback enabled for app-level secret resolution)

**AWS CLI profile fallback for AMI build scripts:**
- Set `aws_profile` when your Terraform AWS provider uses a named profile (for example SSO).
- The module uses this only when `AWS_PROFILE` is not already set in the shell running Terraform.

**Optional post-cutover soak controls:**
- `forgeproxy_cutover_check_interval_secs` controls how often the cleanup helper probes the client-facing HTTPS endpoint after listener cutover.
- `forgeproxy_cutover_required_consecutive_successes` controls how many consecutive successful soak rounds are required before the old slot is scaled down.
- `forgeproxy_cutover_timeout_secs` bounds how long cleanup will keep trying before the apply fails and leaves the old slot intact.

### 2. Initialize Terraform

```bash
terraform init
```

### 3. Review the plan

```bash
terraform plan
```

This will:
1. Build NixOS AMIs for forgeproxy and valkey (and ghe-key-lookup when enabled)
2. Create VPC, subnets, Internet Gateway, NAT Gateway
3. Create security groups and NLB
4. Generate internal TLS materials for backend services
5. Validate or seed the structured bootstrap secrets in AWS Secrets Manager
6. Launch Valkey and the forgeproxy Auto Scaling Group
7. Wait for `/readyz` health checks before the NLB sends traffic to new forgeproxy instances

### 4. Apply the configuration

```bash
terraform apply
```

The build step for AMIs may take 10-15 minutes. Snapshot import can take 5-10 additional minutes.

When `forgeproxy_cache_volume_enabled = true`, rollout preparation also creates
cache seed snapshots from the currently live forgeproxy slot and creates
standby-slot cache EBS volumes from those snapshots before scaling the standby
ASG. On the first deployment, or when no live cache volumes exist yet, the
standby cache volumes are created blank.

### 5. Provide bootstrap secrets before apply

Create a structured JSON file named `./forgeproxy-bootstrap-secrets.json` before the first `terraform apply`. An example file is included at `forgeproxy-bootstrap-secrets.example.json`.

```bash
cp terraform/forgeproxy-bootstrap-secrets.example.json ./forgeproxy-bootstrap-secrets.json
chmod 600 ./forgeproxy-bootstrap-secrets.json
```

Terraform will:
1. Create or update the stable backing secret `<name_prefix>/bootstrap-secrets`
2. Validate that required fields are present before instance creation
3. Derive the individual runtime Secrets Manager secrets from that structured JSON

After the first successful apply, later applies can omit the local file and Terraform will read the existing backing secret from AWS Secrets Manager instead.

If the local file exists and conflicts with the existing backing secret, Terraform emits a warning and asks for interactive confirmation before overwriting the AWS value.

### 6. Verify the deployment

```bash
# Get the NLB endpoint details needed by your DNS provider, such as MarkMonitor, Infoblox, Route 53, Google Cloud DNS, Azure DNS, etc.
terraform output nlb_dns_name
terraform output nlb_zone_id
terraform output nlb_eip

# Health check
curl -k https://$(terraform output -raw nlb_eip)/healthz

# SSH to instance via SSM
aws ssm start-session --target $(terraform output -json forgeproxy_instance_ids | jq -r '.[0]')

# Check logs
sudo journalctl -u forgeproxy -f
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
├── bootstrap-secrets.tf           # Structured bootstrap secret ingestion and validation
├── secrets.tf                     # Derived Secrets Manager secrets
├── ami.tf                         # NixOS AMI build and registration
├── ec2.tf                         # EC2 instances and NLB attachments
├── ghe-key-lookup.tf              # Optional ghe-key-lookup sidecar fleet + internal NLB
└── templates/
    ├── otel-collector-config.yaml.tpl # forgeproxy collector config template
    └── service-config.yaml.tpl    # forgeproxy config.yaml template
```

## Key Design Decisions

### 1. Provider Pattern
All secrets and runtime configuration come from AWS Secrets Manager. The forgeproxy and valkey AMIs are completely generic:
- No hardcoded hostnames
- No hardcoded credentials
- No organization lists

Configuration is fetched at boot time via `ExecStartPre` scripts in systemd services. To change config, update the secret and restart the service — no AMI rebuild needed.

### 2. Upstream and Credentials
- **Upstream hostname/port**: Stored in `forgeproxy/nginx-upstream-hostname` and `forgeproxy/nginx-upstream-port`
  - Changes require restarting nginx: `systemctl restart nginx`
- **Service config**: Complete `config.yaml` in `forgeproxy/service-config`
  - Includes only forgeproxy-owned observability toggles such as local metrics exposure, journald log export enablement, and trace sampling
  - Changes require restarting forgeproxy: `systemctl restart forgeproxy`
- **Collector config**: Complete `otel-collector-config.yaml` in `forgeproxy/otel-collector-config`
  - Includes host metrics and the per-signal OTLP egress settings used by the on-instance Collector
  - Changes require restarting forgeproxy and the collector: `systemctl restart forgeproxy forgeproxy-otlp-collector`
- **Organization credentials**: One secret per org under `forgeproxy/creds/<org-name>`
  - Dynamic discovery at startup; no hardcoded org list
  - Add org: create SM secret, update config, restart forgeproxy
- **SSH host key**: Optional caller-owned secret referenced by `forgeproxy_ssh_host_key_secret_arn`
  - Secret value should be the PEM/OpenSSH private key text for the shared forgeproxy SSH host identity
  - The module does not create or rotate this secret for you

### 3. TLS Configuration
- **Client-facing TLS on the NLB**: Required and caller-owned
  - Set `nlb_tls_cert_arns_by_hostname` to the hostnames and certificate ARNs the listener should accept
  - The module does not request or import public certificates for you; end users bring their own ACM/IAM certificates
- **nginx on the instances**: Uses module-managed TLS only for the NLB-to-instance hop
  - That backend certificate is internal to the deployment and not the public certificate presented to clients
- **Valkey**: TLS disabled in reference deployment (plaintext on port 6379 in private subnet)
  - Network isolation via security groups provides security
  - For production: set `services.valkey.tls.enable = true` in flake.nix

### 4. Optional ghe-key-lookup Sidecar
- Set `enable_ghe_key_lookup = true` to deploy sidecars.
- Configure shape with:
  - `ghe_key_lookup_count`
  - `ghe_key_lookup_instance_type`
  - `ghe_key_lookup_listen_ports`
  - `ghe_key_lookup_vpc_id` / `ghe_key_lookup_subnet_ids`
  - `ghe_key_lookup_security_group_ids` (or let module create one)
- Provide runtime upstream details with:
  - `ghe_key_lookup_ssh_target_endpoint` (required when enabled)
  - optional `ghe_key_lookup_ghe_url`
  - optional SSH/cache variables
- Terraform creates `forgeproxy/ghe-key-lookup-config` and `forgeproxy/ghe-key-lookup-admin-key` secrets; sidecar instances fetch these at boot.

### 5. Single `terraform apply`
Proper `depends_on` ordering ensures:
1. IAM roles → S3 bucket
2. S3 bucket → AMI build
3. AMI build → TLS cert request (needs Valkey private IP)
4. TLS resources → Secrets Manager secrets
5. Secrets → forgeproxy launch template
6. Launch template + target groups → forgeproxy Auto Scaling Group
7. Auto Scaling Group waits for NLB health checks before an update is considered complete

No manual steps required.

### 6. Readiness-gated blue/green forgeproxy rollouts
`terraform apply` now performs forgeproxy replacements as an infrastructure-level blue/green rollout: two Auto Scaling Groups, two sets of NLB target groups, listener cutover, then old-slot scale-down.

This module intentionally does not use AWS CodeDeploy for this path. CodeDeploy is AWS's managed blue/green controller for EC2 deployments, but this repo deploys immutable AMIs via Terraform launch templates rather than an AppSpec-driven application revision with the CodeDeploy agent. Keeping the rollout at the ASG/NLB layer matches the existing deployment model, keeps the entire operation inside `terraform apply`, and still avoids mixed revisions behind the load balancer.

The resulting rollout behavior is:
- The inactive slot launches and warms on the updated launch template while the active slot remains registered with the production listeners.
- By default, Terraform derives the next target slot automatically from the listener that is currently serving traffic; `forgeproxy_active_slot` is only needed as a manual override.
- The NLB health checks gate cutover on `/readyz`, so warm-up must finish before the new slot can receive production traffic.
- Each forgeproxy Auto Scaling Group uses `health_check_type = "ELB"` with a configurable `forgeproxy_health_check_grace_period_secs`, which defaults to `1800` seconds (30 minutes) before failed target-group checks can trigger replacement.
- Startup pre-warm also has a configurable `prewarm_force_open_secs` timeout, and Terraform validates that the ASG grace period is at least that timeout plus the `/readyz` target-group healthy window so readiness force-opens before the ASG can terminate the instance for failed health checks.
- Listener cutover moves all production traffic to a single slot at a time, avoiding mixed `git_revision` values from `/healthz`.
- After listener cutover, Terraform performs a bounded HTTPS soak against `/readyz` and `/healthz` through each configured client-facing hostname before scaling the old slot down.
- If that soak never stabilizes before `forgeproxy_cutover_timeout_secs`, `terraform apply` fails and the old slot is left running instead of being terminated.
- If you force `forgeproxy_active_slot` to the currently live slot during a launch-template change, the prepare helper still fails fast instead of attempting an in-place turnover on the production slot.

Two helper entrypoints back this sequencing:
- `terraform/scripts/forgeproxy-rollout-prepare.sh` scales and waits for the target slot.
- `terraform/scripts/forgeproxy-rollout-cleanup.sh` soaks the cutover through the live NLB and only then scales the inactive slot down.

Those helpers are also exposed as flake packages so they can be run with Nix-managed dependencies:

```bash
nix run .#forgeproxy-rollout-prepare
nix run .#forgeproxy-rollout-cleanup
```

## Operational Changes

### Scale forgeproxy instances
```bash
terraform apply -var='forgeproxy_count=3'
```
No AMI rebuild; existing instances unaffected.

### Change upstream Git forge
Update `upstream_hostname`, `upstream_port`, `upstream_api_url`, or `upstream_git_url_base` in Terraform inputs and rerun `terraform apply`. Terraform regenerates the runtime secrets from those inputs.

### Add new organization
1. Add the new org to `org_creds`.
2. Update `bootstrap-secrets.json` with the new `org_credentials` entry.
3. Rerun `terraform apply`.
4. Restart forgeproxy if you need the new org credentials to be picked up immediately:
   ```bash
   aws ssm send-command \
     --document-name "AWS-RunShellScript" \
     --parameters 'commands=["systemctl restart forgeproxy"]' \
     --targets "Key=tag:Role,Values=forgeproxy"
   ```

### Rotate Valkey password
Terraform generates and persists the Valkey auth token internally. To rotate it, update the Terraform-managed secret and then restart valkey and forgeproxy.

## Region and Partition Support

Set `aws_region` to the AWS region where you want to deploy, and set
`s3_use_fips` according to your compliance and endpoint requirements.

```bash
terraform apply \
  -var='aws_region=us-east-1' \
  -var='s3_use_fips=false'
```

**Note**: NixOS AMI building requires internet access to nixpkgs. In air-gapped
environments, either:
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
aws secretsmanager list-secrets --filters Key=name,Values=forgeproxy/
```

### Instances fail to start
Check systemd logs on the instance:
```bash
aws ssm start-session --target <instance-id>
sudo journalctl -u forgeproxy -n 50
sudo journalctl -u nginx -n 50
sudo journalctl -u valkey -n 50
```

### NLB health checks failing
Ensure the healthz endpoint is available:
```bash
curl -k http://127.0.0.1:8080/healthz
```

## Next Steps

1. **DNS**: Configure every hostname in `var.nlb_tls_cert_arns_by_hostname` with your DNS provider so it resolves to the forgeproxy NLB
   ```bash
   terraform output nlb_dns_name
   terraform output nlb_zone_id
   terraform output configured_proxy_hostnames
   ```
   This project does not manage public DNS records. Use your enterprise DNS workflow and DNS provider of record, such as MarkMonitor, Infoblox, Route 53, Google Cloud DNS, Azure DNS, etc.

2. **TLS for production**: Replace self-signed certificates with real certs
   - Update `terraform/tls.tf` or
   - Update Secrets Manager secrets `forgeproxy/nginx-tls-cert` and `forgeproxy/nginx-tls-key`

3. **Monitoring**: Configure OTLP egress or optional direct scraping
   - Set `metrics_enabled`, `metrics_refresh_interval_secs`, `logs_enabled`, `traces_enabled`, and `traces_sample_ratio` to control forgeproxy's local observability behavior
   - Set `prepare_published_generation_indexes = true` when benchmarking bitmap/MIDX-backed published generations
   - Set `otlp_metrics`, `otlp_logs`, and `otlp_traces` to describe the real external destinations for each signal
   - Set `host_metrics_enabled = true` if you also want the on-instance Collector to emit host CPU, disk, filesystem, load, memory, network, and paging metrics
   - The on-instance Collector reads its exporter configuration from the separate `forgeproxy/otel-collector-config` secret
   - Metrics and logs always egress through the on-instance Collector:
     - Metrics are scraped from `http://127.0.0.1:8080/metrics`
     - Optional host metrics are read locally from the node through the Collector's `hostmetrics` receiver
     - Logs are tailed from `forgeproxy.service` in journald
   - Traces also egress through the on-instance Collector:
     - forgeproxy sends spans to a fixed loopback OTLP receiver on `127.0.0.1:4317`
     - the on-instance Collector then exports those spans to `otlp_traces.endpoint`
   - At startup, forgeproxy writes shared runtime resource attributes to `/run/forgeproxy/runtime-resource-attributes.json`
     - AWS uses IMDSv2; Azure and GCP metadata detection are also attempted
     - the on-instance Collector reuses that file so metrics, logs, and traces share the same stable instance identity
     - when cloud metadata is indeterminate, forgeproxy logs a warning and falls back to best-effort local identifiers instead of failing startup
   - The Collector exports `service.instance.id`, `service.machine_id`, and `service.ip_address` resource attributes, plus `cloud.provider`, `cloud.platform`, and `cloud.region` when they can be detected
   - Each signal can use a different OTLP protocol, endpoint, and HTTP basic-auth credential pair
   - This is the intended place to point at an internal Collector or auth proxy which then forwards to final backends such as VictoriaMetrics
   - Forgeproxy still exposes Prometheus metrics at `http://127.0.0.1:8080/metrics` on the instance

4. **Backup**: Enable automated EBS snapshots and RDS backups (if applicable)

## Support and Documentation

- Forgeproxy docs: See the main repository README
- Terraform docs: https://www.terraform.io/docs
- AWS Secrets Manager: https://docs.aws.amazon.com/secretsmanager/
- NixOS: https://nixos.org/manual/
