# Grafana Dashboard Terraform

This directory manages the forgeproxy Grafana dashboard separately from the AWS
deployment Terraform in the parent directory.

It keeps Grafana provider state, datasource defaults, and dashboard JSON in the
repository so dashboard changes can be reviewed and versioned on the same
branch as the application changes they depend on.

## Files

- `main.tf`: Grafana provider, folder, and dashboard resources
- `variables.tf`: provider and dashboard inputs
- `terraform.tfvars.example`: example datasource and dashboard values
- `dashboards/forgeproxy.json.tftpl`: Terraform-templated Grafana dashboard JSON

## Usage

```bash
cd terraform/grafana
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars
terraform init
terraform plan
terraform apply
```

Required inputs:

- `grafana_url`
- `grafana_auth`
- `metrics_datasource_name`
- `metrics_datasource_uid`
- `logs_datasource_name`
- `logs_datasource_uid`
- `traces_datasource_name`
- `traces_datasource_uid`

The datasource names drive the default dropdown selections Grafana shows in the
dashboard. The datasource UIDs back the actual panel queries.

## Notes

- No backend is configured here by default. Add one if you want remote state.
- The dashboard file uses Terraform templating only for deploy-time values
  like UID, title, default time range, and datasource defaults. Grafana's own
  runtime variables such as `${datasource}` and `$instance` remain intact.
