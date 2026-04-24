locals {
  bootstrap_secrets_secret_name = "${var.name_prefix}/bootstrap-secrets"
  bootstrap_secrets_file_path   = "${path.root}/forgeproxy-bootstrap-secrets.json"
  bootstrap_secrets_file_exists = fileexists(local.bootstrap_secrets_file_path)
}

data "aws_secretsmanager_secret" "bootstrap_secrets" {
  count = local.bootstrap_secrets_file_exists ? 0 : 1

  name = local.bootstrap_secrets_secret_name
}

data "aws_secretsmanager_secret_version" "bootstrap_secrets" {
  count = local.bootstrap_secrets_file_exists ? 0 : 1

  secret_id = data.aws_secretsmanager_secret.bootstrap_secrets[0].id
}

resource "aws_secretsmanager_secret" "bootstrap_secrets" {
  name                    = local.bootstrap_secrets_secret_name
  description             = "Structured bootstrap secrets for forgeproxy Terraform deployments"
  recovery_window_in_days = 0

  tags = {
    Name = "${var.name_prefix}-bootstrap-secrets"
  }
}

locals {
  bootstrap_secrets_json = local.bootstrap_secrets_file_exists ? file(local.bootstrap_secrets_file_path) : data.aws_secretsmanager_secret_version.bootstrap_secrets[0].secret_string
  bootstrap_secrets      = jsondecode(local.bootstrap_secrets_json)

  bootstrap_pat_org_names = toset([
    for org in var.org_creds : org.name
    if lower(org.mode) == "pat"
  ])

  bootstrap_org_credentials = try(local.bootstrap_secrets.org_credentials, {})

  bootstrap_missing_pat_org_credentials = [
    for org_name in local.bootstrap_pat_org_names : org_name
    if trimspace(try(local.bootstrap_org_credentials[org_name], "")) == ""
  ]
}

resource "terraform_data" "bootstrap_secrets_validation" {
  input = {
    bootstrap_secrets_secret_name = local.bootstrap_secrets_secret_name
    bootstrap_secrets_file_path   = local.bootstrap_secrets_file_path
    bootstrap_secrets_file_exists = local.bootstrap_secrets_file_exists
  }

  lifecycle {
    precondition {
      condition     = trimspace(try(local.bootstrap_secrets.forge_admin_token, "")) != ""
      error_message = "bootstrap-secrets must include a non-empty forge_admin_token."
    }

    precondition {
      condition     = trimspace(try(local.bootstrap_secrets.webhook_secret, "")) != ""
      error_message = "bootstrap-secrets must include a non-empty webhook_secret."
    }

    precondition {
      condition     = length(local.bootstrap_missing_pat_org_credentials) == 0
      error_message = "bootstrap-secrets must include non-empty org_credentials entries for every PAT org in var.org_creds. Missing orgs: ${join(", ", local.bootstrap_missing_pat_org_credentials)}"
    }

    precondition {
      condition     = !local.ghe_key_lookup_enabled || trimspace(try(local.bootstrap_secrets.ghe_key_lookup_admin_key, "")) != ""
      error_message = "bootstrap-secrets must include a non-empty ghe_key_lookup_admin_key when enable_ghe_key_lookup is true."
    }
  }
}

resource "terraform_data" "bootstrap_secrets_conflict_prompt" {
  count = local.bootstrap_secrets_file_exists ? 1 : 0

  triggers_replace = {
    bootstrap_secrets_secret_name = local.bootstrap_secrets_secret_name
    bootstrap_secrets_file_path   = local.bootstrap_secrets_file_path
    bootstrap_secrets_file_sha256 = local.bootstrap_secrets_file_exists ? filesha256(local.bootstrap_secrets_file_path) : ""
    aws_region                    = var.aws_region
    aws_profile                   = var.aws_profile
  }

  provisioner "local-exec" {
    command = "bash ${path.module}/scripts/check-bootstrap-secrets-conflict.sh"

    environment = {
      AWS_REGION           = var.aws_region
      AWS_PROFILE_FALLBACK = var.aws_profile
      SECRET_NAME          = local.bootstrap_secrets_secret_name
      LOCAL_FILE_PATH      = local.bootstrap_secrets_file_path
    }
  }
}

resource "aws_secretsmanager_secret_version" "bootstrap_secrets" {
  secret_id = aws_secretsmanager_secret.bootstrap_secrets.id

  secret_string = local.bootstrap_secrets_json

  depends_on = [
    terraform_data.bootstrap_secrets_validation,
    terraform_data.bootstrap_secrets_conflict_prompt,
  ]
}
