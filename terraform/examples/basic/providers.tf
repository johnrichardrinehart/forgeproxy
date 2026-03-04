provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile != "" ? var.aws_profile : null

  default_tags {
    tags = {
      Name        = var.name_prefix
      Environment = "production"
      ManagedBy   = "Terraform"
      Project     = "forgeproxy"
    }
  }
}

provider "tls" {}
provider "local" {}
provider "null" {}
provider "random" {}
