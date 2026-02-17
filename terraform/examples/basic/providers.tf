provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Name        = var.name_prefix
      Environment = "production"
      ManagedBy   = "Terraform"
      Project     = "forgecache"
    }
  }
}

provider "tls" {}
provider "local" {}
provider "null" {}
provider "random" {}
