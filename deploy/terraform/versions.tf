terraform {
  required_version = ">= 1.8.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.62.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Project   = "ebpf-shield"
      ManagedBy = "terraform"
    }
  }
}
