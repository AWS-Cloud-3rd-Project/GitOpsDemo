terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.57"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.10"
    }
  }
    backend s3 {
    bucket         = "amz-draw-dev-bucket-tfstate" # S3 버킷 이름
    key            = "terraform/terraform.tfstate" # tfstate 저장 경로
    region         = "ap-northeast-2"
    dynamodb_table = "terraform-dev-tfstate-lock" # dynamodb table 이름
    }
}
