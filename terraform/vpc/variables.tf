variable "vpc_cidr" {
  description = "The CIDR block for the VPC"
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "A list of availability zones in the region"
  type        = list(string)
  default     = ["ap-northeast-2a", "ap-northeast-2b"]
}

variable "public_subnets" {
  description = "A list of public subnets"
  type        = list(map(string))
  default     = [
    {
      cidr = "10.0.0.0/20",
      az   = "ap-northeast-2a"
    },
    {
      cidr = "10.0.16.0/20",
      az   = "ap-northeast-2b"
    }
  ]
}

variable "private_subnets" {
  description = "A list of private subnets"
  type        = list(map(string))
  default     = [
    {
      cidr = "10.0.128.0/20",
      az   = "ap-northeast-2a"
    },
    {
      cidr = "10.0.144.0/20",
      az   = "ap-northeast-2b"
    }
  ]
}

variable "db_subnets" {
  description = "A list of database subnets"
  type        = list(map(string))
  default     = [
    {
      cidr = "10.0.160.0/20",
      az   = "ap-northeast-2a"
    },
    {
      cidr = "10.0.176.0/20",
      az   = "ap-northeast-2b"
    }
  ]
}

variable "tags" {
  description = "The tags for the resources"
  type        = map(string)
  default     = {
    Terraform = "true"
    Environment = "Production"
  }
}
