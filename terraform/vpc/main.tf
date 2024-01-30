resource "aws_vpc" "ecommerce_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "ECOMMERCE-PROD-VPC-SEOUL"
  }
}

resource "aws_subnet" "public_subnet" {
  count             = length(var.public_subnets)
  vpc_id            = aws_vpc.ecommerce_vpc.id
  cidr_block        = var.public_subnets[count.index]["cidr"]
  availability_zone = var.public_subnets[count.index]["az"]

  tags = {
    Name = "ECOMMERCE-PROD-VPC-SEOUL-public-subnet-${count.index + 1}"
  }
}

resource "aws_subnet" "private_subnet" {
  count             = length(var.private_subnets)
  vpc_id            = aws_vpc.ecommerce_vpc.id
  cidr_block        = var.private_subnets[count.index]["cidr"]
  availability_zone = var.private_subnets[count.index]["az"]

  tags = {
    Name = "ECOMMERCE-PROD-VPC-SEOUL-private-subnet-${count.index + 1}"
  }
}

resource "aws_subnet" "db_subnet" {
  count             = length(var.db_subnets)
  vpc_id            = aws_vpc.ecommerce_vpc.id
  cidr_block        = var.db_subnets[count.index]["cidr"]
  availability_zone = var.db_subnets[count.index]["az"]

  tags = {
    Name = "ECOMMERCE-PROD-VPC-SEOUL-db-subnet-${count.index + 1}"
  }
}
