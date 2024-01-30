provider "aws" {
    region = "ap-northeast-2" # 서울 리전
}

# EKS 클러스터를 위한 IAM 역할
resource "aws_iam_role" "eks_cluster_role" {
    name = "EKS-CLUSTER-ROLE"

    assume_role_policy = jsonencode({
        Version = "2012-10-17",
        Statement = [{
            Action = "sts:AssumeRole",
            Effect = "Allow",
            Principal = {
                Service = "eks.amazonaws.com"
            }
        }]
    })

    # 여기에 EKS 클러스터 관련 IAM 정책 연결 필요
}

# VPC 생성
resource "aws_vpc" "ecommerce_prod_vpc" {
    cidr_block = "10.0.0.0/16"
    enable_dns_support = true
    enable_dns_hostnames = true
    tags = { Name = "ECOMMERCE-PROD-VPC-SEOUL" }
}

# 퍼블릭 서브넷 생성
resource "aws_subnet" "public_subnet" {
    count = 2
    vpc_id = aws_vpc.ecommerce_prod_vpc.id
    cidr_block = count.index == 0 ? "10.0.1.0/24" : "10.0.2.0/24"
    availability_zone = count.index == 0 ? "ap-northeast-2a" : "ap-northeast-2c"
    map_public_ip_on_launch = true
    tags = { Name = "Public Subnet ${count.index}" }
}

# 프라이빗 서브넷 생성 (서비스용)
resource "aws_subnet" "private_service_subnet" {
    count = 2
    vpc_id = aws_vpc.ecommerce_prod_vpc.id
    cidr_block = count.index == 0 ? "10.0.3.0/24" : "10.0.4.0/24"
    availability_zone = count.index == 0 ? "ap-northeast-2a" : "ap-northeast-2c"
    tags = { Name = "Private Service Subnet ${count.index}" }
}

# 프라이빗 서브넷 생성 (DB용)
resource "aws_subnet" "private_db_subnet" {
    count = 2
    vpc_id = aws_vpc.ecommerce_prod_vpc.id
    cidr_block = count.index == 0 ? "10.0.5.0/24" : "10.0.6.0/24"
    availability_zone = count.index == 0 ? "ap-northeast-2a" : "ap-northeast-2c"
    tags = { Name = "Private DB Subnet ${count.index}" }
}

# EKS 클러스터 생성
resource "aws_eks_cluster" "ecommerce_cluster" {
    name = "ECOMMERCE-CLUSTER-PROD-SEOUL-EKS"
    role_arn = aws_iam_role.eks_cluster_role.arn

    vpc_config {
        subnet_ids = concat(aws_subnet.private_service_subnet.*.id, aws_subnet.private_db_subnet.*.id)
        endpoint_private_access = true
        endpoint_public_access = false
    }

    # 제어플레인 로깅 설정 (모두 꺼진 상태)
    logging {
        cluster_logging {
            enabled_types = []
        }
    }
}

# EKS 클러스터 애드온 설정 (kube-proxy, coredns, VPC CNI, Pod Identity Webhook)
resource "aws_eks_addon" "kube_proxy" {
    cluster_name = aws_eks_cluster.ecommerce_cluster.name
    addon_name = "kube-proxy"
    addon_version = "v1.28.1-eksbuild.1"
    resolve_conflicts = "OVERWRITE"
}

resource "aws_eks_addon" "coredns" {
    cluster_name = aws_eks_cluster.ecommerce_cluster.name
    addon_name = "coredns"
    addon_version = "v1.10.1-eksbuild.2"
    resolve_conflicts = "OVERWRITE"
}

resource "aws_eks_addon" "vpc_cni" {
    cluster_name = aws_eks_cluster.ecommerce_cluster.name
    addon_name = "vpc-cni"
    addon_version = "v1.14.1-eksbuild.1"
    resolve_conflicts = "OVERWRITE"
}

resource "aws_eks_addon" "pod_identity_webhook" {
    cluster_name = aws_eks_cluster.ecommerce_cluster.name
    addon_name = "aws-node-termination-handler"
    addon_version = "v1.1.0-eksbuild.1"
    resolve_conflicts = "OVERWRITE"
}

# NAT 게이트웨이 및 EIP 설정
resource "aws_eip" "nat_eip" {
    count = 2
    vpc = true
    tags = { Name = "NAT EIP ${count.index}" }
}

resource "aws_nat_gateway" "nat_gateway" {
    count = 2
    allocation_id = aws_eip.nat_eip[count.index].id
    subnet_id = aws_subnet.public_subnet[count.index].id
    tags = { Name = "NAT Gateway ${count.index}" }
}

# 인터넷 게이트웨이 및 라우팅 설정
resource "aws_internet_gateway" "igw" {
    vpc_id = aws_vpc.ecommerce_prod_vpc.id
    tags = { Name = "ECOMMERCE IGW" }
}

resource "aws_route_table" "public_route_table" {
    vpc_id = aws_vpc.ecommerce_prod_vpc.id
    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.igw.id
    }
    tags = { Name = "Public Route Table" }
}

resource "aws_route_table_association" "public_subnet_rta" {
    count = length(aws_subnet.public_subnet.*.id)
    subnet_id = aws_subnet.public_subnet[count.index].id
    route_table_id = aws_route_table.public_route_table.id
}

# 노드 그룹을 위한 IAM 역할
resource "aws_iam_role" "eks_node_role" {
  name = "eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  # 관련 IAM 정책 연결 필요
}

# 서비스 노드 그룹 생성
resource "aws_eks_node_group" "service_node_group" {
  cluster_name = aws_eks_cluster.ecommerce_cluster.name
  node_group_name = "ecommerce-service-node-group"
  node_role_arn = aws_iam_role.eks_node_role.arn
  subnet_ids = aws_subnet.private_service_subnet.*.id

  scaling_config {
    desired_size = 2
    max_size = 3
    min_size = 1
  }

  instance_types = ["t3.medium"]
}

# DB 노드 그룹 생성
resource "aws_eks_node_group" "db_node_group" {
  cluster_name = aws_eks_cluster.ecommerce_cluster.name
  node_group_name = "ecommerce-db-node-group"
  node_role_arn = aws_iam_role.eks_node_role.arn
  subnet_ids = aws_subnet.private_db_subnet.*.id

  scaling_config {
    desired_size = 1
    max_size = 2
    min_size = 1
  }

  instance_types = ["t3.large"]
}
