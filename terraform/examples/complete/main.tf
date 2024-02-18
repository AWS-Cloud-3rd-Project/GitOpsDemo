provider "aws" {
  region = local.region
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

resource "helm_release" "metrics_server" {
  
  depends_on = [ module.eks ]
  namespace        = "kube-system"
  name             = "metrics-server"
  chart            = "metrics-server"
  version          = "3.11.0"
  repository       = "https://kubernetes-sigs.github.io/metrics-server/"
  create_namespace = true
  set {
    name  = "replicas"
    value = 1
  }
}

resource "helm_release" "aws_load_balancer_controller" {
  depends_on = [module.eks]
  name       = "aws-load-balancer-controller"
  namespace  = "kube-system"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  
  set {
    name  = "clusterName"
    value = module.eks.cluster_name
  }

  set {
    name  = "serviceAccount.create"
    value = "false"
  }

  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  
}


data "aws_availability_zones" "available" {}
data "aws_caller_identity" "current" {}

locals {
  name   = "amz_mall_dev${replace(basename(path.cwd), "_", "-")}"
  region = "ap-northeast-2"

  vpc_cidr = "10.0.0.0/16"
  azs = ["ap-northeast-2a", "ap-northeast-2c"]

  tags = {
    Name = local.name
  }
}
################################################################################
# VPC & Subnet
################################################################################

# VPC
resource "aws_vpc" "amz_mall_vpc" {
  cidr_block = local.vpc_cidr
  enable_dns_support = true
  enable_dns_hostnames = true
  tags = {
    Name = local.name
  }
}

# 퍼블릭 서브넷 1
resource "aws_subnet" "public_subnet_1" {
  vpc_id            = aws_vpc.amz_mall_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = local.azs[0]
  map_public_ip_on_launch = true
  tags = {
    Name = "${local.name}_public_subnet_1"
    "kubernetes.io/role/elb" = "1"
  }
}

# 퍼블릭 서브넷 2
resource "aws_subnet" "public_subnet_2" {
  vpc_id            = aws_vpc.amz_mall_vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = local.azs[1]
  map_public_ip_on_launch = true
  tags = {
    Name = "${local.name}_public_subnet_2"
    "kubernetes.io/role/elb" = "1"
  }
}

# 프라이빗 서브넷 1
resource "aws_subnet" "private_subnet_1" {
  vpc_id            = aws_vpc.amz_mall_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = local.azs[0]
  map_public_ip_on_launch = false
  tags = {
    Name = "${local.name}_private_subnet_1"
  }
}

# 프라이빗 서브넷 2
resource "aws_subnet" "private_subnet_2" {
  vpc_id            = aws_vpc.amz_mall_vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = local.azs[1]
  map_public_ip_on_launch = false
  tags = {
    Name = "${local.name}_private_subnet_2"
  }
}

# 인터넷 게이트웨이 
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.amz_mall_vpc.id
  tags = {
    Name = "${local.name}_igw"
  }
}

################################################################################
# NAT Instance
################################################################################

# # 보안그룹 - NAT Instance
# resource "aws_security_group" "nat_instance_sg" {
#   name        = "nat-instance-sg"
#   description = "Security group for NAT instance"
#   vpc_id      = aws_vpc.amz_mall_vpc.id

#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = ["0.0.0.0/0"]
#   }

#   tags = {
#     Name = "nat-instance-sg"
#   }
# }

# # NAT Instance 1
# resource "aws_instance" "nat_instance_1" {
#   ami           = "ami-08074b02473276b92"
#   instance_type = "t2.micro"
#   subnet_id     = aws_subnet.public_subnet_1.id # 첫 번째 퍼블릭 서브넷의 ID
#   security_groups = [aws_security_group.nat_instance_sg.id]

#   associate_public_ip_address = true
#   source_dest_check = false

#   tags = {
#     Name = "NAT-Instance"
#   }
# }

# # 탄력적 ip 할당
# resource "aws_eip" "nat_eip" {
#   domain = "vpc"
# }

# # 탄력적 ip 연결
# resource "aws_eip_association" "eip_assoc" {
#   instance_id   = aws_instance.nat_instance_1.id
#   allocation_id = aws_eip.nat_eip.id
# }

# # NAT Instance 2
# resource "aws_instance" "nat_instance_2" {
#   ami           = "ami-08074b02473276b92"
#   instance_type = "t2.micro"
#   subnet_id     = aws_subnet.public_subnet_2.id
#   security_groups = [aws_security_group.nat_instance_sg.id]

#   associate_public_ip_address = true
#   source_dest_check = false

#   tags = {
#     Name = "NAT-Instance-2"
#   }
# }

# # NAT Instance 탄력적 ip 2
# resource "aws_eip" "nat_eip_2" {
#   domain = "vpc"
# }

# # NAT Instance 탄력적 IP 연결 2
# resource "aws_eip_association" "eip_assoc2" {
#   instance_id   = aws_instance.nat_instance_2.id
#   allocation_id = aws_eip.nat_eip_2.id
# }

################################################################################
# NAT GateWay
################################################################################


resource "aws_eip" "nat_eip_1" {
  domain = "vpc"
  depends_on = [aws_internet_gateway.igw]
}

resource "aws_nat_gateway" "nat_gw_1" {
  allocation_id = aws_eip.nat_eip_1.id
  subnet_id     = aws_subnet.public_subnet_1.id
  tags = {
    Name = "${local.name}_nat_gw_1"
  }
}

resource "aws_eip" "nat_eip_2" {
  domain = "vpc"
  depends_on = [aws_internet_gateway.igw]
}

resource "aws_nat_gateway" "nat_gw_2" {
  allocation_id = aws_eip.nat_eip_2.id
  subnet_id     = aws_subnet.public_subnet_2.id
  tags = {
    Name = "${local.name}_nat_gw_2"
  }
}
################################################################################
# private route table
################################################################################

# 프라이빗 라우팅 테이블 생성 및 서브넷 연결 ( 프라이빗 서브넷 -> NAT 용도 )
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.amz_mall_vpc.id
  tags = {
    Name = "${local.name}_private_rt"
  }
}

# 라우팅 테이블에 서브넷 연결
resource "aws_route_table_association" "private_subnet_1_association" {
  subnet_id      = aws_subnet.private_subnet_1.id
  route_table_id = aws_route_table.private_rt.id
}

# 라우팅 테이블에 서브넷 연결
resource "aws_route_table_association" "private_subnet_2_association" {
  subnet_id      = aws_subnet.private_subnet_2.id
  route_table_id = aws_route_table.private_rt.id
}

################################################################################
# private route - NAT Instance
################################################################################

# # 라우팅 지정 ( Private Subnet -> NAT )
# resource "aws_route" "private_to_nat" {
#   route_table_id         = aws_route_table.private_rt.id
#   destination_cidr_block = "0.0.0.0/0"
#   network_interface_id = data.aws_network_interface.nat_instance_1_ni.id
# }

# # 네트워크 인터페이스 생성
# data "aws_network_interface" "nat_instance_1_ni" {
#   filter {
#     name   = "attachment.instance-id"
#     values = [aws_instance.nat_instance_1.id]
#   }
# }

################################################################################
# private route table - NAT GW
################################################################################
resource "aws_route" "private_rt_nat_gw_1" {
  route_table_id         = aws_route_table.private_rt.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat_gw_1.id
}
################################################################################
# public route table
################################################################################

# 퍼블릭 라우팅 테이블
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.amz_mall_vpc.id
  tags = {
    Name = "${local.name}_public_rt"
  }
}

# 라우팅 & CIDR 지정  (Public Subnet -> 인터넷 게이트웨이)
resource "aws_route" "public_rt_igw" {
  route_table_id         = aws_route_table.public_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

# 라우팅 테이블에 서브넷 id 할당 ( 퍼블릭 서브넷 )
resource "aws_route_table_association" "public_subnet_1_association" {
  subnet_id      = aws_subnet.public_subnet_1.id
  route_table_id = aws_route_table.public_rt.id
}

# 라우팅 테이블에 서브넷 id 할당 ( 퍼블릭 서브넷 )
resource "aws_route_table_association" "public_subnet_2_association" {
  subnet_id      = aws_subnet.public_subnet_2.id
  route_table_id = aws_route_table.public_rt.id
}



################################################################################
# RDS DataBase
################################################################################

# RDS 서브넷 1
resource "aws_subnet" "rds_subnet_1" {
  vpc_id            = aws_vpc.amz_mall_vpc.id
  cidr_block        = "10.0.100.0/24"  # Start from a higher range
  availability_zone = local.azs[0]
  tags = {
    Name = "${local.name}-rds-1"
  }
}

# RDS 서브넷 2
resource "aws_subnet" "rds_subnet_2" {
  vpc_id            = aws_vpc.amz_mall_vpc.id
  cidr_block        = "10.0.101.0/24"  # Ensure there's no overlap
  availability_zone = local.azs[1]
  tags = {
    Name = "${local.name}-rds-2"
  }
}


# DB(RDS) 서브넷 그룹 생성
resource "aws_db_subnet_group" "rds_subnet_group" {
  name        = "ecommerce-seoul-mariadb-subnet-group"
  subnet_ids  = [aws_subnet.rds_subnet_1.id, aws_subnet.rds_subnet_2.id]
  tags = {
    Name = "My_DB_Subnet_Group"
  }
}

# 라우팅 테이블에 서브넷 ID 연결 ( 퍼블릭 서브넷 )
resource "aws_route_table_association" "rds_subnet_1_association" {
  subnet_id      = aws_subnet.rds_subnet_1.id
  route_table_id = aws_route_table.private_rt.id
}

# 라우팅 테이블에 서브넷 ID 연결 ( 퍼블릭 서브넷 )
resource "aws_route_table_association" "rds_subnet_2_association" {
  subnet_id      = aws_subnet.rds_subnet_2.id
  route_table_id = aws_route_table.private_rt.id
}

# RDS 인스턴스 생성
# resource "aws_db_instance" "default" {
#   allocated_storage    = 20
#   storage_type         = "gp2"
#   engine               = "mariadb"
#   engine_version       = "10.6.14"  # MariaDB 엔진 버전을 확인하세요
#   instance_class       = "db.t3.medium"
#   identifier           = "amzdraw-seoul-mariadb"  # 데이터베이스 인스턴스 식별자
#   db_name              = "amzdraw-DB"  # 데이터베이스 이름
#   username             = "dohyungjunyong"
#   password             = "dohyungjunyong"
#   parameter_group_name = "default.mariadb10.6"  # MariaDB에 맞는 파라미터 그룹
#   db_subnet_group_name = aws_db_subnet_group.rds_subnet_group.name
#   skip_final_snapshot  = true
# }


# AWS Load Balancer Controller용 IAM 역할을 생성
# 이 역할은 Kubernetes 서비스 계정이 AWS 서비스와 상호작용할 수 있도록 설정된 OIDC 공급자와 연동
# https://registry.terraform.io/modules/terraform-aws-modules/iam/aws/latest/examples/iam-role-for-service-accounts-eks#module_load_balancer_controller_targetgroup_binding_only_irsa_role
module "load_balancer_controller_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = "${local.name}-lb-controller-irsa-role"
  attach_load_balancer_controller_policy = true 
  
  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }

  tags = local.tags
}
# module "load_balancer_controller_targetgroup_binding_only_irsa_role": TargetGroupBinding 작업만을 위한 별도의 IAM 역할을 생성
# 이는 특정한 작업에 대한 더 세분화된 접근 권한을 설정할 때 유용
module "load_balancer_controller_targetgroup_binding_only_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name = "${local.name}-lb-controller-tg-binding-only-irsa-role"
  attach_load_balancer_controller_targetgroup_binding_only_policy = true  

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }

  tags = local.tags
}

# resource "kubernetes_service_account" "aws-load-balancer-controller": Kubernetes 내에서 aws-load-balancer-controller라는 서비스 계정을 생성하고,
# 이전에 만든 IAM 역할과 연결 이 서비스 계정은 AWS Load Balancer Controller가 Kubernetes 클러스터 내에서 실행될 때 사용
resource "kubernetes_service_account" "aws-load-balancer-controller" {
  metadata {
    name        = "aws-load-balancer-controller"
    namespace   = "kube-system"
    annotations = {
      "eks.amazonaws.com/role-arn" = module.load_balancer_controller_irsa_role.iam_role_arn 
    }

    labels = {
      "app.kubernetes.io/component" = "controller"
      "app.kubernetes.io/name" = "aws-load-balancer-controller"
    }

  }

  depends_on = [module.load_balancer_controller_irsa_role]
}

################################################################################
# EKS Module
################################################################################

# EKS 모듈 
module "eks" {

  # 모듈 디렉토리
  source = "../.."

  # 클러스터 버전 1.28
  cluster_version = "1.28"

  # 클러스터 이름
  cluster_name = local.name

  # 퍼블릭에서 클러스터 엔드포인트 연결 허용
  cluster_endpoint_public_access = true

  # 클러스터 에드온 설정
  cluster_addons = {
    # Kubernetes 클러스터 내에서 DNS 서비스를 제공
    # 클러스터 내의 서비스 이름을 IP 주소로 변환하여, 
    # 컨테이너가 서비스 이름을 사용하여 서로를 찾고 통신할 수 있게 한다
    coredns = {
      preserve    = true # 클러스터 업그레이드 시 coredns의 설정이 보존됩니다.
      most_recent = true
    }
    # Kubernetes 클러스터 내의 네트워킹을 관리합니다.
    # 각 노드에 실행되며, TCP, UDP, SCTP 스트림을 포드 간에
    # 또는 클러스터 외부와 포드 사이에서 라우팅하는 역할
    kube-proxy = {
      most_recent = true
    }
    #  네트워크 인터페이스
    # 각 Kubernetes 팟에 VPC 네트워크 내의 IP 주소를 할당하여,
    # 팟이 VPC의 자원과  통신
    vpc-cni = {
      most_recent = true
    }
  }


  # 외부 암호화 키 사용 설정

  #  AWS에서 생성한 KMS 키 대신 사용자가 지정한
  # KMS 키를 사용하겠다는 것을 나타냅니다.
  create_kms_key = false 

  cluster_encryption_config = {
    resources        = ["secrets"] # 암호화할 리소스 유형을 지정 여기서는 Kubernetes 시크릿을 암호화
  provider_key_arn = module.kms.key_arn # 사용할 KMS 키의 ARN 지정. 이 키는 module.kms에서 생성, 지정
}

# 추가 IAM 역할 정책 설정
# 이 설정은 EKS 클러스터에 필요한 추가적인 IAM 정책을 연결할 때 사용
iam_role_additional_policies = {
  additional = aws_iam_policy.additional.arn # 추가 정책의 ARN을 지정. 이 정책은 aws_iam_policy 리소스를 통해 생성
}

  # VPC 설정 - EKS 클러스터를 위한 VPC와 서브넷 설정
  vpc_id = aws_vpc.amz_mall_vpc.id 
  subnet_ids = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id] # 프라이빗 서브넷 ID들

  # 클러스터 보안 그룹 규칙 확장 - EKS 클러스터의 보안을 강화하기 위한 추가 규칙
  cluster_security_group_additional_rules = {
    # 노드 간 임시 포트에 대한 TCP 트래픽 허용
    ingress_nodes_ephemeral_ports_tcp = {
      description                = "Nodes on ephemeral ports"
      protocol                   = "tcp"
      from_port                  = 1025
      to_port                    = 65535
      type                       = "ingress"
      source_node_security_group = true
    }
    # 다른 보안 그룹으로부터의 SSH 접근 허용
    ingress_source_security_group_id = {
      description              = "Ingress from another computed security group"
      protocol                 = "tcp"
      from_port                = 22
      to_port                  = 22
      type                     = "ingress"
      source_security_group_id = aws_security_group.additional.id
    }
  }

  # 노드 간 보안 그룹 규칙 확장 - 노드 간 통신 보안 강화
  node_security_group_additional_rules = {
    # 노드 간 모든 포트와 프로토콜에 대한 통신 허용
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
    # 다른 보안 그룹으로부터의 SSH 접근 허용
    ingress_source_security_group_id = {
      description              = "Ingress from another computed security group"
      protocol                 = "tcp"
      from_port                = 22
      to_port                  = 22
      type                     = "ingress"
      source_security_group_id = aws_security_group.additional.id
    }
  }

  # EKS 관리형 노드 그룹 설정
  eks_managed_node_groups = {
    # 서비스용 노드 그룹
    service_node_group = {
      name = "service_node_group"

      # iam_role_attach_cni_policy 옵션을 true로 설정하면, Amazon EKS 클러스터를 위한 Amazon VPC CNI 플러그인에 필요한 IAM 정책이 자동으로 노드 그룹에 연결
      iam_role_attach_cni_policy = true

      instance_types = ["t3.large"]
      capacity_type  = "ON_DEMAND"
      min_size     = 2
      max_size     = 4
      desired_size = 2
      subnet_ids     = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id] # 프라이빗 서브넷 ID
      tags = {
        ExtraTag = "service_node_group"
      }
    }
    # 에코 시스템용 노드 그룹
    eco_system_node_group = {
      iam_role_attach_cni_policy = true
      name = "eco_system_node_group"
      instance_types = ["t3.large"]
      capacity_type  = "ON_DEMAND"
      min_size     = 1
      max_size     = 1
      desired_size = 1
      subnet_ids     = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id] # 프라이빗 서브넷 ID
      tags = {
        ExtraTag = "eco_system_node_group"
      }
    }
    # search_node_group = {
    #   name = "search_node_group"

    #   instance_types = ["t3.medium"]
    #   capacity_type  = "ON_DEMAND"

    #   min_size     = 1
    #   max_size     = 1
    #   desired_size = 1
    #   # local.azs에서 az의 인덱스를 사용하여 각 서브넷 ID에 접근
    #   subnet_ids     =  [aws_subnet.rds_subnet_2.id]

    #   tags = {
    #     ExtraTag = "search_node_group"
    #   }
    # }
  }

  # aws-auth configmap 관리 설정 - 클러스터 접근 권한 관리
  manage_aws_auth_configmap = true

  # 클러스터 사용자 설정 - 클러스터 접근을 위한 IAM 사용자 설정
  aws_auth_users = [
    {
      userarn  = "arn:aws:iam::009946608368:user/DOHYUNG"
      username = "DOHYUNG"
      groups   = ["system:masters"]
    },
    {
      userarn  = "arn:aws:iam::009946608368:user/DOHYUNG2"
      username = "DOHYUNG2"
      groups   = ["system:masters"]
    },
    {
      userarn  = "arn:aws:iam::009946608368:user/JUNYONG"
      username = "JUNYONG"
      groups   = ["system:masters"]
    },
  ]
  aws_auth_accounts = [
    "009946608368"
  ]

  # 클러스터 태그 설정
  tags = local.tags

    

     # Create a new cluster where both an identity provider and Fargate profile is created
  # will result in conflicts since only one can take place at a time
  # # OIDC Identity provider
  # cluster_identity_providers = {
  #   sts = {
  #     client_id = "sts.amazonaws.com"
  #   }
  # }
}

################################################################################
# Supporting resources
################################################################################
# 추가 보안 그룹 설정 - 클러스터와 관련된 추가적인 보안 정의
resource "aws_security_group" "additional" {
  name_prefix = "${local.name}-additional" 
  vpc_id      = aws_vpc.amz_mall_vpc.id    # 보안 그룹이 속할 VPC의 ID

  # SSH 접근을 위한 인그레스 규칙을 정의합니다.
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }

  tags = merge(local.tags, { Name = "${local.name}-additional" }) 
}

# 추가 IAM 정책 설정 - 클러스터 관리에 필요한 추가적인 IAM 정책을 정의
resource "aws_iam_policy" "additional" {
  name   = "${local.name}-additional"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Action   = ["ec2:Describe*"],
        Effect   = "Allow",
        Resource = "*"
      },
    ]
  })
}

# KMS 모듈 설정 - 클러스터 암호화에 사용될 KMS 키를 생성 및 관리
module "kms" { 
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 1.5"

  aliases               = ["amzdraw-eks/${local.name}"]
  description           = "${local.name} cluster encryption key"
  enable_default_policy = true
  key_owners            = [data.aws_caller_identity.current.arn]

  tags = local.tags
}