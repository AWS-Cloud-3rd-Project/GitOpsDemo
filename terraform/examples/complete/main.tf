provider "aws" {
  region = local.region
}

# data "aws_eks_cluster" "cluster" {
#   name = aws_eks_cluster.eks_cluster.name
# }

# data "aws_eks_cluster_auth" "cluster" {
#   name = aws_eks_cluster.eks_cluster.name
# }

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
  # host                   = data.aws_eks_cluster.cluster.endpoint
  # cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  # token                  = data.aws_eks_cluster_auth.cluster.token
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
    # host                   = data.aws_eks_cluster.cluster.endpoint
    # cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
    # token                  = data.aws_eks_cluster_auth.cluster.token
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
  # depends_on = [aws_eks_cluster.eks_cluster]
  # namespace  = "kube-system"
  # name       = "metrics-server"
  # chart      = "metrics-server"
  # version    = "3.11.0"
  # repository = "https://kubernetes-sigs.github.io/metrics-server/"
  # set {
  #   name  = "replicas"
  #   value = "1"
  # }

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

resource "aws_vpc" "amz_mall_vpc" {
  cidr_block = local.vpc_cidr
  enable_dns_support = true
  enable_dns_hostnames = true
  tags = {
    Name = local.name
  }
}

resource "aws_subnet" "public_subnet_1" {
  vpc_id            = aws_vpc.amz_mall_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = local.azs[0]
  map_public_ip_on_launch = true
  tags = {
    Name = "${local.name}_public_subnet_1"
  }
}

resource "aws_subnet" "public_subnet_2" {
  vpc_id            = aws_vpc.amz_mall_vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = local.azs[1]
  map_public_ip_on_launch = true
  tags = {
    Name = "${local.name}_public_subnet_2"
  }
}

resource "aws_subnet" "private_subnet_1" {
  vpc_id            = aws_vpc.amz_mall_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = local.azs[0]
  map_public_ip_on_launch = false
  tags = {
    Name = "${local.name}_private_subnet_1"
  }
}

resource "aws_subnet" "private_subnet_2" {
  vpc_id            = aws_vpc.amz_mall_vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = local.azs[1]
  map_public_ip_on_launch = false
  tags = {
    Name = "${local.name}_private_subnet_2"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.amz_mall_vpc.id
  tags = {
    Name = "${local.name}_igw"
  }
}

################################################################################
# NAT Instance
################################################################################

# SG - NAT Instance
resource "aws_security_group" "nat_instance_sg" {
  name        = "nat-instance-sg"
  description = "Security group for NAT instance"
  vpc_id      = aws_vpc.amz_mall_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "nat-instance-sg"
  }
}

# NAT Instance 1
resource "aws_instance" "nat_instance_1" {
  ami           = "ami-08074b02473276b92"
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.public_subnet_1.id # 첫 번째 퍼블릭 서브넷의 ID
  security_groups = [aws_security_group.nat_instance_sg.id]

  associate_public_ip_address = true
  source_dest_check = false

  tags = {
    Name = "NAT-Instance"
  }
}
resource "aws_eip" "nat_eip" {
  domain = "vpc"
}
resource "aws_eip_association" "eip_assoc" {
  instance_id   = aws_instance.nat_instance_1.id
  allocation_id = aws_eip.nat_eip.id
}

# NAT Instance 2
resource "aws_instance" "nat_instance_2" {
  ami           = "ami-08074b02473276b92"
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.public_subnet_2.id
  security_groups = [aws_security_group.nat_instance_sg.id]

  associate_public_ip_address = true
  source_dest_check = false

  tags = {
    Name = "NAT-Instance-2"
  }
}
resource "aws_eip" "nat_eip_2" {
  domain = "vpc"
}
resource "aws_eip_association" "eip_assoc2" {
  instance_id   = aws_instance.nat_instance_2.id
  allocation_id = aws_eip.nat_eip_2.id
}

################################################################################
# NAT GateWay
################################################################################


# resource "aws_eip" "nat_eip_1" {
#   domain = "vpc"
#   depends_on = [aws_internet_gateway.igw]
# }

# resource "aws_nat_gateway" "nat_gw_1" {
#   allocation_id = aws_eip.nat_eip_1.id
#   subnet_id     = aws_subnet.public_subnet_1.id
#   tags = {
#     Name = "${local.name}_nat_gw_1"
#   }
# }

# resource "aws_eip" "nat_eip_2" {
#   domain = "vpc"
#   depends_on = [aws_internet_gateway.igw]
# }

# resource "aws_nat_gateway" "nat_gw_2" {
#   allocation_id = aws_eip.nat_eip_2.id
#   subnet_id     = aws_subnet.public_subnet_2.id
#   tags = {
#     Name = "${local.name}_nat_gw_2"
#   }
# }


################################################################################
# public route table
################################################################################

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.amz_mall_vpc.id
  tags = {
    Name = "${local.name}_public_rt"
  }
}

resource "aws_route" "public_rt_igw" {
  route_table_id         = aws_route_table.public_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public_subnet_1_association" {
  subnet_id      = aws_subnet.public_subnet_1.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_subnet_2_association" {
  subnet_id      = aws_subnet.public_subnet_2.id
  route_table_id = aws_route_table.public_rt.id
}

################################################################################
# private route table
################################################################################

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.amz_mall_vpc.id
  tags = {
    Name = "${local.name}_private_rt"
  }
}
resource "aws_route_table_association" "private_subnet_1_association" {
  subnet_id      = aws_subnet.private_subnet_1.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_subnet_2_association" {
  subnet_id      = aws_subnet.private_subnet_2.id
  route_table_id = aws_route_table.private_rt.id
}
################################################################################
# private route table - NAT Instance
################################################################################
resource "aws_route" "private_to_nat" {
  route_table_id         = aws_route_table.private_rt.id
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id = data.aws_network_interface.nat_instance_1_ni.id
}

data "aws_network_interface" "nat_instance_1_ni" {
  filter {
    name   = "attachment.instance-id"
    values = [aws_instance.nat_instance_1.id]
  }
}
################################################################################
# private route table - NAT GW
################################################################################
# resource "aws_route" "private_rt_nat_gw_1" {
#   route_table_id         = aws_route_table.private_rt.id
#   destination_cidr_block = "0.0.0.0/0"
#   nat_gateway_id         = aws_nat_gateway.nat_gw_1.id
# }

# resource "aws_route_table_association" "private_subnet_1_association" {
#   subnet_id      = aws_subnet.private_subnet_1.id
#   route_table_id = aws_route_table.private_rt.id
# }

# resource "aws_route_table_association" "private_subnet_2_association" {
#   subnet_id      = aws_subnet.private_subnet_2.id
#   route_table_id = aws_route_table.private_rt.id
# }


################################################################################
# RDS DataBase
################################################################################


resource "aws_subnet" "rds_subnet_1" {
  vpc_id            = aws_vpc.amz_mall_vpc.id
  cidr_block        = "10.0.100.0/24"  # Start from a higher range
  availability_zone = local.azs[0]
  tags = {
    Name = "${local.name}-rds-1"
  }
}

resource "aws_subnet" "rds_subnet_2" {
  vpc_id            = aws_vpc.amz_mall_vpc.id
  cidr_block        = "10.0.101.0/24"  # Ensure there's no overlap
  availability_zone = local.azs[1]
  tags = {
    Name = "${local.name}-rds-2"
  }
}


# DB 서브넷 그룹 생성
resource "aws_db_subnet_group" "rds_subnet_group" {
  name        = "ecommerce-seoul-mariadb-subnet-group"
  subnet_ids  = [aws_subnet.rds_subnet_1.id, aws_subnet.rds_subnet_2.id]
  tags = {
    Name = "My_DB_Subnet_Group"
  }
}

resource "aws_route_table_association" "rds_subnet_1_association" {
  subnet_id      = aws_subnet.rds_subnet_1.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "rds_subnet_2_association" {
  subnet_id      = aws_subnet.rds_subnet_2.id
  route_table_id = aws_route_table.private_rt.id
}

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

################################################################################
# EKS Module
################################################################################

module "eks" {
  source = "../.."
  cluster_version = "1.28"
  cluster_name                   = local.name
  cluster_endpoint_public_access = true

  cluster_addons = {
    coredns = {
      preserve    = true
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
  }
 
  # External encryption key
  create_kms_key = false
  cluster_encryption_config = {
    resources        = ["secrets"]
    provider_key_arn = module.kms.key_arn
  }

  iam_role_additional_policies = {
    additional = aws_iam_policy.additional.arn
  }

  vpc_id = aws_vpc.amz_mall_vpc.id 
  subnet_ids = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]     # module.vpc.private_subnets
  
  # Extend cluster security group rules
  cluster_security_group_additional_rules = {
    ingress_nodes_ephemeral_ports_tcp = {
      description                = "Nodes on ephemeral ports"
      protocol                   = "tcp"
      from_port                  = 1025
      to_port                    = 65535
      type                       = "ingress"
      source_node_security_group = true
    }
    # Test: https://github.com/terraform-aws-modules/terraform-aws-eks/pull/2319
    ingress_source_security_group_id = {
      description              = "Ingress from another computed security group"
      protocol                 = "tcp"
      from_port                = 22
      to_port                  = 22
      type                     = "ingress"
      source_security_group_id = aws_security_group.additional.id
    }
  }

  # Extend node-to-node security group rules
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
    # Test: https://github.com/terraform-aws-modules/terraform-aws-eks/pull/2319
    ingress_source_security_group_id = {
      description              = "Ingress from another computed security group"
      protocol                 = "tcp"
      from_port                = 22
      to_port                  = 22
      type                     = "ingress"
      source_security_group_id = aws_security_group.additional.id
    }
  }
  eks_managed_node_groups = {
    service_node_group = {
      name = "service_node_group"
      iam_role_attach_cni_policy = true
      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND"

      min_size     = 2
      max_size     = 4
      desired_size = 2
      # local.azs에서 az의 인덱스를 사용하여 각 서브넷 ID에 접근 
      subnet_ids     = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id] # module.vpc.private_subnets[i]

      tags = {
        ExtraTag = "example"
      }
    }
    eco_system_node_group = {
      iam_role_attach_cni_policy = true
      name = "eco_system_node_group"

      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND"
      # local.azs에서 az의 인덱스를 사용하여 각 서브넷 ID에 접근
      subnet_ids     = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id] # [for i in range(length(local.azs)) : module.vpc.private_subnets[i]]

      min_size     = 1
      max_size     = 1
      desired_size = 1
      # local.azs에서 az의 인덱스를 사용하여 각 서브넷 ID에 접근

      tags = {
        ExtraTag = "example"
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
    #     ExtraTag = "example"
    #   }
    # }
  }

  # Create a new cluster where both an identity provider and Fargate profile is created
  # will result in conflicts since only one can take place at a time
  # # OIDC Identity provider
  # cluster_identity_providers = {
  #   sts = {
  #     client_id = "sts.amazonaws.com"
  #   }
  # }

  # aws-auth configmap
  manage_aws_auth_configmap = true


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

  tags = local.tags
}

################################################################################
# Supporting resources
################################################################################

resource "aws_security_group" "additional" {
  name_prefix = "${local.name}-additional"
  vpc_id      = aws_vpc.amz_mall_vpc.id # module.vpc.vpc_id

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
    ]
  }

  tags = merge(local.tags, { Name = "${local.name}-additional" })
}
# Bastion Host Security Group
resource "aws_security_group" "bastion" {
  name        = "SG-${local.name}-bastion"
  description = "SG_Bastion_Host"
  vpc_id      = aws_vpc.amz_mall_vpc.id # module.vpc.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # 혹은 보다 제한된 CIDR 블록을 사용하세요
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name}-bastion"
  }
}

# Bastion Host EC2 Instance
resource "aws_instance" "bastion" {
  ami           = "ami-0cfaf4bd9bad9f802" 
  instance_type = "t2.micro"

  associate_public_ip_address = true
  security_groups= [aws_security_group.bastion.id]

  subnet_id = aws_subnet.public_subnet_2.id
  tags = {
    Name = "bastion-${local.name}"
  }
}

resource "aws_iam_policy" "additional" {
  name = "${local.name}-additional"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

module "kms" { 
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 1.5"

  aliases               = ["amzdraw-eks/${local.name}"]
  description           = "${local.name} cluster encryption key"
  enable_default_policy = true
  key_owners            = [data.aws_caller_identity.current.arn]

  tags = local.tags
}


# ################################################################################
# # EKS Reousrces EKS 클러스터를 위한 IAM 역할과 정책
# ################################################################################
# resource "aws_iam_role" "eks_cluster_role" {
#   name = "eks_cluster_role"

#   assume_role_policy = jsonencode({
#     Version = "2012-10-17",
#     Statement = [
#       {
#         Effect = "Allow",
#         Principal = {
#           Service = "eks.amazonaws.com",
#         },
#         Action = "sts:AssumeRole",
#       },
#     ],
#   })
# }

# resource "aws_iam_role_policy_attachment" "eks_cluster_AmazonEKSClusterPolicy" {
#   role       = aws_iam_role.eks_cluster_role.id
#   policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
# }

# resource "aws_iam_role_policy_attachment" "eks_cluster_AmazonEKSServicePolicy" {
#   role       = aws_iam_role.eks_cluster_role.id
#   policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
# }


# ################################################################################
# # EKS Reousrces EKS 클러스터
# ################################################################################

# resource "aws_eks_cluster" "eks_cluster" {
#   name     = "amz_mall_dev_eks_cluster"
#   role_arn = aws_iam_role.eks_cluster_role.arn

#   version = "1.28"

#   vpc_config {
#     subnet_ids = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]
#     endpoint_public_access  = true
#   }

#   encryption_config {
#     provider {
#       key_arn = aws_kms_key.eks.arn
#     }
#     resources = ["secrets"]
#   }

#   depends_on = [
#     aws_iam_role_policy_attachment.eks_cluster_AmazonEKSClusterPolicy,
#     aws_iam_role_policy_attachment.eks_cluster_AmazonEKSServicePolicy,
#   ]
# }
# ################################################################################
# # EKS Reousrces EKS 노드 그룹
# ################################################################################

# resource "aws_iam_role" "eks_node_role" {
#   name = "eks_node_role"

#   assume_role_policy = jsonencode({
#     Version = "2012-10-17",
#     Statement = [
#       {
#         Effect = "Allow",
#         Principal = {
#           Service = "ec2.amazonaws.com",
#         },
#         Action = "sts:AssumeRole",
#       },
#     ],
#   })
# }

# resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
#   role       = aws_iam_role.eks_node_role.id
#   policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
# }

# resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
#   role       = aws_iam_role.eks_node_role.id
#   policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
# }
# ################################################################################
# # EKS Reousrces EKS 노드 그룹 리소스
# ################################################################################
# resource "aws_eks_node_group" "service_node_group" {
#   cluster_name    = aws_eks_cluster.eks_cluster.name
#   node_group_name = "service_node_group"
#   node_role_arn   = aws_iam_role.eks_node_role.arn
#   subnet_ids      = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]

#   scaling_config {
#     desired_size = 2
#     max_size     = 4
#     min_size     = 2
#   }

#   instance_types = ["t3.medium"]
# }

# resource "aws_eks_node_group" "eco_system_node_group" {
#   cluster_name    = aws_eks_cluster.eks_cluster.name
#   node_group_name = "eco_system_node_group"
#   node_role_arn   = aws_iam_role.eks_node_role.arn
#   subnet_ids      = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]

#   scaling_config {
#     desired_size = 1
#     max_size     = 1
#     min_size     = 1
#   }

#   instance_types = ["t3.medium"]
# }



# ################################################################################
# # AWS Auth ConfigMap 관리
# ################################################################################

# resource "kubernetes_config_map" "aws_auth" {
#   depends_on = [aws_eks_node_group.service_node_group, aws_eks_node_group.eco_system_node_group]
#   metadata {
#     name      = "aws-auth"
#     namespace = "kube-system"
#   }

#   data = {
#     mapRoles = yamlencode([
#       {
#         rolearn  = aws_iam_role.eks_node_role.arn
#         username = "system:node:{{EC2PrivateDNSName}}"
#         groups   = ["system:bootstrappers", "system:nodes"]
#       },
#       {
#         rolearn  = "arn:aws:iam::009946608368:role/AdditionalRole"
#         username = "additionalRole"
#         groups   = ["system:masters"]
#       }
#     ])
#     mapUsers = yamlencode([
#       {
#         userarn  = "arn:aws:iam::009946608368:user/DOHYUNG"
#         username = "DOHYUNG"
#         groups   = ["system:masters"]
#       },
#       {
#         userarn  = "arn:aws:iam::009946608368:user/DOHYUNG2"
#         username = "DOHYUNG2"
#         groups   = ["system:masters"]
#       },
#       {
#         userarn  = "arn:aws:iam::009946608368:user/JUNYONG"
#         username = "JUNYONG"
#         groups   = ["system:masters"]
#       }
#     ])
#   }
# }


# resource "aws_kms_key" "eks" {
#   description             = "KMS key for EKS encryption"
#   enable_key_rotation     = true
#   deletion_window_in_days = 10
# }

# resource "aws_security_group" "eks_cluster_sg" {
#   name        = "eks-cluster-sg"
#   description = "Security group for EKS cluster"
#   vpc_id      = aws_vpc.amz_mall_vpc.id

#   ingress {
#     from_port   = 1025
#     to_port     = 65535
#     protocol    = "tcp"
#     self        = true
#     description = "Nodes on ephemeral ports"
#   }

#   ingress {
#     from_port   = 22
#     to_port     = 22
#     protocol    = "tcp"
#     security_groups = [aws_security_group.additional.id]
#     description = "Ingress from another computed security group"
#   }

#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = ["0.0.0.0/0"]
#   }
# }
# resource "aws_eks_addon" "kube_proxy" {
#   cluster_name  = aws_eks_cluster.eks_cluster.name
#   addon_name    = "kube-proxy"
#   addon_version = "v1.28.4-minimal-eksbuild.1"
# }

# resource "aws_eks_addon" "coredns" {
#   cluster_name  = aws_eks_cluster.eks_cluster.name
#   addon_name    = "coredns"
#   addon_version = "v1.10.1-eksbuild.6"
# }


# resource "aws_eks_addon" "vpc_cni" {
#   cluster_name  = aws_eks_cluster.eks_cluster.name
#   addon_name    = "vpc-cni"
#   addon_version = "v1.16.0-eksbuild.1"
# }


# resource "aws_eks_addon" "pod_identity_webhook" {
#   cluster_name  = aws_eks_cluster.eks_cluster.name
#   addon_name    = "vpc-cni" 
#   addon_version = "v1.10.1-eksbuild.1" # 적절한 버전을 지정합니다.
# }