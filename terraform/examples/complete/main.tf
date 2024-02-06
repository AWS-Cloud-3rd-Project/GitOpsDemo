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
  source_dest_check           = false

  tags = {
    Name = "NAT-Instance"
  }
}
# NAT Instance 2
resource "aws_instance" "nat_instance_2" {
  ami           = "ami-08074b02473276b92"
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.public_subnet_2.id
  security_groups = [aws_security_group.nat_instance_sg.id]

  associate_public_ip_address = true
  source_dest_check           = false

  tags = {
    Name = "NAT-Instance-2"
  }
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

# resource "aws_route" "private_rt_nat_gw_1" {
#   route_table_id         = aws_route_table.private_rt.id
#   destination_cidr_block = "0.0.0.0/0"
#   nat_gateway_id         = aws_nat_gateway.nat_gw_1.id
# }

resource "aws_route_table_association" "private_subnet_1_association" {
  subnet_id      = aws_subnet.private_subnet_1.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_subnet_2_association" {
  subnet_id      = aws_subnet.private_subnet_2.id
  route_table_id = aws_route_table.private_rt.id
}

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
################################################################################
# RDS DataBase
################################################################################

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


################################################################################
# Cognito User Pool
################################################################################

# Cognito 사용자 풀을 생성합니다.
resource "aws_cognito_user_pool" "themzmall_user_pool" {

  # 사용자 풀의 이름을 지정합니다.
  name = "themzmall_user_pool"

  # 비밀번호 정책을 설정합니다.
  password_policy {

    # 비밀번호의 최소 길이를 지정합니다.
    minimum_length    = 5

    # 비밀번호에 소문자가 적어도 하나 이상 포함
    require_lowercase = true

    # 비밀번호에 숫자가 적어도 하나 이상 포함
    require_numbers   = false

    # 비밀번호에 기호가 적어도 하나 이상 포함
    require_symbols   = false

    # 비밀번호에 대문자가 적어도 하나 이상 포함
    require_uppercase = false
  }

  # 사용자 풀 스키마를 정의
  schema {

    # 스키마의 속성 유형을 지정 - 문자열(String)
    attribute_data_type = "String"

    # 속성 이름을 지정 - 'email'
    name = "email"

    # 해당 속성이 필수인지 여부를 지정
    required = true

    # 개발자 전용 속성인지 여부를 지정
    developer_only_attribute = false

    # 문자열 속성 제약 조건을 지정합니다.
    string_attribute_constraints {

      # 최소 길이를 지정합니다.
      min_length = 5

      # 최대 길이를 지정합니다.
      max_length = 256
    }
  }

  # 자동으로 검증할 속성을 지정 - 'email'을 사용하여 자동으로 이메일을 검증
  auto_verified_attributes = ["email"]
}

################################################################################
# Cognito User Pool Client
################################################################################

# Cognito 사용자 풀 클라이언트를 생성
resource "aws_cognito_user_pool_client" "themzmall_user_pool_client" {

  # 클라이언트 이름
  name = "themzmall_app_client"

  # 해당 클라이언트가 속할 사용자 풀 ID를 지정
  user_pool_id = aws_cognito_user_pool.themzmall_user_pool.id # 사용자 풀 리소스 ID로 변경
  
  # 클라이언트 비밀을 생성할지 여부 지정. 
  generate_secret = true
  
  # 허용된 OAuth 플로우 지정. 'code'와 'implicit'를 사용할 수 있다
  allowed_oauth_flows = ["code", "implicit"]
  
  # 사용자 풀 클라이언트에서 OAuth 플로우를 사용할 수 있게 할지 여부 지정
  allowed_oauth_flows_user_pool_client = true
  
  # 허용된 OAuth 스코프를 지정합니다. 여기서는 'email'과 'openid'를 허합니다.
  allowed_oauth_scopes = ["email", "openid"]
  
  # 콜백 URL을 지정, 인증 후 사용자가 리디렉션될 URL 설정
  callback_urls = ["https://www.example.com/callback"]
  
  # 로그아웃 URL을 지정, 사용자가 로그아웃할 때 리디렉션될 URL 설정
  logout_urls = ["https://www.example.com/signout"]
}

################################################################################
# Cognito User Pool Domain
################################################################################

# Cognito 사용자 풀 도메인 생성
resource "aws_cognito_user_pool_domain" "themzmall_user_pool_domain" {
  domain       = "themzmall_user_pool" # Cognito 사용자 풀 도메인 이름 설정
  certificate_arn = aws_acm_certificate.cert.arn
  user_pool_id = aws_cognito_user_pool.amz_mall_user_pool.id # 연결할 사용자 풀 ID 설정
}

################################################################################
# Cognito Google OAuth
################################################################################

# AWS Cognito에서 Google을 ID 공급자로 설정하는 Terraform 리소스 정의
resource "aws_cognito_identity_provider" "google" {

  # Cognito 사용자 풀 ID를 지정, Google ID 공급자를 연결할 풀
  user_pool_id  = aws_cognito_user_pool.amz_mall_user_pool.id
  
  # 공급자 이름으로 'Google'설정
  provider_name = "Google"
  
  # 공급자 유형으로 'Google'을 설정합니다. Cognito가 어떤 종류의 공급자인지 인식하는 데 사용
  provider_type = "Google"

  # 공급자 세부 정보를 제공, Google에서 받은 클라이언트 ID와 비밀번호
  provider_details = {
    client_id     = "GOOGLE_CLIENT_ID"       # Google에서 생성한 OAuth 2.0 클라이언트 ID
    client_secret = "GOOGLE_CLIENT_SECRET"   # Google에서 생성한 OAuth 2.0 클라이언트 비밀번호
    authorize_scopes = "profile email openid" # OAuth 스코프: 사용자의 기본 프로필 정보와 이메일 주소, 그리고 OpenID 요청
  }

  # 사용자의 Google 프로필에서 어떤 속성을 Cognito 사용자 프로필의 어떤 필드로 매핑할지 정의합니다.
  attribute_mapping = {
    email = "email"           # Google의 이메일을 Cognito의 이메일 속성으로 매핑
    name  = "name"            # Google의 이름을 Cognito의 이름 속성으로 매핑
    given_name = "given_name" # Google의 주어진 이름(First name)을 Cognito의 주어진 이름 속성으로 매핑
    family_name = "family_name" # Google의 성(Family name)을 Cognito의 성 속성으로 매핑
    picture = "picture"       # Google의 프로필 사진을 Cognito의 사진 속성으로 매핑
  }
}

################################################################################
# Route53
################################################################################
# Route 53 호스팅 영역 생성
# resource "aws_route53_zone" "themzmall" {
#   name = "themzmall.shop" # 호스팅할 도메인 이름
# }

# # A 레코드 - 도메인을 IP 주소로 연결
# resource "aws_route53_record" "a_record" {
#   zone_id = aws_route53_zone.themzmall.id  # 위에서 생성한 호스팅 영역 ID
#   name    = "themzmall.shop"                 # 레코드에 대한 도메인 이름
#   type    = "A"                              # 레코드 타입 A
#   ttl     = "300"                            # 레코드의 Time To Live
#   records = ["192.0.2.1"]                    # IP 주소
# }

# # CNAME 레코드 - www를 theamzmall.shop 도메인으로 연결
# resource "aws_route53_record" "cname_record" {
#   zone_id = aws_route53_zone.example.zone_id # 호스팅 영역 ID
#   name    = "www.theamzmall.shop"            # CNAME 레코드에 대한 도메인 이름
#   type    = "CNAME"                          # 레코드 타입 CNAME
#   ttl     = "300"                            # Time To Live
#   records = ["theamzmall.shop"]              # CNAME의 대상 도메인
# }
