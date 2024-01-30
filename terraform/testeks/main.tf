module "eks" {
  source = "terraform-aws-modules/eks/aws" # Terraform AWS EKS 모듈을 사용합니다.
  version = "19.16.0" # 모듈의 버전을 19.16.0으로 지정합니다.

#   cluster_name = ECOMMERCE-CLUSTER-PROD-SEOUL-EKS
#   cluster_version = "1.28"
  cluster_endpoint_public_access = true # 클러스터 API 서버에 대한 공개 인터넷 접근을 활성화합니다.

  # 클러스터 애드온을 정의합니다. 애드온은 클러스터의 기능을 확장하는 구성 요소입니다.
  cluster_addons = {
    kube-proxy = {
      # kube-proxy 애드온의 버전을 지정합니다. 
      addon_version = "v1.28.2-eksbuild.2"
      configuration_values = jsonencode({
        resources = {
          limits = {
            cpu = "100m" # CPU 사용 한도를 100m(밀리코어)로 설정합니다.
            memory = "128M" # 메모리 사용 한도를 128MB로 설정합니다.
          }
          requests = {
            cpu = "50m" # CPU 요청을 50m(밀리코어)로 설정합니다.
            memory = "64M" # 메모리 요청을 64MB로 설정합니다.
          }
        }
      })
    }
    vpc-cni = {
      # vpc-cni 애드온의 버전을 지정합니다. 이 애드온은 클러스터의 네트워킹을 담당합니다.
      addon_version = "v1.15.4-eksbuild.1"
      configuration_values = jsonencode({
        resources = {
          limits = {
            cpu = "0.5" # CPU 사용 한도를 0.5코어로 설정합니다.
            memory = "512M" # 메모리 사용 한도를 512MB로 설정합니다.
          }
          requests = {
            cpu = "0.05" # CPU 요청을 0.05코어로 설정합니다.
            memory = "64M" # 메모리 요청을 64MB로 설정합니다.
          }
        }
      })
    }
    coredns = {
      # coredns 애드온의 버전을 지정합니다. 이 애드온은 클러스터 내 DNS 서비스를 관리합니다.
      addon_version = "v1.10.1-eksbuild.6"
      configuration_values = jsonencode({
        computeType = "Fargate" # Fargate에서 실행될 때의 계산 유형을 설정합니다.
        resources = {
          limits = {
            cpu = "0.25" # CPU 사용 한도를 0.25코어로 설정합니다.
            memory = "256M" # 메모리 사용 한도를 256MB로 설정합니다.
          }
          requests = {
            cpu = "0.25" # CPU 요청을 0.25코어로 설정합니다.
            memory = "256M" # 메모리 요청을 256MB로 설정합니다.
          }
        }
      })
    }
    aws-ebs-csi-driver = {
      # AWS EBS CSI 드라이버 애드온의 버전을 지정합니다. 이 드라이버는 EKS 클러스터에서 EBS 볼륨을 관리합니다.
      addon_version = "v1.25.0-eksbuild.1"
      service_account_role_arn = module.ebs_csi_irsa_role.iam_role_arn # CSI 드라이버가 사용할 IAM 역할의 ARN을 지정합니다.
    }
  }

  vpc_id = module.vpc.vpc_id # 클러스터가 사용할 VPC ID를 지정합니다.
  subnet_ids = module.vpc.private_subnets # 클러스터에 할당할 프라이빗 서브넷 ID를 지정합니다.
#   db_subnet_ids = module.vpc.db_subnets # DB에 사용할 서브넷 ID를 지정합니다.

  # Fargate 프로파일은 클러스터의 기본 보안 그룹을 사용하므로 기본 및 노드 그룹 보안 그룹 생성을 비활성화합니다.
  create_cluster_security_group = false
  create_node_security_group = false

  manage_aws_auth_configmap = true # aws-auth ConfigMap을 관리합니다. 이 ConfigMap은 클러스터와 통신할 수 있는 IAM 역할 및 사용자를 정의합니다.
  aws_auth_roles = [
    # 관리자 역할을 수행할 수 있는 사용자를 허용합니다.
    {
      rolearn = aws_iam_role.eks_admin.arn
    #   username = local.eks_admin_username
      groups = [
        "system:masters" # 관리자 그룹에 사용자를 추가합니다.
      ]
    },
    # Karpenter가 시작한 노드에 대한 IAM 역할을 추가합니다. Karpenter는 클러스터 내에서 노드를 자동으로 스케일링하는 서비스입니다.
    {
      rolearn = module.karpenter.role_arn
      username = "system:node:{{EC2PrivateDNSName}}"
      groups = [
        "system:bootstrappers", # 노드 시작에 필요한 권한을 부여합니다.
        "system:nodes", # 노드 관리에 필요한 권한을 부여합니다.
      ]
    },
  ]

  # KMS 관리를 위해 루트 계정에 권한을 부여합니다.
  kms_key_enable_default_policy = true

#   tags = merge(local.tags, {
#     # Karpenter가 사용할 보안 그룹을 식별하기 위해 필요한 태그를 설정합니다. 
#     "karpenter.sh/discovery" = local.name
#   })
}
