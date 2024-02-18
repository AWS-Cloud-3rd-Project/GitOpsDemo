################################################################################
# Cluster
################################################################################
output "cluster_arn" {
  description = "The Amazon Resource Name (ARN) of the cluster"
  value       = module.eks.cluster_arn
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = module.eks.cluster_certificate_authority_data
}

output "cluster_endpoint" {
  description = "Endpoint for your Kubernetes API server"
  value       = module.eks.cluster_endpoint
}

output "cluster_id" {
  description = "The ID of the EKS cluster. Note: currently a value is returned only for local EKS clusters created on Outposts"
  value       = module.eks.cluster_id
}

output "cluster_name" {
  description = "The name of the EKS cluster"
  value       = module.eks.cluster_name
}

output "cluster_oidc_issuer_url" {
  description = "The URL on the EKS cluster for the OpenID Connect identity provider"
  value       = module.eks.cluster_oidc_issuer_url
}

output "cluster_platform_version" {
  description = "Platform version for the cluster"
  value       = module.eks.cluster_platform_version
}

output "cluster_status" {
  description = "Status of the EKS cluster. One of `CREATING`, `ACTIVE`, `DELETING`, `FAILED`"
  value       = module.eks.cluster_status
}

output "cluster_security_group_id" {
  description = "Cluster security group that was created by Amazon EKS for the cluster. Managed node groups use this security group for control-plane-to-data-plane communication. Referred to as 'Cluster security group' in the EKS console"
  value       = module.eks.cluster_security_group_id
}

################################################################################
# KMS Key
################################################################################

output "kms_key_arn" {
  description = "The Amazon Resource Name (ARN) of the key"
  value       = module.eks.kms_key_arn
}

output "kms_key_id" {
  description = "The globally unique identifier for the key"
  value       = module.eks.kms_key_id
}

output "kms_key_policy" {
  description = "The IAM resource policy set on the key"
  value       = module.eks.kms_key_policy
}

################################################################################
# Security Group
################################################################################

output "cluster_security_group_arn" {
  description = "Amazon Resource Name (ARN) of the cluster security group"
  value       = module.eks.cluster_security_group_arn
}

################################################################################
# IRSA
################################################################################

output "oidc_provider" {
  description = "The OpenID Connect identity provider (issuer URL without leading `https://`)"
  value       = module.eks.oidc_provider
}

output "oidc_provider_arn" {
  description = "The ARN of the OIDC Provider if `enable_irsa = true`"
  value       = module.eks.oidc_provider_arn
}

output "cluster_tls_certificate_sha1_fingerprint" {
  description = "The SHA1 fingerprint of the public key of the cluster's certificate"
  value       = module.eks.cluster_tls_certificate_sha1_fingerprint
}

################################################################################
# IAM Role
################################################################################

output "cluster_iam_role_name" {
  description = "IAM role name of the EKS cluster"
  value       = module.eks.cluster_iam_role_name
}

output "cluster_iam_role_arn" {
  description = "IAM role ARN of the EKS cluster"
  value       = module.eks.cluster_iam_role_arn
}

output "cluster_iam_role_unique_id" {
  description = "Stable and unique string identifying the IAM role"
  value       = module.eks.cluster_iam_role_unique_id
}

################################################################################
# EKS Addons
################################################################################
output "cluster_addons" {
  description = "Map of attribute maps for all EKS cluster addons enabled"
  value       = module.eks.cluster_addons
}

# output "cluster_addons_coredns" {
#   description = "Map of attribute maps for all EKS cluster addons enabled"
#   value       = aws_eks_addon.coredns
# }
# output "cluster_addons_kube_proxy" {
#   description = "Map of attribute maps for all EKS cluster addons enabled"
#   value       = aws_eks_addon.kube_proxy
# }
# output "cluster_addons_vpc_cni" {
#   description = "Map of attribute maps for all EKS cluster addons enabled"
#   value       = aws_eks_addon.vpc_cni
# }
# output "cluster_addons_pod_identity_webhook" {
#   description = "Map of attribute maps for all EKS cluster addons enabled"
#   value       = aws_eks_addon.pod_identity_webhook
# }
################################################################################
# EKS Identity Provider
################################################################################

# output "cluster_identity_providers" {
#   value = aws_eks_cluster.eks_cluster.identity_providers
# }
output "cluster_identity_providers" {
  description = "Map of attribute maps for all EKS identity providers enabled"
  value       = module.eks.cluster_identity_providers
}

################################################################################
# CloudWatch Log Group
################################################################################

output "cloudwatch_log_group_name" {
  description = "Name of cloudwatch log group created"
  value       = module.eks.cloudwatch_log_group_name
}

output "cloudwatch_log_group_arn" {
  description = "Arn of cloudwatch log group created"
  value       = module.eks.cloudwatch_log_group_arn
}

################################################################################
# EKS Managed Node Group
################################################################################
output "eks_managed_node_groups" {
  description = "Map of attribute maps for all EKS managed node groups created"
  value       = module.eks.eks_managed_node_groups
}

output "eks_managed_node_groups_autoscaling_group_names" {
  description = "List of the autoscaling group names created by EKS managed node groups"
  value       = module.eks.eks_managed_node_groups_autoscaling_group_names
}

# output "eks_managed_node_groups" {
#   value = {
#     for ng in aws_eks_node_group.service_node_group, aws_eks_node_group.eco_system_node_group :
#     ng.node_group_name => ng.id
#   }
# }

# output "eks_managed_node_groups_autoscaling_group_names" {
#   value = {
#     for ng in aws_eks_node_group.service_node_group, aws_eks_node_group.eco_system_node_group :
#     ng.node_group_name => ng.resources[0].autoscaling_groups[0].name
#   }
# }

################################################################################
# Additional
################################################################################
output "aws_auth_configmap_yaml" {
  description = "Formatted yaml output for base aws-auth configmap containing roles used in cluster node groups/fargate profiles"
  value       = module.eks.aws_auth_configmap_yaml
}

# output "aws_auth_configmap_yaml" {
#   value = kubernetes_config_map.aws_auth.data["mapRoles"]
# }


# output "rds_subnet_1_id" {
#   value = aws_subnet.rds_subnet_1.id
#   description = "The ID of the first RDS subnet"
# }

# output "rds_subnet_2_id" {
#   value = aws_subnet.rds_subnet_2.id
#   description = "The ID of the second RDS subnet"
# }

# output "db_subnet_group_name" {
#   value = aws_db_subnet_group.rds_subnet_group.name
#   description = "The name of the DB subnet group"
# }

# output "rds_instance_endpoint" {
#   value = aws_db_instance.default.endpoint
#   description = "The endpoint of the RDS instance"
# }

# output "rds_instance_arn" {
#   value = aws_db_instance.default.arn
#   description = "The ARN of the RDS instance"
# }