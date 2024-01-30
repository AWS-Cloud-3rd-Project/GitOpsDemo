variable "cluster_name" {
  description = "The name of the EKS cluster"
  default     = "ECOMMERCE-PROD-CLUSTER-SEOUL-EKS"
}

variable "cluster_version" {
  description = "Kubernetes version for the EKS cluster"
  default     = "1.28"
}