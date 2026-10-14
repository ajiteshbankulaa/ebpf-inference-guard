data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(
    data.aws_availability_zones.available.names,
    0,
    2
  )
}

# Virtual Private Cloud
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "6.7.2"

  name = "ebpf-shield-vpc"
  cidr = "10.0.0.0/16"

  azs = local.azs

  public_subnets = [
    "10.0.101.0/24",
    "10.0.102.0/24"
  ]

  private_subnets = [
    "10.0.1.0/24",
    "10.0.2.0/24"
  ]

  enable_dns_support   = true
  enable_dns_hostnames = true

  enable_nat_gateway = true
  single_nat_gateway = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# Managed Kubernetes cluster
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "21.26.0"

  name               = "ebpf-shield"
  kubernetes_version = "1.36"

  endpoint_public_access       = true
  endpoint_private_access      = true
  endpoint_public_access_cidrs = [var.admin_cidr]

  enable_cluster_creator_admin_permissions = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  addons = {
    coredns    = {}
    kube-proxy = {}

    vpc-cni = {
      before_compute = true
    }

    eks-pod-identity-agent = {
      before_compute = true
    }
  }

  eks_managed_node_groups = {
    shield = {
      ami_type = "AL2023_x86_64_STANDARD"

      instance_types = ["c7i.large"]

      min_size     = 1
      desired_size = 1
      max_size     = 2

      disk_size = 30

      iam_role_additional_policies = {
        SSM = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      }
    }
  }
}

# Container registry for XDP Shield
resource "aws_ecr_repository" "shield" {
  name                 = "ebpf-shield"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

# Registry for protected test application
resource "aws_ecr_repository" "echo" {
  name                 = "ebpf-shield-echo"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}
