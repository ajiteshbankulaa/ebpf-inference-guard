output "cluster_name" {
  value = module.eks.cluster_name
}

output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "shield_ecr_url" {
  value = aws_ecr_repository.shield.repository_url
}

output "echo_ecr_url" {
  value = aws_ecr_repository.echo.repository_url
}
