variable "admin_cidr" {
  description = "Public IPv4 CIDR allowed to access the EKS API"
  type        = string

  validation {
    condition     = can(cidrnetmask(var.admin_cidr)) && var.admin_cidr != "0.0.0.0/0"
    error_message = "admin_cidr must be a valid, restricted IPv4 CIDR; do not expose the EKS API to 0.0.0.0/0."
  }
}
