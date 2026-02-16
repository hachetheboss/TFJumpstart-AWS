/*
NIST 800-53 Controls Addressed in VPC Module Variables:
- AC-4: Information Flow Enforcement
- AC-17: Remote Access
- CM-2: Baseline Configuration
- CM-6: Configuration Settings
- SC-7: Boundary Protection
- SC-28: Protection of Information at Rest
- SI-4: System Monitoring
*/

variable "name" {
  description = "Name to be used on all resources as identifier. Must be alphanumeric with hyphens and less than 32 characters."
  type        = string
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9-]+", var.name)) && length(var.name) <= 32
    error_message = "Name must be alphanumeric with hyphens and less than 32 characters."
  }
}

variable "environment" {
  description = "The environment (e.g., dev, staging, prod). Used for resource tagging and environment-specific configurations."
  type        = string
  default     = "prod"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "cidr" {
  description = "The CIDR block for the VPC. Must be a valid RFC 1918 private address range."
  type        = string
  
  validation {
    condition     = can(regex("^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.)\\d{1,3}\\.\\d{1,3}/\\d{1,2}$", var.cidr))
    error_message = "CIDR must be a valid RFC 1918 private address range."
  }
}

variable "vpc_cidr" {
  description = "The CIDR block for the VPC. Used for network ACL rules. Must be a valid CIDR block."
  type        = string
  
  validation {
    condition     = can(regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", var.vpc_cidr))
    error_message = "VPC CIDR must be a valid CIDR block (e.g., 10.0.0.0/16)."
  }
}

variable "azs" {
  description = "A list of availability zones in the region. Must specify at least 2 AZs for high availability."
  type        = list(string)
  default     = []
  
  validation {
    condition     = length(var.azs) >= 2 || length(var.azs) == 0
    error_message = "At least 2 availability zones must be specified for high availability."
  }
}

variable "public_subnets" {
  description = "A list of public subnets inside the VPC. Must be within the VPC CIDR range."
  type        = list(string)
  default     = []
  
  validation {
    condition     = alltrue([for s in var.public_subnets : can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$", s))])
    error_message = "Public subnets must be valid CIDR blocks."
  }
}

variable "private_subnets" {
  description = "A list of private subnets inside the VPC. Must be within the VPC CIDR range and not overlap with public subnets."
  type        = list(string)
  default     = []
  
  validation {
    condition     = alltrue([for s in var.private_subnets : can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$", s))])
    error_message = "Private subnets must be valid CIDR blocks."
  }
}

variable "enable_nat_gateway" {
  description = "Should be true if you want to provision NAT Gateways for your private subnets. (NIST 800-53: AC-4, SC-7)"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Should be true if you want to provision a single shared NAT Gateway across all private subnets. (NIST 800-53: CP-10, SC-7)"
  type        = bool
  default     = false
}

variable "data_classification" {
  description = "Data classification level (e.g., public, internal, confidential, restricted). Used for resource tagging and access control. (NIST 800-53: AC-4, MP-4, SC-28)"
  type        = string
  default     = "confidential"
  
  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
  }
}

variable "owner_contact" {
  description = "Email address of the resource owner or team. Used for operational notifications and incident response. (NIST 800-53: PM-9, IR-4)"
  type        = string
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.owner_contact))
    error_message = "Owner contact must be a valid email address."
  }
}

variable "cost_center" {
  description = "Cost center for resource allocation and tracking. (NIST 800-53: PM-5)"
  type        = string
  default     = ""
}

variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs for monitoring network traffic. (NIST 800-53: AU-2, AU-6, AU-12, SI-4)"
  type        = bool
  default     = true
}

variable "flow_log_retention_days" {
  description = "Number of days to retain VPC Flow Logs. (NIST 800-53: AU-11)"
  type        = number
  default     = 365
  
  validation {
    condition     = var.flow_log_retention_days >= 90 && var.flow_log_retention_days <= 2557
    error_message = "Flow log retention must be between 90 and 2557 days."
  }
}

variable "enable_dns_hostnames" {
  description = "Enable DNS hostnames in the VPC. (NIST 800-53: CM-6, SC-7)"
  type        = bool
  default     = true
}

variable "enable_dns_support" {
  description = "Enable DNS resolution in the VPC. (NIST 800-53: CM-6, SC-7)"
  type        = bool
  default     = true
}

variable "tags" {
  description = "A map of tags to add to all resources. Used for resource management, cost allocation, and security automation. (NIST 800-53: CM-2, CM-8, PM-5)"
  type        = map(string)
  default     = {}
  
  validation {
    condition     = alltrue([for k, v in var.tags : can(regex("^[\\.\\-a-zA-Z0-9_/+=:\\s]+$", v))])
    error_message = "Tags can only contain alphanumeric characters, spaces, and the following: ._-:/=+@"
  }
}

variable "enable_default_security_group_deny_all" {
  description = "Update the default security group to deny all traffic by default. (NIST 800-53: AC-4, SC-7)"
  type        = bool
  default     = true
}

variable "enable_network_acl" {
  description = "Enable custom Network ACLs for the VPC. (NIST 800-53: AC-4, SC-7)"
  type        = bool
  default     = true
}

variable "enable_vpc_flow_logs_to_cloudwatch" {
  description = "Enable VPC Flow Logs to CloudWatch Logs. (NIST 800-53: AU-2, AU-6, AU-12, SI-4)"
  type        = bool
  default     = true
}

variable "vpc_flow_logs_iam_role_arn" {
  description = "The ARN of the IAM role that will be used for VPC Flow Logs. Required if enable_vpc_flow_logs_to_cloudwatch is true. (NIST 800-53: AC-3, IA-2, IA-5)"
  type        = string
  default     = ""
  
  validation {
    condition     = var.vpc_flow_logs_iam_role_arn == "" || can(regex("^arn:aws:iam::[0-9]+:role/[a-zA-Z0-9+=,.@_-]+$", var.vpc_flow_logs_iam_role_arn))
    error_message = "VPC Flow Logs IAM role ARN must be a valid IAM role ARN or empty string."
  }
}

variable "enable_flow_log_encryption" {
  description = "Enable encryption for VPC Flow Logs. (NIST 800-53: SC-12, SC-13, SC-28)"
  type        = bool
  default     = true
}

variable "flow_log_kms_key_arn" {
  description = "The ARN of the KMS key to use for encrypting VPC Flow Logs. If not provided, the default AWS managed key will be used. (NIST 800-53: SC-12, SC-13, SC-28)"
  type        = string
  default     = ""
  
  validation {
    condition     = var.flow_log_kms_key_arn == "" || can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]+:key/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", var.flow_log_kms_key_arn))
    error_message = "Flow Log KMS key ARN must be a valid KMS key ARN or empty string."
  }
}
