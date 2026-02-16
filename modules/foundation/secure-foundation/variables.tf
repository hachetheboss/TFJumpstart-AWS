/*
NIST 800-53 Controls Addressed:
- AC-2: Account Management
- AC-3: Access Enforcement
- AC-4: Information Flow Enforcement
- AC-6: Least Privilege
- AC-17: Remote Access
- AU-2: Audit Events
- AU-3: Content of Audit Records
- AU-6: Audit Review, Analysis, and Reporting
- AU-11: Audit Record Retention
- CA-2: Security Assessments
- CA-7: Continuous Monitoring
- CM-2: Baseline Configuration
- CM-6: Configuration Settings
- CP-9: Information System Backup
- IA-2: Identification and Authentication
- IA-5: Authenticator Management
- IR-4: Incident Handling
- RA-5: Vulnerability Scanning
- SC-7: Boundary Protection
- SC-12: Cryptographic Key Management
- SC-28: Protection of Information at Rest
- SI-3: Malicious Code Protection
- SI-4: System Monitoring
*/

# Core Configuration
variable "name" {
  description = "The name prefix for all resources. Used for resource naming and tagging. Must be alphanumeric with hyphens and less than 32 characters."
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

variable "data_classification" {
  description = "Data classification level (e.g., public, internal, confidential, restricted). Used for resource tagging and access control."
  type        = string
  default     = "confidential"
  
  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
  }
}

variable "owner_contact" {
  description = "Email address of the resource owner or team. Used for operational notifications and incident response."
  type        = string
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.owner_contact))
    error_message = "Owner contact must be a valid email address."
  }
}

# Network Configuration
variable "cidr" {
  description = "The CIDR block for the VPC. Must be a valid RFC 1918 private address range."
  type        = string
  default     = "10.0.0.0/16"
  
  validation {
    condition     = can(regex("^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.)\\d{1,3}\\.\\d{1,3}/\\d{1,2}$", var.cidr))
    error_message = "CIDR must be a valid RFC 1918 private address range."
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
}

variable "private_subnets" {
  description = "A list of private subnets inside the VPC. Must be within the VPC CIDR range and not overlap with public subnets."
  type        = list(string)
  default     = []
}

# Security Services Configuration
variable "enable_guardduty" {
  description = "Enable AWS GuardDuty for continuous security monitoring and threat detection. (NIST 800-53: SI-4, IR-4, RA-5)"
  type        = bool
  default     = true
}

variable "guardduty_finding_publishing_frequency" {
  description = "Specifies the frequency of notifications sent for subsequent finding occurrences. (NIST 800-53: SI-4)"
  type        = string
  default     = "SIX_HOURS"
  
  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_finding_publishing_frequency)
    error_message = "GuardDuty finding publishing frequency must be one of: FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS."
  }
}

variable "enable_inspector" {
  description = "Enable Amazon Inspector for automated security assessment. (NIST 800-53: CA-2, RA-5, SI-2)"
  type        = bool
  default     = true
}

variable "enable_macie" {
  description = "Enable Amazon Macie for data security and privacy. (NIST 800-53: AC-4, MP-4, SC-28)"
  type        = bool
  default     = true
}

variable "macie_finding_publishing_frequency" {
  description = "Specifies how often to publish updates to policy findings for the account. (NIST 800-53: AU-6, SI-4)"
  type        = string
  default     = "SIX_HOURS"
  
  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.macie_finding_publishing_frequency)
    error_message = "Macie finding publishing frequency must be one of: FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS."
  }
}

variable "enable_config" {
  description = "Enable AWS Config for resource configuration tracking and compliance auditing. (NIST 800-53: CM-2, CM-6, CM-8)"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable AWS Security Hub for consolidated security findings and compliance checks. (NIST 800-53: CA-2, CA-7, RA-5, SI-4)"
  type        = bool
  default     = true
}

variable "enable_cloudtrail" {
  description = "Enable AWS CloudTrail for API activity logging and monitoring. (NIST 800-53: AC-2, AU-2, AU-3, AU-6, AU-12)"
  type        = bool
  default     = true
}

# Logging and Monitoring Configuration
variable "flow_log_retention_in_days" {
  description = "Number of days to retain VPC Flow Logs in CloudWatch. (NIST 800-53: AU-11)"
  type        = number
  default     = 365
  
  validation {
    condition     = var.flow_log_retention_in_days >= 90 && var.flow_log_retention_in_days <= 2557
    error_message = "Flow log retention must be between 90 and 2557 days."
  }
}

variable "cloudtrail_log_retention_days" {
  description = "Number of days to retain CloudTrail logs. (NIST 800-53: AU-11)"
  type        = number
  default     = 365
  
  validation {
    condition     = var.cloudtrail_log_retention_days >= 90 && var.cloudtrail_log_retention_days <= 2557
    error_message = "CloudTrail log retention must be between 90 and 2557 days."
  }
}

variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for security events. (NIST 800-53: AU-6, SI-4)"
  type        = bool
  default     = true
}

# Encryption Configuration
variable "enable_kms" {
  description = "Enable AWS KMS for encryption of resources. (NIST 800-53: SC-12, SC-13, SC-28)"
  type        = bool
  default     = true
}

variable "kms_key_rotation" {
  description = "Specifies whether key rotation is enabled for KMS keys. (NIST 800-53: SC-12)"
  type        = bool
  default     = true
}

# Network Security Configuration
variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs for monitoring network traffic. (NIST 800-53: AC-4, AU-2, AU-12, SC-7)"
  type        = bool
  default     = true
}

variable "enable_default_security_group_deny_all" {
  description = "Update the default security group to deny all traffic by default. (NIST 800-53: AC-4, SC-7)"
  type        = bool
  default     = true
}

# Backup and Recovery Configuration
variable "enable_backup" {
  description = "Enable AWS Backup for automated backup of resources. (NIST 800-53: CP-9, CP-10)"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain backups. (NIST 800-53: CP-9, CP-10)"
  type        = number
  default     = 35
  
  validation {
    condition     = var.backup_retention_days >= 1 && var.backup_retention_days <= 3650
    error_message = "Backup retention must be between 1 and 3650 days."
  }
}

# Tagging
variable "tags" {
  description = "A map of tags to add to all resources. Used for resource management, cost allocation, and security automation. (NIST 800-53: CM-2, CM-8, PM-5)"
  type        = map(string)
  default     = {}
  
  validation {
    condition     = alltrue([for k, v in var.tags : can(regex("^[\\.\\-a-zA-Z0-9_/+=:\\s]+$", v))])
    error_message = "Tags can only contain alphanumeric characters, spaces, and the following: ._-:/=+@"
  }
}

# Compliance Configuration
variable "compliance_frameworks" {
  description = "List of compliance frameworks to enable (e.g., nist_800_53, hipaa, gdpr). (NIST 800-53: CA-2, PM-9)"
  type        = list(string)
  default     = ["nist_800_53"]
  
  validation {
    condition     = alltrue([for f in var.compliance_frameworks : contains(["nist_800_53", "hipaa", "gdpr", "soc_2"], f)])
    error_message = "Supported compliance frameworks are: nist_800_53, hipaa, gdpr, soc_2."
  }
}

# Notification Configuration
variable "security_notification_arn" {
  description = "ARN of the SNS topic for security notifications. (NIST 800-53: IR-4, IR-5, IR-6)"
  type        = string
  default     = ""
  
  validation {
    condition     = var.security_notification_arn == "" || can(regex("^arn:aws:sns:[a-z0-9-]+:[0-9]+:[a-zA-Z0-9_-]+$", var.security_notification_arn))
    error_message = "Security notification ARN must be a valid SNS topic ARN or empty string."
  }
}

# Additional Security Controls
variable "enable_aws_shield" {
  description = "Enable AWS Shield Standard for DDoS protection. (NIST 800-53: SC-5, SI-4)"
  type        = bool
  default     = true
}

variable "enable_aws_waf" {
  description = "Enable AWS WAF for web application protection. (NIST 800-53: AC-4, SC-7, SI-3)"
  type        = bool
  default     = true
}

variable "enable_aws_config_rules" {
  description = "Enable AWS Config managed rules for compliance monitoring. (NIST 800-53: CM-2, CM-6, CM-8, SI-4)"
  type        = bool
  default     = true
}
