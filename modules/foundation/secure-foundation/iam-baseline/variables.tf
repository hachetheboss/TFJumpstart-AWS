/*
NIST 800-53 Controls Addressed:
- AC-2: Account Management
- AC-6: Least Privilege
- IA-2: Identification and Authentication
- IA-4: Identifier Management
- IA-5: Authenticator Management
- IA-5(1): Password-Based Authentication
- IA-5(4): Automated Support for Password Strength Determination
- IA-5(7): No Embedded Unencrypted Static Authenticators
*/

variable "name" {
  description = "The name prefix for all resources. Used for resource naming and tagging."
  type        = string
  
  validation {
    condition     = length(var.name) <= 32 && can(regex("^[a-zA-Z0-9-]+", var.name))
    error_message = "Name must be alphanumeric with hyphens and less than 32 characters."
  }
}

variable "enable_password_policy" {
  description = "Whether to enable strict IAM password policy in compliance with NIST 800-63B"
  type        = bool
  default     = true
}

variable "enable_service_account_password_policy" {
  description = "Whether to enable a separate, more restrictive password policy for service accounts"
  type        = bool
  default     = true
}

variable "permissions_boundary_arn" {
  description = "ARN of the IAM policy to set as permissions boundary for all IAM roles"
  type        = string
  default     = ""
  
  validation {
    condition     = var.permissions_boundary_arn == "" || can(regex("^arn:aws:iam::[0-9]+:policy/[a-zA-Z0-9+=,.@_-]+$", var.permissions_boundary_arn))
    error_message = "The permissions_boundary_arn must be a valid IAM policy ARN or empty string."
  }
}

variable "break_glass_role_max_session_duration" {
  description = "Maximum session duration (in seconds) for the break glass role. Default is 1 hour (3600 seconds)."
  type        = number
  default     = 3600
  
  validation {
    condition     = var.break_glass_role_max_session_duration >= 3600 && var.break_glass_role_max_session_duration <= 43200
    error_message = "Break glass role session duration must be between 1 hour (3600 seconds) and 12 hours (43200 seconds)."
  }
}

variable "enable_self_service_password_reset" {
  description = "Whether to allow users to reset their own passwords through the AWS Management Console"
  type        = bool
  default     = true
}

variable "enable_iam_access_analyzer" {
  description = "Whether to enable IAM Access Analyzer for identifying external access to resources"
  type        = bool
  default     = true
}

variable "tags" {
  description = "A map of tags to add to all resources. Tags are used for resource management, cost allocation, and security automation."
  type        = map(string)
  default     = {}
  
  validation {
    condition     = alltrue([for k, v in var.tags : can(regex("^[\\.\\-a-zA-Z0-9_/+=:\\s]+$", v))])
    error_message = "Tags can only contain alphanumeric characters, spaces, and the following: ._-:/=+@"
  }
}

variable "enable_iam_password_policy_notification" {
  description = "Whether to enable SNS notifications for IAM password policy changes"
  type        = bool
  default     = true
}

variable "password_policy_notification_arn" {
  description = "ARN of the SNS topic for password policy change notifications"
  type        = string
  default     = ""
  
  validation {
    condition     = var.password_policy_notification_arn == "" || can(regex("^arn:aws:sns:[a-z0-9-]+:[0-9]+:[a-zA-Z0-9_-]+$", var.password_policy_notification_arn))
    error_message = "The password_policy_notification_arn must be a valid SNS topic ARN or empty string."
  }
}

variable "enable_service_control_policies" {
  description = "Whether to enable AWS Organizations Service Control Policies (SCPs) for additional guardrails"
  type        = bool
  default     = true
}

variable "enable_iam_credential_report" {
  description = "Whether to enable IAM credential reports for auditing and compliance"
  type        = bool
  default     = true
}

variable "enable_iam_password_policy_rotation" {
  description = "Whether to enable automatic rotation of IAM user access keys"
  type        = bool
  default     = true
}

variable "access_key_max_age_days" {
  description = "Maximum age (in days) for IAM user access keys before they must be rotated"
  type        = number
  default     = 90
  
  validation {
    condition     = var.access_key_max_age_days >= 1 && var.access_key_max_age_days <= 365
    error_message = "Access key max age must be between 1 and 365 days."
  }
}

variable "enable_iam_user_console_access_monitoring" {
  description = "Whether to enable monitoring of IAM user console access for security events"
  type        = bool
  default     = true
}

variable "enable_iam_user_unused_credentials_check" {
  description = "Whether to enable detection of unused IAM user credentials"
  type        = bool
  default     = true
}

variable "unused_credentials_max_age_days" {
  description = "Maximum age (in days) for unused IAM user credentials before they are flagged"
  type        = number
  default     = 90
  
  validation {
    condition     = var.unused_credentials_max_age_days >= 1 && var.unused_credentials_max_age_days <= 365
    error_message = "Unused credentials max age must be between 1 and 365 days."
  }
}
