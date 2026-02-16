/*
NIST 800-53 Controls Addressed in IAM Factory Module Variables:
- AC-2: Account Management
- AC-3: Access Enforcement
- AC-5: Separation of Duties
- AC-6: Least Privilege
- IA-2: Identification and Authentication
- IA-4: Identifier Management
- IA-5: Authenticator Management
- IA-6: Authenticator Feedback
- IA-7: Cryptographic Module Authentication
- AU-2: Audit Events
- AU-3: Content of Audit Records
- AU-6: Audit Review, Analysis, and Reporting
- AU-12: Audit Generation
- SC-7: Boundary Protection
- SC-12: Cryptographic Key Establishment and Management
- SC-28: Protection of Information at Rest
- SI-4: System Monitoring
- SI-7: Software, Firmware, and Information Integrity
*/

# Core Configuration
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
  description = "Data classification level (e.g., public, internal, confidential, restricted). Used for resource tagging and access control. (NIST 800-53: AC-4, MP-4, SC-28)"
  type        = string
  default     = "confidential"
  
  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
  }
}

variable "default_owner_contact" {
  description = "Default email address of the resource owner or team. Used for operational notifications and incident response. (NIST 800-53: PM-9, IR-4)"
  type        = string
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.default_owner_contact))
    error_message = "Default owner contact must be a valid email address."
  }
}

variable "default_cost_center" {
  description = "Default cost center for resource allocation and tracking. (NIST 800-53: PM-5)"
  type        = string
  default     = ""
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

# IAM Users Configuration
variable "iam_users" {
  description = "List of IAM users to create with their respective configurations. (NIST 800-53: AC-2, AC-3, AC-5, AC-6, IA-2, IA-4, IA-5)"
  type = list(object({
    name                  = string
    path                 = optional(string, "/users/")
    force_destroy        = optional(bool, false)
    permissions_boundary = optional(string, "")
    groups               = optional(list(string), [])
    policies             = optional(list(string), [])
    inline_policies      = optional(list(object({
      name   = string
      policy = string
    })), [])
    tags                 = optional(map(string), {})
    create_access_key    = optional(bool, false)
    create_console_access = optional(bool, true)
    password_reset_required = optional(bool, true)
    password_length      = optional(number, 20)
    owner_contact        = optional(string, "")
    cost_center          = optional(string, "")
  }))
  default = []
  
  validation {
    condition     = alltrue([
      for user in var.iam_users : 
      can(regex("^[a-zA-Z0-9_+=,.@-]+", user.name)) && 
      (user.password_length == null || (user.password_length >= 14 && user.password_length <= 128))
    ])
    error_message = "User names must be valid IAM user names (alphanumeric and '+=,.@-') and password length must be between 14 and 128 characters if specified."
  }
}

# IAM Groups Configuration
variable "iam_groups" {
  description = "List of IAM groups to create. (NIST 800-53: AC-2, AC-3, AC-5, AC-6)"
  type = list(object({
    name                  = string
    path                 = optional(string, "/groups/")
    policies             = optional(list(string), [])
    inline_policies      = optional(list(object({
      name   = string
      policy = string
    })), [])
    permissions_boundary = optional(string, "")
  }))
  default = []
}

# IAM Roles Configuration
variable "iam_roles" {
  description = "List of IAM roles to create. (NIST 800-53: AC-2, AC-3, AC-5, AC-6, AC-17)"
  type = list(object({
    name                  = string
    description          = optional(string, "")
    path                 = optional(string, "/roles/")
    max_session_duration = optional(number, 3600)
    permissions_boundary = optional(string, "")
    assume_role_policy   = string
    policies             = optional(list(string), [])
    inline_policies      = optional(list(object({
      name   = string
      policy = string
    })), [])
    tags                 = optional(map(string), {})
  }))
  default = []
  
  validation {
    condition     = alltrue([
      for role in var.iam_roles : 
      role.max_session_duration >= 3600 && role.max_session_duration <= 43200
    ])
    error_message = "Maximum session duration must be between 1 hour (3600 seconds) and 12 hours (43200 seconds)."
  }
}

# IAM Policies Configuration
variable "iam_policies" {
  description = "List of IAM policies to create. (NIST 800-53: AC-3, AC-5, AC-6)"
  type = list(object({
    name        = string
    description = optional(string, "")
    path        = optional(string, "/")
    policy      = string
    tags        = optional(map(string), {})
  }))
  default = []
}

# Password Policy Configuration
variable "enable_password_policy" {
  description = "Whether to enable the IAM account password policy. (NIST 800-53: IA-5)"
  type        = bool
  default     = true
}

variable "password_policy" {
  description = "Configuration for the IAM account password policy. (NIST 800-53: IA-5)"
  type = object({
    minimum_length     = optional(number, 14)
    require_lowercase = optional(bool, true)
    require_numbers   = optional(bool, true)
    require_uppercase = optional(bool, true)
    require_symbols   = optional(bool, true)
    allow_change      = optional(bool, true)
    max_age           = optional(number, 90)
    reuse_prevention  = optional(number, 24)
    hard_expiry       = optional(bool, false)
  })
  default = {}
  
  validation {
    condition     = (var.password_policy.minimum_length >= 14 && var.password_policy.minimum_length <= 128) &&
                   (var.password_policy.max_age >= 1 && var.password_policy.max_age <= 1095) &&
                   (var.password_policy.reuse_prevention >= 1 && var.password_policy.reuse_prevention <= 24)
    error_message = "Password policy validation failed. Minimum length must be 14-128 characters, max age 1-1095 days, and reuse prevention 1-24 generations."
  }
}

# MFA Configuration
variable "enable_mfa_enforcement" {
  description = "Whether to enforce MFA for all IAM users. (NIST 800-53: IA-2, IA-5)"
  type        = bool
  default     = true
}

variable "enable_self_service_mfa" {
  description = "Whether to allow users to manage their own MFA devices. (NIST 800-53: IA-2, IA-5)"
  type        = bool
  default     = true
}

variable "max_mfa_age_seconds" {
  description = "Maximum age in seconds for MFA sessions. (NIST 800-53: IA-2, IA-5)"
  type        = number
  default     = 86400  # 24 hours
  
  validation {
    condition     = var.max_mfa_age_seconds >= 900 && var.max_mfa_age_seconds <= 129600  # 15 minutes to 36 hours
    error_message = "MFA session duration must be between 900 (15 minutes) and 129600 (36 hours) seconds."
  }
}

# Access Key Configuration
variable "enable_access_key_rotation" {
  description = "Whether to enforce access key rotation. (NIST 800-53: IA-5)"
  type        = bool
  default     = true
}

variable "access_key_max_age_days" {
  description = "Maximum age in days for access keys before they must be rotated. (NIST 800-53: IA-5)"
  type        = number
  default     = 90
  
  validation {
    condition     = var.access_key_max_age_days >= 1 && var.access_key_max_age_days <= 365
    error_message = "Access key max age must be between 1 and 365 days."
  }
}

# Break Glass Access Configuration
variable "enable_break_glass_access" {
  description = "Whether to enable break glass access for emergency scenarios. (NIST 800-53: AC-2, AC-3, AC-6)"
  type        = bool
  default     = true
}

variable "break_glass_principal_arns" {
  description = "List of IAM user or role ARNs that should have break glass access. (NIST 800-53: AC-2, AC-3, AC-6)"
  type        = list(string)
  default     = []
  
  validation {
    condition     = alltrue([
      for arn in var.break_glass_principal_arns :
      can(regex("^arn:aws:(iam|sts)::[0-9]+:(user|role|federated-user|assumed-role)/[a-zA-Z0-9+=,.@_-]+$", arn))
    ])
    error_message = "Break glass principal ARNs must be valid IAM user or role ARNs."
  }
}

variable "break_glass_max_session_seconds" {
  description = "Maximum session duration in seconds for break glass access. (NIST 800-53: AC-2, AC-3, AC-6)"
  type        = number
  default     = 3600  # 1 hour
  
  validation {
    condition     = var.break_glass_max_session_seconds >= 900 && var.break_glass_max_session_seconds <= 43200  # 15 minutes to 12 hours
    error_message = "Break glass session duration must be between 900 (15 minutes) and 43200 (12 hours) seconds."
  }
}

# Service Account Protection
variable "enable_service_account_protection" {
  description = "Whether to enable protection for service accounts. (NIST 800-53: AC-2, AC-3, IA-5)"
  type        = bool
  default     = true
}

# IAM Access Analyzer Configuration
variable "enable_access_analyzer" {
  description = "Whether to enable IAM Access Analyzer. (NIST 800-53: AC-2, AC-3, AC-6, AU-2, AU-6, AU-12, SI-4)"
  type        = bool
  default     = true
}

# Credential Report Configuration
variable "enable_credential_report" {
  description = "Whether to enable IAM credential reports. (NIST 800-53: AU-6, AU-12)"
  type        = bool
  default     = true
}

# Account Alias
variable "account_alias" {
  description = "The account alias to set for the AWS account. (NIST 800-53: AC-2, IA-4)"
  type        = string
  default     = ""
  
  validation {
    condition     = var.account_alias == "" || can(regex("^[a-z0-9-]+", var.account_alias))
    error_message = "Account alias must be lowercase alphanumeric with hyphens only."
  }
}

# Permissions Boundary
variable "permissions_boundary_arn" {
  description = "The ARN of the IAM policy to set as the permissions boundary for all IAM entities. (NIST 800-53: AC-3, AC-5, AC-6)"
  type        = string
  default     = ""
  
  validation {
    condition     = var.permissions_boundary_arn == "" || can(regex("^arn:aws:iam::[0-9]+:policy/[a-zA-Z0-9+=,.@_-]+$", var.permissions_boundary_arn))
    error_message = "Permissions boundary ARN must be a valid IAM policy ARN or empty string."
  }
}

# PGP Key for Encrypting Secrets
variable "pgp_key" {
  description = "Either a base-64 encoded PGP public key, or a keybase username in the format keybase:username. Used to encrypt login profiles and access keys. (NIST 800-53: SC-12, SC-28)"
  type        = string
  default     = ""
  
  validation {
    condition     = var.pgp_key == "" || can(regex("^(keybase:[a-zA-Z0-9_-]+|(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)$", var.pgp_key))
    error_message = "PGP key must be either a base64-encoded public key or in the format 'keybase:username'."
  }
}

# IAM User Management Features
variable "enable_user_management" {
  description = "Whether to enable IAM user management features. (NIST 800-53: AC-2, AC-3, AC-5, AC-6)"
  type        = bool
  default     = true
}

variable "enable_role_management" {
  description = "Whether to enable IAM role management features. (NIST 800-53: AC-2, AC-3, AC-5, AC-6, AC-17)"
  type        = bool
  default     = true
}

variable "enable_policy_management" {
  description = "Whether to enable IAM policy management features. (NIST 800-53: AC-3, AC-5, AC-6)"
  type        = bool
  default     = true
}

variable "enable_access_key_management" {
  description = "Whether to enable IAM access key management features. (NIST 800-53: IA-5)"
  type        = bool
  default     = true
}

variable "enable_mfa_management" {
  description = "Whether to enable IAM MFA management features. (NIST 800-53: IA-2, IA-5)"
  type        = bool
  default     = true
}

variable "enable_password_management" {
  description = "Whether to enable IAM password management features. (NIST 800-53: IA-5)"
  type        = bool
  default     = true
}

variable "enable_ssh_key_management" {
  description = "Whether to enable IAM SSH key management features. (NIST 800-53: IA-5)"
  type        = bool
  default     = true
}

variable "enable_service_specific_credentials" {
  description = "Whether to enable IAM service-specific credentials features. (NIST 800-53: IA-5)"
  type        = bool
  default     = true
}

variable "enable_signing_certificate_management" {
  description = "Whether to enable IAM signing certificate management features. (NIST 800-53: IA-5)"
  type        = bool
  default     = true
}

variable "enable_service_quotas" {
  description = "Whether to enable IAM service quotas features. (NIST 800-53: AC-2, AC-3)"
  type        = bool
  default     = true
}

variable "enable_service_last_accessed" {
  description = "Whether to enable IAM service last accessed features. (NIST 800-53: AU-6, AU-12)"
  type        = bool
  default     = true
}

# Local Variables
locals {
  # Flattened list of all group policy attachments
  group_policy_attachments = flatten([
    for group in var.iam_groups : [
      for policy in group.policies : {
        group      = group.name
        policy_arn = policy
      }
    ]
  ])
  
  # Flattened list of all user policy attachments
  user_policy_attachments = flatten([
    for user in var.iam_users : [
      for policy in user.policies : {
        user       = user.name
        policy_arn = policy
      }
    ]
  ])
  
  # Default password policy with overrides
  password_policy = merge(
    {
      minimum_length     = 14
      require_lowercase = true
      require_uppercase = true
      require_numbers   = true
      require_symbols   = true
      allow_change      = true
      max_age           = 90
      reuse_prevention  = 24
      hard_expiry       = false
    },
    var.password_policy
  )
}
