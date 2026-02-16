/*
NIST 800-53 Controls Addressed in IAM Factory Outputs:
- AC-2: Account Management
- AC-3: Access Enforcement
- AC-5: Separation of Duties
- AC-6: Least Privilege
- IA-2: Identification and Authentication
- IA-4: Identifier Management
- IA-5: Authenticator Management
- AU-2: Audit Events
- AU-6: Audit Review, Analysis, and Reporting
- AU-12: Audit Generation
- SC-7: Boundary Protection
- SC-12: Cryptographic Key Establishment and Management
- SC-28: Protection of Information at Rest
- SI-4: System Monitoring
*/

# IAM Users Outputs
output "iam_users" {
  description = "Map of IAM user names to their ARNs. (NIST 800-53: AC-2, AC-3, IA-4, IA-5)"
  value       = { for k, v in aws_iam_user.user : k => v.arn }
}

output "iam_user_names" {
  description = "List of IAM user names. (NIST 800-53: AC-2, IA-4)"
  value       = [for user in aws_iam_user.user : user.name]
}

output "iam_user_arns" {
  description = "List of IAM user ARNs. (NIST 800-53: AC-2, IA-4)"
  value       = [for user in aws_iam_user.user : user.arn]
}

output "iam_user_login_profiles" {
  description = "Map of IAM user names to their encrypted passwords (if console access was enabled). (NIST 800-53: IA-5)"
  value       = { for k, v in aws_iam_user_login_profile.login_profile : k => v.encrypted_password }
  sensitive   = true
}

output "iam_access_keys" {
  description = "Map of IAM user names to their encrypted access keys (if access keys were created). (NIST 800-53: IA-5, SC-12, SC-28)"
  value = {
    for k, v in aws_iam_access_key.access_key : k => {
      id                 = v.id
      encrypted_secret   = v.encrypted_secret
      key_fingerprint    = v.key_fingerprint
      pgp_key            = v.pgp_key
      secret             = v.encrypted_secret != "" ? "[Sensitive: Encrypted with PGP key]" : ""
      ses_smtp_password  = v.ses_smtp_password
      status             = v.status
    }
  }
  sensitive = true
}

# IAM Groups Outputs
output "iam_groups" {
  description = "Map of IAM group names to their ARNs. (NIST 800-53: AC-2, AC-3, AC-5, AC-6)"
  value       = { for k, v in aws_iam_group.group : k => v.arn }
}

output "iam_group_names" {
  description = "List of IAM group names. (NIST 800-53: AC-2, AC-5)"
  value       = [for group in aws_iam_group.group : group.name]
}

output "iam_group_arns" {
  description = "List of IAM group ARNs. (NIST 800-53: AC-2, AC-5)"
  value       = [for group in aws_iam_group.group : group.arn]
}

output "iam_group_memberships" {
  description = "Map of IAM users to their group memberships. (NIST 800-53: AC-2, AC-5, AC-6)"
  value       = { for k, v in aws_iam_group_membership.group_membership : k => v.users }
}

# IAM Roles Outputs
output "iam_roles" {
  description = "Map of IAM role names to their ARNs. (NIST 800-53: AC-2, AC-3, AC-5, AC-6, AC-17)"
  value       = { for k, v in aws_iam_role.role : k => v.arn }
}

output "iam_role_names" {
  description = "List of IAM role names. (NIST 800-53: AC-2, AC-5, AC-17)"
  value       = [for role in aws_iam_role.role : role.name]
}

output "iam_role_arns" {
  description = "List of IAM role ARNs. (NIST 800-53: AC-2, AC-5, AC-17)"
  value       = [for role in aws_iam_role.role : role.arn]
}

# IAM Policies Outputs
output "iam_policies" {
  description = "Map of IAM policy names to their ARNs. (NIST 800-53: AC-3, AC-5, AC-6)"
  value       = { for k, v in aws_iam_policy.policy : k => v.arn }
}

output "iam_policy_names" {
  description = "List of IAM policy names. (NIST 800-53: AC-3, AC-5)"
  value       = [for policy in aws_iam_policy.policy : policy.name]
}

output "iam_policy_arns" {
  description = "List of IAM policy ARNs. (NIST 800-53: AC-3, AC-5)"
  value       = [for policy in aws_iam_policy.policy : policy.arn]
}

# Password Policy Outputs
output "password_policy" {
  description = "The IAM account password policy. (NIST 800-53: IA-5)"
  value       = var.enable_password_policy ? aws_iam_account_password_policy.strict[0] : null
}

# Break Glass Access Outputs
output "break_glass_role_arn" {
  description = "The ARN of the break glass IAM role. (NIST 800-53: AC-2, AC-3, AC-6)"
  value       = var.enable_break_glass_access ? aws_iam_role.break_glass_role[0].arn : ""
}

# IAM Access Analyzer Outputs
output "access_analyzer_arn" {
  description = "The ARN of the IAM Access Analyzer. (NIST 800-53: AC-2, AC-3, AC-6, AU-2, AU-6, AU-12, SI-4)"
  value       = var.enable_access_analyzer ? aws_accessanalyzer_analyzer.organization[0].arn : ""
}

output "access_analyzer_id" {
  description = "The ID of the IAM Access Analyzer. (NIST 800-53: AC-2, AC-3, AC-6, AU-2, AU-6, AU-12, SI-4)"
  value       = var.enable_access_analyzer ? aws_accessanalyzer_analyzer.organization[0].id : ""
}

# Account Alias Output
output "account_alias" {
  description = "The AWS account alias. (NIST 800-53: AC-2, IA-4)"
  value       = var.account_alias != "" ? aws_iam_account_alias.alias[0].account_alias : ""
}

# Service Account Protection Outputs
output "service_account_protection_policy_arn" {
  description = "The ARN of the IAM policy for service account protection. (NIST 800-53: AC-2, AC-3, IA-5)"
  value       = var.enable_service_account_protection ? aws_iam_policy.service_account_protection[0].arn : ""
}

# MFA Enforcement Outputs
output "mfa_enforcement_policy_arn" {
  description = "The ARN of the IAM policy for MFA enforcement. (NIST 800-53: IA-2, IA-5)"
  value       = var.enable_mfa_enforcement ? aws_iam_policy.mfa_enforcement[0].arn : ""
}

output "self_service_mfa_policy_arn" {
  description = "The ARN of the IAM policy for self-service MFA management. (NIST 800-53: IA-2, IA-5)"
  value       = var.enable_self_service_mfa ? aws_iam_policy.self_service_mfa[0].arn : ""
}

# Access Key Rotation Outputs
output "access_key_rotation_policy_arn" {
  description = "The ARN of the IAM policy for access key rotation. (NIST 800-53: IA-5)"
  value       = var.enable_access_key_rotation ? aws_iam_policy.access_key_rotation[0].arn : ""
}

# Credential Report Outputs
output "credential_report_policy_arn" {
  description = "The ARN of the IAM policy for credential reports. (NIST 800-53: AU-6, AU-12)"
  value       = var.enable_credential_report ? aws_iam_policy.credential_report[0].arn : ""
}

# IAM User Management Outputs
output "user_management_policy_arn" {
  description = "The ARN of the IAM policy for user management. (NIST 800-53: AC-2, AC-3, AC-5, AC-6)"
  value       = var.enable_user_management ? aws_iam_policy.user_management[0].arn : ""
}

output "role_management_policy_arn" {
  description = "The ARN of the IAM policy for role management. (NIST 800-53: AC-2, AC-3, AC-5, AC-6, AC-17)"
  value       = var.enable_role_management ? aws_iam_policy.role_management[0].arn : ""
}

output "policy_management_policy_arn" {
  description = "The ARN of the IAM policy for policy management. (NIST 800-53: AC-3, AC-5, AC-6)"
  value       = var.enable_policy_management ? aws_iam_policy.policy_management[0].arn : ""
}

output "access_key_management_policy_arn" {
  description = "The ARN of the IAM policy for access key management. (NIST 800-53: IA-5)"
  value       = var.enable_access_key_management ? aws_iam_policy.access_key_management[0].arn : ""
}

output "mfa_management_policy_arn" {
  description = "The ARN of the IAM policy for MFA management. (NIST 800-53: IA-2, IA-5)"
  value       = var.enable_mfa_management ? aws_iam_policy.mfa_management[0].arn : ""
}

output "password_management_policy_arn" {
  description = "The ARN of the IAM policy for password management. (NIST 800-53: IA-5)"
  value       = var.enable_password_management ? aws_iam_policy.password_management[0].arn : ""
}

output "ssh_key_management_policy_arn" {
  description = "The ARN of the IAM policy for SSH key management. (NIST 800-53: IA-5)"
  value       = var.enable_ssh_key_management ? aws_iam_policy.ssh_key_management[0].arn : ""
}

output "service_specific_credentials_policy_arn" {
  description = "The ARN of the IAM policy for service-specific credentials. (NIST 800-53: IA-5)"
  value       = var.enable_service_specific_credentials ? aws_iam_policy.service_specific_credentials[0].arn : ""
}

output "signing_certificate_management_policy_arn" {
  description = "The ARN of the IAM policy for signing certificate management. (NIST 800-53: IA-5)"
  value       = var.enable_signing_certificate_management ? aws_iam_policy.signing_certificate_management[0].arn : ""
}

output "service_quotas_policy_arn" {
  description = "The ARN of the IAM policy for service quotas. (NIST 800-53: AC-2, AC-3)"
  value       = var.enable_service_quotas ? aws_iam_policy.service_quotas[0].arn : ""
}

output "service_last_accessed_policy_arn" {
  description = "The ARN of the IAM policy for service last accessed data. (NIST 800-53: AU-6, AU-12)"
  value       = var.enable_service_last_accessed ? aws_iam_policy.service_last_accessed[0].arn : ""
}

# Permissions Boundary Output
output "permissions_boundary_arn" {
  description = "The ARN of the IAM policy used as the permissions boundary for all IAM entities. (NIST 800-53: AC-3, AC-5, AC-6)"
  value       = var.permissions_boundary_arn
}

# PGP Key Output
output "pgp_key_fingerprint" {
  description = "The fingerprint of the PGP key used to encrypt sensitive data. (NIST 800-53: SC-12, SC-28)"
  value       = var.pgp_key != "" ? (can(regex("^keybase:", var.pgp_key)) ? "[Keybase key]" : "[Local PGP key]") : ""
  sensitive   = true
}
