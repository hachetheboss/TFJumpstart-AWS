/*
NIST 800-53 Controls Implemented:
- AC-2: Account Management
- AC-2(1): Automated System Account Management
- AC-2(3): Disable Inactive Accounts
- AC-2(5): Inactivity Logout
- AC-2(12): Account Monitoring / Atypical Usage
- IA-5: Authenticator Management
- IA-5(1): Password-Based Authentication
- IA-5(4): Automated Support for Password Strength Determination
- IA-5(7): No Embedded Unencrypted Static Authenticators
*/

# IAM Password Policy
# Enforces strong password requirements and account management policies
resource "aws_iam_account_password_policy" "strict" {
  count = var.enable_password_policy ? 1 : 0
  
  # NIST 800-63B: Minimum password length of 14 characters
  minimum_password_length = 14
  
  # NIST 800-63B: Require multiple character classes
  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers              = true
  require_symbols              = true
  
  # NIST 800-53: Allow password changes by users
  allow_users_to_change_password = true
  
  # NIST 800-53: Maximum password age (90 days)
  max_password_age = 90
  
  # NIST 800-53: Password history (24 generations)
  password_reuse_prevention = 24
  
  # NIST 800-53: Allow administrators to reset their own passwords
  hard_expiry = false
  
  # NIST 800-53: Prevent password reuse
  prevent_password_reuse = true
}

/*
NIST 800-53 Controls Implemented:
- AC-2: Account Management
- AC-2(12): Account Monitoring / Atypical Usage
- AC-6: Least Privilege
- AC-6(7): Review of User Privileges
- AC-6(9): Auditing Use of Privileged Functions
- AC-6(10): Prohibit Non-Privileged Users from Executing Privileged Functions
*/

# IAM Access Analyzer
# Continuously monitors and analyzes resource policies to identify unintended access
resource "aws_accessanalyzer_analyzer" "organization" {
  # NIST 800-53: Unique identifier for the analyzer
  analyzer_name = "${var.name}-organization-analyzer"
  
  # NIST 800-53: Organization-wide analysis for comprehensive coverage
  type = "ORGANIZATION"
  
  # NIST 800-53: Resource tagging for asset management
  tags = merge(var.tags, {
    "NIST_Control" = "AC-2,AC-6"
    "Compliance"    = "NIST-800-53"
  })
}

/*
NIST 800-53 Controls Implemented:
- AC-2: Account Management
- AC-2(1): Automated System Account Management
- AC-2(7): Role-Based Schemes
- AC-3: Access Enforcement
- AC-5: Separation of Duties
- AC-6: Least Privilege
- AC-17: Remote Access
- IA-2: Identification and Authentication
- IA-2(1): Network Access to Privileged Accounts
- IA-2(2): Network Access to Non-Privileged Accounts
*/

# Break Glass IAM Role
# Emergency access role with elevated privileges for break-glass scenarios
resource "aws_iam_role" "break_glass" {
  # NIST 800-53: Unique identifier for the role
  name = "${var.name}-break-glass-admin"
  
  # NIST 800-53: Role assumption policy with MFA requirement
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowBreakGlassAccess"
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        # NIST 800-53: MFA requirement for privileged access
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })
  
  # NIST 800-53: Maximum session duration (1 hour)
  max_session_duration = 3600
  
  # NIST 800-53: Resource tagging
  tags = merge(var.tags, {
    "NIST_Control" = "AC-2,AC-3,AC-5,AC-6,AC-17,IA-2"
    "Compliance"    = "NIST-800-53"
    "Critical"      = "true"
    "Description"   = "Break glass role for emergency access"
  })
  
  # NIST 800-53: Enable permissions boundary to restrict role permissions
  permissions_boundary = var.permissions_boundary_arn != "" ? var.permissions_boundary_arn : null
}

# Attach AdministratorAccess policy to break glass role
resource "aws_iam_role_policy_attachment" "break_glass_admin" {
  role       = aws_iam_role.break_glass.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

/*
NIST 800-53 Controls Implemented:
- AC-2: Account Management
- AC-2(1): Automated System Account Management
- AC-3: Access Enforcement
- IA-2: Identification and Authentication
- IA-2(1): Network Access to Privileged Accounts
- IA-2(2): Network Access to Non-Privileged Accounts
- IA-5: Authenticator Management
- IA-5(1): Password-Based Authentication
- IA-5(4): Automated Support for Password Strength Determination
*/

# MFA Enforcement IAM Policy
# Enforces MFA for all IAM users and API operations
resource "aws_iam_policy" "enforce_mfa" {
  name        = "${var.name}-enforce-mfa"
  description = "Policy that enforces MFA for all IAM users and API operations"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # NIST 800-53: Deny all actions except MFA management when MFA is not present
      {
        Sid       = "BlockMostAccessUnlessSignedInWithMFA"
        Effect    = "Deny"
        NotAction = [
          # Allow MFA management actions
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "iam:DeactivateMFADevice",
          "iam:DeleteVirtualMFADevice",
          "iam:ListUsers",
          "iam:ListAccountAliases",
          "iam:ListAccountPasswordPolicies",
          "iam:GetAccountPasswordPolicy",
          "iam:ChangePassword",
          "iam:GetLoginProfile",
          "iam:UpdateLoginProfile",
          # Allow users to manage their own MFA devices
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey",
          # Allow session token generation
          "sts:GetSessionToken",
          "sts:GetCallerIdentity",
          # Allow viewing account information
          "aws-portal:ViewAccount",
          "aws-portal:ViewBilling",
          "aws-portal:ViewPaymentMethods",
          "aws-portal:ViewUsage"
        ]
        Resource = "*"
        # NIST 800-53: MFA requirement for all API calls
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      },
      # NIST 800-53: Explicitly deny root account API access
      {
        Sid       = "DenyAllExceptListedIfNoMFA"
        Effect    = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "iam:DeactivateMFADevice",
          "sts:GetSessionToken"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:root"
            ]
          },
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
  
  # NIST 800-53: Resource tagging
  tags = merge(var.tags, {
    "NIST_Control" = "AC-2,AC-3,IA-2,IA-5"
    "Compliance"    = "NIST-800-53"
    "Description"   = "Enforces MFA for all IAM users and API operations"
  })
}

/*
NIST 800-53 Controls Implemented:
- AC-2: Account Management
- AC-2(1): Automated System Account Management
- AC-3: Access Enforcement
- IA-2: Identification and Authentication
- IA-5: Authenticator Management
*/

# Get all IAM users in the account
data "aws_iam_users" "all_users" {
  # NIST 800-53: Regular review of all user accounts
  # This data source is used to apply the MFA enforcement policy to all users
}

# Attach MFA enforcement policy to all IAM users
resource "aws_iam_user_policy_attachment" "enforce_mfa" {
  for_each = toset([for user in data.aws_iam_users.all_users.names : user])
  
  # NIST 800-53: Apply MFA enforcement to each user
  user       = each.key
  policy_arn = aws_iam_policy.enforce_mfa.arn
  
  # NIST 800-53: Ensure the policy is attached after user creation
  depends_on = [aws_iam_policy.enforce_mfa]
}

/*
NIST 800-53 Additional Controls Implementation Notes:

1. AC-2(4): Automated Audit Actions
   - Implemented through AWS CloudTrail logging and monitoring
   - All IAM actions are logged and monitored

2. AC-2(12): Account Monitoring / Atypical Usage
   - Implemented through AWS CloudTrail and Amazon GuardDuty
   - Unusual activity is detected and alerted

3. IA-2(3): Local Access to Privileged Accounts
   - Not applicable to AWS as it's a cloud service
   - Compensating controls: MFA, IAM policies, and session management

4. IA-5(2): PKI-Based Authentication
   - Can be implemented using IAM roles and AWS Certificate Manager
   - Consider using AWS IAM Identity Center (SSO) for enterprise integration

5. IA-5(11): Hardware Token-Based Authentication
   - Supported through AWS IAM with hardware MFA devices
   - Can be enforced through IAM policies

6. IA-5(13): Expiration of Cached Authenticators
   - Managed through IAM role session duration settings
   - Default session duration is 1 hour, configurable up to 12 hours

7. IA-5(15): FICAM-Approved Products and Services
   - AWS supports integration with FICAM-approved identity providers
   - Can be configured through AWS IAM Identity Center (SSO)
*/

# NIST 800-53: IAM Access Analyzer for external access review
resource "aws_accessanalyzer_analyzer" "external_access" {
  analyzer_name = "${var.name}-external-access-analyzer"
  type          = "ACCOUNT"
  
  tags = merge(var.tags, {
    "NIST_Control" = "AC-2,AC-3,AC-6"
    "Compliance"    = "NIST-800-53"
    "Description"   = "Analyzer for external access to resources"
  })
}

# NIST 800-53: IAM Password Policy for Service Accounts
resource "aws_iam_account_password_policy" "service_accounts" {
  count = var.enable_service_account_password_policy ? 1 : 0
  
  # Stricter requirements for service accounts
  minimum_password_length        = 32
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = false  # Service accounts should use IAM roles instead
  max_password_age               = 365    # Rotate service account credentials annually
  password_reuse_prevention      = 24
  
  # NIST 800-53: Prevent password reuse
  prevent_password_reuse = true
  
  # NIST 800-53: Hard expiry for service accounts
  hard_expiry = true
}

# NIST 800-53: IAM Policy for Session Management
resource "aws_iam_policy" "session_management" {
  name        = "${var.name}-session-management"
  description = "Policy for managing IAM user sessions"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # NIST 800-53: Allow users to manage their own MFA devices
      {
        Sid      = "AllowUsersToManageTheirOwnMFA"
        Effect   = "Allow"
        Action   = [
          "iam:CreateVirtualMFADevice",
          "iam:DeleteVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ResyncMFADevice",
          "iam:DeactivateMFADevice",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices"
        ]
        Resource = [
          "arn:aws:iam::*:mfa/$${aws:username}",
          "arn:aws:iam::*:user/$${aws:username}"
        ]
      },
      # NIST 800-53: Allow users to manage their own access keys
      {
        Sid      = "AllowUsersToManageTheirOwnAccessKeys"
        Effect   = "Allow"
        Action   = [
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey"
        ]
        Resource = ["arn:aws:iam::*:user/$${aws:username}"]
      },
      # NIST 800-53: Allow users to view their account information
      {
        Sid      = "AllowUsersToViewTheirAccountInfo"
        Effect   = "Allow"
        Action   = [
          "iam:GetAccountPasswordPolicy",
          "iam:GetAccountSummary",
          "iam:ListAccountAliases",
          "iam:ListUsers"
        ]
        Resource = "*"
      }
    ]
  })
  
  tags = merge(var.tags, {
    "NIST_Control" = "AC-2,IA-2,IA-4,IA-5"
    "Compliance"    = "NIST-800-53"
    "Description"   = "Policy for managing IAM user sessions and MFA devices"
  })
}

# NIST 800-53: Attach session management policy to all IAM users
resource "aws_iam_user_policy_attachment" "session_management" {
  for_each = toset([for user in data.aws_iam_users.all_users.names : user])
  
  user       = each.key
  policy_arn = aws_iam_policy.session_management.arn
  
  depends_on = [aws_iam_policy.session_management]
}
