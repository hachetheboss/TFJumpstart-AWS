# IAM Factory Module

This Terraform module provides a comprehensive IAM (Identity and Access Management) factory for creating and managing AWS IAM resources with NIST 800-53 compliance. The module enforces security best practices and provides a flexible interface for managing IAM users, groups, roles, and policies.

## NIST 800-53 Compliance

This module implements the following NIST 800-53 controls:

### Access Control (AC) Family
- **AC-2**: Account Management
- **AC-3**: Access Enforcement
- **AC-5**: Separation of Duties
- **AC-6**: Least Privilege
- **AC-17**: Remote Access

### Identification and Authentication (IA) Family
- **IA-2**: Identification and Authentication
- **IA-4**: Identifier Management
- **IA-5**: Authenticator Management
- **IA-6**: Authenticator Feedback
- **IA-7**: Cryptographic Module Authentication

### Audit and Accountability (AU) Family
- **AU-2**: Audit Events
- **AU-3**: Content of Audit Records
- **AU-6**: Audit Review, Analysis, and Reporting
- **AU-12**: Audit Generation

### System and Communications Protection (SC) Family
- **SC-7**: Boundary Protection
- **SC-12**: Cryptographic Key Establishment and Management
- **SC-28**: Protection of Information at Rest

### System and Information Integrity (SI) Family
- **SI-4**: System Monitoring
- **SI-7**: Software, Firmware, and Information Integrity

## Features

- **User Management**: Create and manage IAM users with secure defaults
- **Group Management**: Organize users into groups with appropriate permissions
- **Role Management**: Create IAM roles with trust relationships
- **Policy Management**: Define and attach IAM policies
- **Password Policy**: Enforce strong password requirements
- **MFA Enforcement**: Require multi-factor authentication
- **Access Key Rotation**: Enforce access key rotation
- **Break Glass Access**: Configure emergency access procedures
- **Service Account Protection**: Protect service accounts from interactive access
- **IAM Access Analyzer**: Enable IAM Access Analyzer for your organization
- **Credential Reports**: Generate and manage IAM credential reports
- **Service-Specific Credentials**: Manage service-specific credentials
- **SSH Key Management**: Manage SSH public keys for IAM users

## Usage

```hcl
module "iam_factory" {
  source = "git::https://github.com/your-org/terraform-aws-iam-factory.git?ref=v1.0.0"

  environment = "prod"
  data_classification = "confidential"
  default_owner_contact = "security@example.com"
  default_cost_center = "security"

  # Enable security features
  enable_password_policy = true
  enable_mfa_enforcement = true
  enable_access_key_rotation = true
  enable_break_glass_access = true
  enable_service_account_protection = true
  enable_access_analyzer = true
  enable_credential_report = true

  # Configure password policy
  password_policy = {
    minimum_length     = 14
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
    allow_change      = true
    max_age           = 90
    reuse_prevention  = 24
    hard_expiry       = false
  }

  # Configure break glass access
  break_glass_principal_arns = [
    "arn:aws:iam::123456789012:user/break-glass-admin"
  ]
  break_glass_max_session_seconds = 3600  # 1 hour

  # Define IAM users
  iam_users = [
    {
      name                  = "alice"
      groups               = ["developers"]
      create_console_access = true
      create_access_key    = true
      owner_contact        = "alice@example.com"
      tags = {
        Department = "Engineering"
        JobFunction = "Developer"
      }
    },
    {
      name                  = "bob"
      groups               = ["developers", "operations"]
      create_console_access = true
      owner_contact        = "bob@example.com"
      tags = {
        Department = "DevOps"
        JobFunction = "SRE"
      }
    }
  ]

  # Define IAM groups
  iam_groups = [
    {
      name = "developers"
      policies = [
        "arn:aws:iam::aws:policy/ReadOnlyAccess"
      ]
    },
    {
      name = "operations"
      policies = [
        "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
      ]
    }
  ]

  # Define IAM roles
  iam_roles = [
    {
      name        = "ec2-s3-access-role"
      description = "Allows EC2 instances to access S3 buckets"
      assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Action = "sts:AssumeRole"
            Effect = "Allow"
            Principal = {
              Service = "ec2.amazonaws.com"
            }
          }
        ]
      })
      policies = [
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
      ]
    }
  ]

  # Define custom IAM policies
  iam_policies = [
    {
      name        = "MyCustomPolicy"
      description = "A custom IAM policy"
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Action   = ["s3:ListAllMyBuckets", "s3:GetBucketLocation"]
            Effect   = "Allow"
            Resource = "*"
          }
        ]
      })
    }
  ]

  # Set account alias
  account_alias = "my-org-prod-account"

  # Set permissions boundary
  permissions_boundary_arn = "arn:aws:iam::123456789012:policy/PermissionsBoundary"

  # PGP key for encrypting secrets
  pgp_key = "keybase:username"  # or a base64-encoded PGP public key
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| environment | The environment (e.g., dev, staging, prod) | `string` | `"prod"` | no |
| data_classification | Data classification level (e.g., public, internal, confidential, restricted) | `string` | `"confidential"` | no |
| default_owner_contact | Default email address of the resource owner or team | `string` | n/a | yes |
| default_cost_center | Default cost center for resource allocation and tracking | `string` | `""` | no |
| tags | A map of tags to add to all resources | `map(string)` | `{}` | no |
| iam_users | List of IAM users to create | `list(any)` | `[]` | no |
| iam_groups | List of IAM groups to create | `list(any)` | `[]` | no |
| iam_roles | List of IAM roles to create | `list(any)` | `[]` | no |
| iam_policies | List of IAM policies to create | `list(any)` | `[]` | no |
| enable_password_policy | Whether to enable the IAM account password policy | `bool` | `true` | no |
| password_policy | Configuration for the IAM account password policy | `any` | `{}` | no |
| enable_mfa_enforcement | Whether to enforce MFA for all IAM users | `bool` | `true` | no |
| enable_self_service_mfa | Whether to allow users to manage their own MFA devices | `bool` | `true` | no |
| max_mfa_age_seconds | Maximum age in seconds for MFA sessions | `number` | `86400` | no |
| enable_access_key_rotation | Whether to enforce access key rotation | `bool` | `true` | no |
| access_key_max_age_days | Maximum age in days for access keys before they must be rotated | `number` | `90` | no |
| enable_break_glass_access | Whether to enable break glass access for emergency scenarios | `bool` | `true` | no |
| break_glass_principal_arns | List of IAM user or role ARNs that should have break glass access | `list(string)` | `[]` | no |
| break_glass_max_session_seconds | Maximum session duration in seconds for break glass access | `number` | `3600` | no |
| enable_service_account_protection | Whether to enable protection for service accounts | `bool` | `true` | no |
| enable_access_analyzer | Whether to enable IAM Access Analyzer | `bool` | `true` | no |
| enable_credential_report | Whether to enable IAM credential reports | `bool` | `true` | no |
| account_alias | The account alias to set for the AWS account | `string` | `""` | no |
| permissions_boundary_arn | The ARN of the IAM policy to set as the permissions boundary for all IAM entities | `string` | `""` | no |
| pgp_key | Either a base-64 encoded PGP public key, or a keybase username in the format keybase:username | `string` | `""` | no |

## Outputs

| Name | Description |
|------|-------------|
| iam_users | Map of IAM user names to their ARNs |
| iam_groups | Map of IAM group names to their ARNs |
| iam_roles | Map of IAM role names to their ARNs |
| iam_policies | Map of IAM policy names to their ARNs |
| password_policy | The IAM account password policy |
| break_glass_role_arn | The ARN of the break glass IAM role |
| access_analyzer_arn | The ARN of the IAM Access Analyzer |
| access_analyzer_id | The ID of the IAM Access Analyzer |
| account_alias | The AWS account alias |
| service_account_protection_policy_arn | The ARN of the IAM policy for service account protection |
| mfa_enforcement_policy_arn | The ARN of the IAM policy for MFA enforcement |
| self_service_mfa_policy_arn | The ARN of the IAM policy for self-service MFA management |
| access_key_rotation_policy_arn | The ARN of the IAM policy for access key rotation |
| credential_report_policy_arn | The ARN of the IAM policy for credential reports |
| user_management_policy_arn | The ARN of the IAM policy for user management |
| role_management_policy_arn | The ARN of the IAM policy for role management |
| policy_management_policy_arn | The ARN of the IAM policy for policy management |
| access_key_management_policy_arn | The ARN of the IAM policy for access key management |
| mfa_management_policy_arn | The ARN of the IAM policy for MFA management |
| password_management_policy_arn | The ARN of the IAM policy for password management |
| ssh_key_management_policy_arn | The ARN of the IAM policy for SSH key management |
| service_specific_credentials_policy_arn | The ARN of the IAM policy for service-specific credentials |
| signing_certificate_management_policy_arn | The ARN of the IAM policy for signing certificate management |
| service_quotas_policy_arn | The ARN of the IAM policy for service quotas |
| service_last_accessed_policy_arn | The ARN of the IAM policy for service last accessed data |
| permissions_boundary_arn | The ARN of the IAM policy used as the permissions boundary |
| pgp_key_fingerprint | The fingerprint of the PGP key used to encrypt sensitive data |

## Best Practices

1. **Enable MFA for All Users**: Always enable MFA for all IAM users, especially those with administrative privileges.

2. **Use Groups for Permission Assignment**: Assign permissions to groups rather than individual users to simplify permission management.

3. **Implement Least Privilege**: Grant only the permissions required to perform a task.

4. **Enable Access Key Rotation**: Regularly rotate access keys to reduce the risk of key compromise.

5. **Use IAM Access Analyzer**: Enable IAM Access Analyzer to help identify resources that are shared with an external entity.

6. **Enable Credential Reports**: Regularly review credential reports to monitor account activity and identify potential security risks.

7. **Use Break Glass Accounts**: Set up break glass accounts for emergency access with strict controls and monitoring.

8. **Enable Service Account Protection**: Protect service accounts from interactive access to prevent privilege escalation.

9. **Use Permissions Boundaries**: Apply permissions boundaries to limit the maximum permissions that can be granted to IAM entities.

10. **Enable CloudTrail Logging**: Ensure that CloudTrail logging is enabled to monitor API activity in your AWS account.

## Security Considerations

- **Sensitive Outputs**: This module may output sensitive information such as IAM access keys and encrypted passwords. Ensure that these outputs are handled securely.
- **Permissions Boundaries**: Consider using permissions boundaries to limit the maximum permissions that can be granted to IAM entities created by this module.
- **MFA**: Always enable MFA for IAM users, especially those with administrative privileges.
- **Audit Logging**: Enable AWS CloudTrail logging to monitor API activity in your AWS account.
- **Regular Reviews**: Regularly review IAM users, groups, roles, and policies to ensure that they are still needed and properly configured.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [NIST 800-53](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf) - Security and Privacy Controls for Information Systems and Organizations
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html)
