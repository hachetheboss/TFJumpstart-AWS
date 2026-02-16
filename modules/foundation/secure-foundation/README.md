# Secure Foundation Module

This module creates a secure foundation for AWS infrastructure with compliance and security best practices built-in. It's designed to meet the needs of highly regulated organizations while remaining flexible for various use cases.

## Features

### Network Security
- **VPC with Public and Private Subnets**: Multi-AZ deployment with NAT gateways
- **VPC Flow Logs**: Comprehensive network traffic logging to S3
- **Private Subnet Isolation**: No direct internet access for private subnets
- **Security Group Defaults**: Restrictive by default

### Identity and Access Management
- **IAM Password Policy**: Enforces strong password requirements
- **MFA Enforcement**: Requires MFA for all IAM users
- **Break Glass Role**: Emergency access role with MFA and time-based access
- **Least Privilege**: Default deny-all IAM policies

### Logging and Monitoring
- **CloudTrail**: Multi-region activity logging with validation
- **VPC Flow Logs**: Network traffic monitoring
- **S3 Access Logs**: Bucket-level activity tracking
- **CloudWatch Logs**: Centralized log aggregation

### Security Services
- **AWS GuardDuty**: Intelligent threat detection
- **Amazon Inspector**: Automated security assessments
- **Amazon Macie**: Data privacy and protection
- **AWS Security Hub**: Centralized security findings
- **AWS Config**: Resource configuration tracking

### Data Protection
- **S3 Encryption**: Server-side encryption for all S3 buckets
- **Versioning**: Enabled for all S3 buckets
- **Lifecycle Policies**: Automatic data archiving and expiration
- **Access Logging**: All S3 buckets have access logging enabled

## Usage

```hcl
module "secure_foundation" {
  source = "git::https://github.com/your-org/terraform-jumpstart-aws.git//modules/foundation/secure-foundation?ref=v1.0.0"

  name        = "production"
  environment = "prod"
  
  cidr            = "10.0.0.0/16"
  azs             = ["us-west-2a", "us-west-2b", "us-west-2c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  
  # Security Services
  enable_guardduty = true
  enable_inspector = true
  enable_macie     = true
  enable_config    = true
  
  # Log Retention
  flow_log_retention_in_days = 365
  cloudtrail_log_retention_days = 365
  
  tags = {
    Environment = "production"
    Terraform   = "true"
    Compliance = "hipaa"
  }
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0 |
| aws | >= 4.0 |

## Providers

| Name | Version |
|------|---------|
| aws | >= 4.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-------:|:--------:|
| name | The name prefix for all resources | string | - | yes |
| environment | The environment (e.g., dev, staging, prod) | string | "prod" | no |
| cidr | The CIDR block for the VPC | string | "10.0.0.0/16" | no |
| azs | A list of availability zones in the region | list(string) | [] | no |
| public_subnets | A list of public subnets inside the VPC | list(string) | [] | no |
| private_subnets | A list of private subnets inside the VPC | list(string) | [] | no |
| enable_guardduty | Enable AWS GuardDuty for threat detection | bool | true | no |
| guardduty_finding_publishing_frequency | Frequency of GuardDuty notifications | string | "SIX_HOURS" | no |
| enable_inspector | Enable Amazon Inspector for security assessment | bool | true | no |
| enable_macie | Enable Amazon Macie for data security | bool | true | no |
| macie_finding_publishing_frequency | Frequency of Macie findings | string | "SIX_HOURS" | no |
| enable_config | Enable AWS Config for resource tracking | bool | true | no |
| enable_security_hub | Enable AWS Security Hub | bool | true | no |
| flow_log_retention_in_days | Retention period for VPC Flow Logs | number | 365 | no |
| cloudtrail_log_retention_days | Retention period for CloudTrail logs | number | 365 | no |
| tags | A map of tags to add to all resources | map(string) | {} | no |

## Outputs

| Name | Description |
|------|-------------|
| vpc_id | The ID of the VPC |
| public_subnets | List of IDs of public subnets |
| private_subnets | List of IDs of private subnets |
| guardduty_detector_id | The ID of the GuardDuty detector |
| inspector_enabled | Whether Amazon Inspector is enabled |
| macie_account_status | The status of the Amazon Macie account |
| security_hub_arn | The ARN of the Security Hub |
| flow_logs_bucket_arn | The ARN of the S3 bucket for VPC Flow Logs |
| audit_logs_bucket_arn | The ARN of the S3 bucket for audit logs |
| cloudtrail_arn | The ARN of the CloudTrail |
| break_glass_role_arn | The ARN of the break glass IAM role |
| enforce_mfa_policy_arn | The ARN of the MFA enforcement IAM policy |
| config_configuration_recorder_arn | The ARN of the configuration recorder |
| config_iam_role_arn | The ARN of the IAM role used for AWS Config |

## Security Considerations

### For Highly Regulated Organizations

1. **Data Residency**
   - Use AWS KMS with customer-managed CMKs for encryption
   - Enable S3 Object Lock for WORM (Write Once Read Many) compliance
   - Consider AWS Outposts or Local Zones for data sovereignty requirements

2. **Enhanced Monitoring**
   - Enable AWS Organizations and AWS Security Hub organization-wide
   - Integrate with SIEM solutions for centralized monitoring
   - Set up CloudWatch Alarms for critical security events

3. **Access Control**
   - Implement SCPs (Service Control Policies) at the AWS Organization level
   - Require MFA for all IAM users and root account
   - Use IAM Access Analyzer to identify external access

4. **Compliance**
   - Enable AWS Config rules for compliance frameworks (e.g., HIPAA, GDPR, NIST)
   - Use AWS Audit Manager for continuous compliance auditing
   - Regularly review AWS Security Hub findings

5. **Network Security**
   - Implement VPC endpoints for private connectivity to AWS services
   - Use AWS Network Firewall or third-party firewalls for advanced threat protection
   - Enable VPC Flow Logs and send to a security monitoring solution

6. **Incident Response**
   - Create and test an incident response plan
   - Use AWS Detective for security investigations
   - Implement AWS Backup for critical data protection

## License

[Specify your license here]
