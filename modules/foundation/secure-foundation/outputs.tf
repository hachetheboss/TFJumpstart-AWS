# VPC Outputs
output "vpc_id" {
  description = "The ID of the VPC"
  value       = module.vpc.vpc_id
}

output "vpc_cidr_block" {
  description = "The CIDR block of the VPC"
  value       = module.vpc.vpc_cidr_block
}

output "public_subnets" {
  description = "List of IDs of public subnets"
  value       = module.vpc.public_subnets
}

output "private_subnets" {
  description = "List of IDs of private subnets"
  value       = module.vpc.private_subnets
}

# Security Service Outputs
output "guardduty_detector_id" {
  description = "The ID of the GuardDuty detector"
  value       = try(aws_guardduty_detector.this[0].id, "")
}

output "inspector_enabled" {
  description = "Whether Amazon Inspector is enabled"
  value       = var.enable_inspector
}

output "macie_account_status" {
  description = "The status of the Amazon Macie account"
  value       = try(aws_macie2_account.this[0].status, "DISABLED")
}

output "security_hub_arn" {
  description = "The ARN of the Security Hub"
  value       = try(aws_securityhub_account.this[0].arn, "")
}

# Logging Outputs
output "flow_logs_bucket_arn" {
  description = "The ARN of the S3 bucket for VPC Flow Logs"
  value       = aws_s3_bucket.flow_logs.arn
}

output "audit_logs_bucket_arn" {
  description = "The ARN of the S3 bucket for audit logs"
  value       = aws_s3_bucket.audit_logs.arn
}

output "cloudtrail_arn" {
  description = "The ARN of the CloudTrail"
  value       = module.cloudtrail.cloudtrail_arn
}

# IAM Outputs
output "break_glass_role_arn" {
  description = "The ARN of the break glass IAM role"
  value       = module.iam_baseline.break_glass_role_arn
}

output "enforce_mfa_policy_arn" {
  description = "The ARN of the MFA enforcement IAM policy"
  value       = module.iam_baseline.enforce_mfa_policy_arn
}

# Config Outputs
output "config_configuration_recorder_arn" {
  description = "The ARN of the configuration recorder"
  value       = try(module.aws_config[0].config_configuration_recorder_arn, "")
}

output "config_iam_role_arn" {
  description = "The ARN of the IAM role used for AWS Config"
  value       = try(module.aws_config[0].config_iam_role_arn, "")
}
