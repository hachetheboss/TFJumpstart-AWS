output "break_glass_role_arn" {
  description = "The ARN of the break glass IAM role"
  value       = aws_iam_role.break_glass.arn
}

output "enforce_mfa_policy_arn" {
  description = "The ARN of the MFA enforcement IAM policy"
  value       = aws_iam_policy.enforce_mfa.arn
}

output "access_analyzer_arn" {
  description = "The ARN of the IAM Access Analyzer"
  value       = aws_accessanalyzer_analyzer.organization.arn
}
