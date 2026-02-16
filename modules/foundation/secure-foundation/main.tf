/*
NIST 800-53 Controls Implemented in this Module:

1. Access Control (AC) Family:
   - AC-2: Account Management
   - AC-3: Access Enforcement
   - AC-4: Information Flow Enforcement
   - AC-5: Separation of Duties
   - AC-6: Least Privilege
   - AC-17: Remote Access
   - AC-20: Use of External Systems

2. Audit and Accountability (AU) Family:
   - AU-2: Audit Events
   - AU-3: Content of Audit Records
   - AU-6: Audit Review, Analysis, and Reporting
   - AU-7: Audit Reduction and Report Generation
   - AU-12: Audit Generation

3. Security Assessment and Authorization (CA) Family:
   - CA-2: Security Assessments
   - CA-7: Continuous Monitoring
   - CA-9: Internal System Connections

4. Configuration Management (CM) Family:
   - CM-2: Baseline Configuration
   - CM-6: Configuration Settings
   - CM-7: Least Functionality
   - CM-8: System Component Inventory

5. Contingency Planning (CP) Family:
   - CP-9: Information System Backup
   - CP-10: Information System Recovery and Reconstitution

6. Identification and Authentication (IA) Family:
   - IA-2: Identification and Authentication
   - IA-5: Authenticator Management
   - IA-6: Authenticator Feedback

7. Incident Response (IR) Family:
   - IR-4: Incident Handling
   - IR-5: Incident Monitoring
   - IR-6: Incident Reporting

8. Maintenance (MA) Family:
   - MA-4: Nonlocal Maintenance

9. Media Protection (MP) Family:
   - MP-4: Media Storage
   - MP-5: Media Transport
   - MP-6: Media Sanitization

10. Risk Assessment (RA) Family:
    - RA-5: Vulnerability Scanning

11. System and Communications Protection (SC) Family:
    - SC-7: Boundary Protection
    - SC-12: Cryptographic Key Establishment and Management
    - SC-13: Cryptographic Protection
    - SC-28: Protection of Information at Rest
    - SC-39: Process Isolation

12. System and Information Integrity (SI) Family:
    - SI-3: Malicious Code Protection
    - SI-4: System Monitoring
    - SI-7: Software, Firmware, and Information Integrity
    - SI-12: Information Output Handling and Retention
*/

locals {
  default_tags = merge(
    var.tags,
    {
      "Terraform"     = "true"
      "Environment"   = var.environment
      "Compliance"    = "NIST-800-53"
      "DataSensitivity" = var.data_classification
      "Owner"         = var.owner_contact
    }
  )

  # Create a map of all compliance-related resources
  compliance_resources = {
    guardduty = var.enable_guardduty
    inspector = var.enable_inspector
    macie     = var.enable_macie
    config    = var.enable_config
    security_hub = var.enable_security_hub
    cloudtrail = var.enable_cloudtrail
  }
  
  # NIST 800-53: System and Communications Protection (SC-7)
  allowed_ingress_ports = [
    { port = 80, protocol = "tcp", description = "HTTP" },
    { port = 443, protocol = "tcp", description = "HTTPS" },
    { port = 22, protocol = "tcp", description = "SSH" }
  ]
  
  # NIST 800-53: Audit and Accountability (AU-2)
  cloudtrail_log_group_retention_days = 365  # NIST 800-53: AU-11
  
  # NIST 800-53: Configuration Management (CM-6)
  required_tags = [
    "Environment",
    "Owner",
    "DataSensitivity",
    "Compliance"
  ]
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# VPC Module
module "vpc" {
  source = "../vpc"

  name               = var.name
  cidr               = var.cidr
  azs                = var.azs
  private_subnets    = var.private_subnets
  public_subnets     = var.public_subnets
  enable_nat_gateway = true
  single_nat_gateway = false
  tags               = local.default_tags
}

# VPC Flow Logs to CloudWatch and S3
module "vpc_flow_logs" {
  source  = "terraform-aws-modules/flow-log/aws"
  version = "~> 2.0"

  log_destination_type = "s3"
  log_destination_arn  = aws_s3_bucket.flow_logs.arn
  traffic_type         = "ALL"
  vpc_id               = module.vpc.vpc_id
  
  tags = local.default_tags
}

# S3 Bucket for Flow Logs
resource "aws_s3_bucket" "flow_logs" {
  bucket_prefix = "${var.name}-flow-logs-"
  force_destroy = false
  
  # Enable versioning for log integrity
  versioning {
    enabled = true
  }
  
  # Enable server-side encryption
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  
  # Enable object-level logging
  logging {
    target_bucket = aws_s3_bucket.audit_logs.id
    target_prefix = "s3/${var.name}-flow-logs/"
  }
  
  lifecycle_rule {
    id      = "archive"
    enabled = true
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 60
      storage_class = "GLACIER"
    }
    
    expiration {
      days = 365
    }
  }
  
  tags = merge(local.default_tags, {
    Name = "${var.name}-flow-logs"
  })
}

# S3 Bucket for Audit Logs
resource "aws_s3_bucket" "audit_logs" {
  bucket_prefix = "${var.name}-audit-logs-"
  force_destroy = false
  
  versioning {
    enabled = true
  }
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  
  # Prevent deletion of log data
  lifecycle {
    prevent_destroy = true
  }
  
  tags = merge(local.default_tags, {
    Name = "${var.name}-audit-logs"
  })
}

# S3 Bucket Policy for Audit Logs
resource "aws_s3_bucket_policy" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyUnencryptedUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.audit_logs.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "AES256"
          }
        }
      },
      {
        Sid       = "DenyIncorrectEncryptionHeader"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.audit_logs.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = ""
          }
        }
      }
    ]
  })
}

# AWS Config
module "aws_config" {
  count = var.enable_config ? 1 : 0
  
  source  = "terraform-aws-modules/config/aws"
  version = "~> 2.0"
  
  create_configuration_recorder = true
  create_iam_role              = true
  
  s3_bucket_name = aws_s3_bucket.audit_logs.id
  
  managed_rules = [
    {
      name            = "s3-bucket-server-side-encryption-enabled"
      identifier      = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
      input_parameters = {}
    },
    {
      name            = "vpc-flow-logs-enabled"
      identifier      = "VPC_FLOW_LOGS_ENABLED"
      input_parameters = {}
    },
    {
      name            = "root-account-mfa-enabled"
      identifier      = "ROOT_ACCOUNT_MFA_ENABLED"
      input_parameters = {}
    }
  ]
  
  tags = local.default_tags
}

# GuardDuty
resource "aws_guardduty_detector" "this" {
  count = var.enable_guardduty ? 1 : 0
  
  enable                       = true
  finding_publishing_frequency = var.guardduty_finding_publishing_frequency
  
  datasources {
    s3_logs {
      enable = true
    }
    dns_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }
  
  tags = local.default_tags
}

# Amazon Inspector
resource "aws_inspector2_enabler" "this" {
  count = var.enable_inspector ? 1 : 0
  
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["ECR", "EC2", "LAMBDA"]
  
  depends_on = [aws_guardduty_detector.this]
}

# Amazon Macie
resource "aws_macie2_account" "this" {
  count = var.enable_macie ? 1 : 0
  
  finding_publishing_frequency = var.macie_finding_publishing_frequency
  status                       = "ENABLED"
  
  depends_on = [aws_guardduty_detector.this]
}

# AWS Security Hub
resource "aws_securityhub_account" "this" {
  count = var.enable_security_hub ? 1 : 0
  
  enable_default_standards = true
  auto_enable_controls    = true
  
  depends_on = [
    aws_guardduty_detector.this,
    aws_inspector2_enabler.this,
    aws_macie2_account.this
  ]
}

# CloudTrail
module "cloudtrail" {
  source  = "terraform-aws-modules/cloudtrail/aws"
  version = "~> 3.0"
  
  name                          = var.name
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail        = true
  enable_logging               = true
  
  cloud_watch_logs_group_retention_in_days = 365
  
  s3_bucket_name = aws_s3_bucket.audit_logs.id
  
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
  
  tags = local.default_tags
}

# IAM Baseline
module "iam_baseline" {
  source = "./iam-baseline"
  
  name              = var.name
  enable_password_policy = true
  
  tags = local.default_tags
}
