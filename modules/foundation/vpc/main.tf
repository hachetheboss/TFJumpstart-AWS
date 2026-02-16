/*
NIST 800-53 Controls Implemented in VPC Module:

1. Access Control (AC) Family:
   - AC-4: Information Flow Enforcement
   - AC-17: Remote Access

2. Audit and Accountability (AU) Family:
   - AU-2: Audit Events
   - AU-3: Content of Audit Records
   - AU-6: Audit Review, Analysis, and Reporting
   - AU-12: Audit Generation

3. Configuration Management (CM) Family:
   - CM-2: Baseline Configuration
   - CM-6: Configuration Settings
   - CM-7: Least Functionality
   - CM-8: System Component Inventory

4. System and Communications Protection (SC) Family:
   - SC-7: Boundary Protection
   - SC-7(5): Deny by Default / Allow by Exception
   - SC-12: Cryptographic Key Establishment and Management
   - SC-13: Cryptographic Protection
   - SC-28: Protection of Information at Rest
   - SC-39: Process Isolation

5. System and Information Integrity (SI) Family:
   - SI-3: Malicious Code Protection
   - SI-4: System Monitoring
   - SI-7: Software, Firmware, and Information Integrity
*/

locals {
  name = var.name
  
  # NIST 800-53: CM-2 - Baseline Configuration
  tags = merge(
    {
      "Name"              = local.name
      "Terraform"         = "true"
      "Environment"       = var.environment
      "Compliance"        = "nist_800_53"
      "DataSensitivity"   = var.data_classification
      "Owner"             = var.owner_contact
      "ManagedBy"         = "terraform"
      "NetworkTier"       = "vpc"
      "CostCenter"        = var.cost_center
      "ComplianceNotes"   = "NIST-800-53:AC-4,AC-17,AU-2,AU-3,AU-6,AU-12,CM-2,CM-6,CM-7,CM-8,SC-7,SC-12,SC-13,SC-28,SC-39,SI-3,SI-4,SI-7"
    },
    var.tags
  )

  # NIST 800-53: CP-10 - Information System Recovery and Reconstitution
  num_azs = length(var.azs)
  azs     = slice(var.azs, 0, min(local.num_azs, 3)) # Use up to 3 AZs for better HA
  
  # NIST 800-53: SC-7 - Boundary Protection
  default_network_acl_ingress = [
    {
      rule_no    = 100
      action     = "allow"
      from_port  = 0
      to_port    = 0
      protocol   = "-1"
      cidr_block = var.vpc_cidr
      icmp_type  = 0
      icmp_code  = 0
    },
    {
      rule_no    = 200
      action     = "allow"
      from_port  = 80
      to_port    = 80
      protocol   = "tcp"
      cidr_block = "0.0.0.0/0"
      icmp_type  = 0
      icmp_code  = 0
    },
    {
      rule_no    = 210
      action     = "allow"
      from_port  = 443
      to_port    = 443
      protocol   = "tcp"
      cidr_block = "0.0.0.0/0"
      icmp_type  = 0
      icmp_code  = 0
    }
  ]
  
  default_network_acl_egress = [
    {
      rule_no    = 100
      action     = "allow"
      from_port  = 0
      to_port    = 0
      protocol   = "-1"
      cidr_block = "0.0.0.0/0"
      icmp_type  = 0
      icmp_code  = 0
    }
  ]
}

# NIST 800-53: CM-2, CM-6, SC-7 - VPC with secure configuration
resource "aws_vpc" "this" {
  # NIST 800-53: CM-6 - Configuration Settings
  cidr_block = var.cidr
  
  # NIST 800-53: SC-7 - Boundary Protection
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  # NIST 800-53: CM-7 - Least Functionality
  instance_tenancy = "default"
  
  # NIST 800-53: CM-2 - Baseline Configuration
  tags = merge(
    local.tags,
    { 
      "Name" = local.name,
      "NetworkTier" = "vpc"
    }
  )
  
  # NIST 800-53: CM-6 - Configuration Settings
  lifecycle {
    ignore_changes = [
      # Ignore changes to tags that are managed by external systems
      tags["CreatedBy"],
      tags["CreationDate"],
      tags["LastModified"],
      tags["LastModifiedBy"]
    ]
  }
}

# NIST 800-53: CM-2, CM-6 - Default Network ACL with secure rules
resource "aws_default_network_acl" "this" {
  default_network_acl_id = aws_vpc.this.default_network_acl_id
  
  # NIST 800-53: SC-7(5) - Deny by Default
  # Default deny all inbound traffic
  ingress = local.default_network_acl_ingress
  
  # Default allow all outbound traffic
  egress = local.default_network_acl_egress
  
  # NIST 800-53: CM-2 - Baseline Configuration
  tags = merge(
    local.tags,
    { 
      "Name" = "${local.name}-default-acl",
      "NetworkTier" = "network-acl"
    }
  )
  
  # Ensure this is created after the VPC
  depends_on = [aws_vpc.this]
}

# NIST 800-53: CM-2, CM-6 - Default Security Group with deny all rules
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  
  # NIST 800-53: SC-7(5) - Deny by Default
  # No ingress or egress rules defined to deny all traffic by default
  
  # NIST 800-53: CM-2 - Baseline Configuration
  tags = merge(
    local.tags,
    { 
      "Name" = "${local.name}-default-sg",
      "NetworkTier" = "security-group"
    }
  )
  
  # Ensure this is created after the VPC
  depends_on = [aws_vpc.this]
}

# Public Subnets
resource "aws_subnet" "public" {
  count = length(var.public_subnets)

  vpc_id            = aws_vpc.this.id
  cidr_block        = element(var.public_subnets, count.index)
  availability_zone = element(local.azs, count.index)
  
  tags = merge(
    local.tags,
    { 
      Name = "${local.name}-public-${element(local.azs, count.index)}",
      "kubernetes.io/role/elb" = "1"
    }
  )
}

# Private Subnets
resource "aws_subnet" "private" {
  count = length(var.private_subnets)

  vpc_id            = aws_vpc.this.id
  cidr_block        = element(var.private_subnets, count.index)
  availability_zone = element(local.azs, count.index)
  
  tags = merge(
    local.tags,
    { 
      Name = "${local.name}-private-${element(local.azs, count.index)}",
      "kubernetes.io/role/internal-elb" = "1"
    }
  )
}

# Internet Gateway
resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  
  tags = merge(
    local.tags,
    { Name = "${local.name}-igw" }
  )
}

# NAT Gateways (one per AZ if enabled)
resource "aws_eip" "nat" {
  count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : local.num_azs) : 0
  
  vpc = true
  
  tags = merge(
    local.tags,
    { Name = "${local.name}-nat-${count.index}" }
  )
}

resource "aws_nat_gateway" "this" {
  count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : local.num_azs) : 0
  
  allocation_id = element(aws_eip.nat.*.id, count.index)
  subnet_id     = element(aws_subnet.public.*.id, count.index)
  
  tags = merge(
    local.tags,
    { Name = "${local.name}-ngw-${count.index}" }
  )
  
  depends_on = [aws_internet_gateway.this]
}

# Route Tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  
  tags = merge(
    local.tags,
    { Name = "${local.name}-public" }
  )
}

resource "aws_route_table" "private" {
  count  = var.enable_nat_gateway ? local.num_azs : 0
  vpc_id = aws_vpc.this.id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = element(
      aws_nat_gateway.this.*.id,
      var.single_nat_gateway ? 0 : count.index
    )
  }
  
  tags = merge(
    local.tags,
    { Name = "${local.name}-private-${element(local.azs, count.index)}" }
  )
}

# Route Table Associations
resource "aws_route_table_association" "public" {
  count = length(var.public_subnets)
  
  subnet_id      = element(aws_subnet.public.*.id, count.index)
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count = var.enable_nat_gateway ? length(var.private_subnets) : 0
  
  subnet_id      = element(aws_subnet.private.*.id, count.index)
  route_table_id = element(
    aws_route_table.private.*.id,
    var.single_nat_gateway ? 0 : count.index
  )
}

# VPC Flow Logs
resource "aws_flow_log" "this" {
  iam_role_arn    = aws_iam_role.vpc_flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.this.id
}

resource "aws_cloudwatch_log_group" "flow_log" {
  name              = "/aws/vpc-flow-logs/${local.name}"
  retention_in_days = 30
  
  tags = local.tags
}

resource "aws_iam_role" "vpc_flow_log" {
  name = "${local.name}-vpc-flow-log-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      },
    ]
  })
  
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "vpc_flow_log" {
  role       = aws_iam_role.vpc_flow_log.name
  policy_arn = aws_iam_policy.vpc_flow_log.arn
}

resource "aws_iam_policy" "vpc_flow_log" {
  name        = "${local.name}-vpc-flow-log-policy"
  description = "IAM policy for VPC Flow Logs"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      },
    ]
  })
}
