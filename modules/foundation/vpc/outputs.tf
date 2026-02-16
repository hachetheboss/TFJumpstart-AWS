/*
NIST 800-53 Controls Addressed in VPC Module Outputs:
- AC-4: Information Flow Enforcement
- CM-2: Baseline Configuration
- CM-8: System Component Inventory
- SC-7: Boundary Protection
- SI-4: System Monitoring
*/

# Core VPC Outputs
output "vpc_id" {
  description = "The ID of the VPC. (NIST 800-53: CM-2, CM-8)"
  value       = aws_vpc.this.id
}

output "vpc_arn" {
  description = "The ARN of the VPC. (NIST 800-53: CM-2, CM-8)"
  value       = aws_vpc.this.arn
}

output "vpc_cidr_block" {
  description = "The CIDR block of the VPC. (NIST 800-53: CM-2, CM-8, SC-7)"
  value       = aws_vpc.this.cidr_block
}

output "vpc_main_route_table_id" {
  description = "The ID of the main route table associated with this VPC. (NIST 800-53: CM-2, CM-8, SC-7)"
  value       = aws_vpc.this.main_route_table_id
}

output "vpc_default_network_acl_id" {
  description = "The ID of the network ACL created by default on VPC creation. (NIST 800-53: AC-4, SC-7)"
  value       = aws_vpc.this.default_network_acl_id
}

output "vpc_default_security_group_id" {
  description = "The ID of the security group created by default on VPC creation. (NIST 800-53: AC-4, SC-7)"
  value       = aws_vpc.this.default_security_group_id
}

# Subnet Outputs
output "public_subnets" {
  description = "List of IDs of public subnets. (NIST 800-53: CM-8, SC-7)"
  value       = aws_subnet.public[*].id
}

output "public_subnet_arns" {
  description = "List of ARNs of public subnets. (NIST 800-53: CM-8)"
  value       = aws_subnet.public[*].arn
}

output "public_subnets_cidr_blocks" {
  description = "List of CIDR blocks of public subnets. (NIST 800-53: CM-8, SC-7)"
  value       = aws_subnet.public[*].cidr_block
}

output "private_subnets" {
  description = "List of IDs of private subnets. (NIST 800-53: CM-8, SC-7)"
  value       = aws_subnet.private[*].id
}

output "private_subnet_arns" {
  description = "List of ARNs of private subnets. (NIST 800-53: CM-8)"
  value       = aws_subnet.private[*].arn
}

output "private_subnets_cidr_blocks" {
  description = "List of CIDR blocks of private subnets. (NIST 800-53: CM-8, SC-7)"
  value       = aws_subnet.private[*].cidr_block
}

# Route Table Outputs
output "public_route_table_ids" {
  description = "List of IDs of public route tables. (NIST 800-53: CM-8, SC-7)"
  value       = [aws_route_table.public.id]
}

output "private_route_table_ids" {
  description = "List of IDs of private route tables. (NIST 800-53: CM-8, SC-7)"
  value       = aws_route_table.private[*].id
}

output "public_route_table_association_ids" {
  description = "List of IDs of the public route table associations. (NIST 800-53: CM-8)"
  value       = aws_route_table_association.public[*].id
}

output "private_route_table_association_ids" {
  description = "List of IDs of the private route table associations. (NIST 800-53: CM-8)"
  value       = aws_route_table_association.private[*].id
}

# NAT Gateway Outputs
output "nat_public_ips" {
  description = "List of public Elastic IPs created for AWS NAT Gateway. (NIST 800-53: AC-4, SC-7)"
  value       = aws_eip.nat[*].public_ip
}

output "natgw_ids" {
  description = "List of NAT Gateway IDs. (NIST 800-53: AC-4, SC-7)"
  value       = aws_nat_gateway.this[*].id
}

# Internet Gateway Outputs
output "igw_id" {
  description = "The ID of the Internet Gateway. (NIST 800-53: AC-4, SC-7)"
  value       = aws_internet_gateway.this.id
}

output "igw_arn" {
  description = "The ARN of the Internet Gateway. (NIST 800-53: CM-8)"
  value       = aws_internet_gateway.this.arn
}

# Flow Logs Outputs
output "vpc_flow_log_id" {
  description = "The ID of the Flow Log resource. (NIST 800-53: AU-2, AU-6, AU-12, SI-4)"
  value       = var.enable_flow_logs ? aws_flow_log.this[0].id : null
}

output "vpc_flow_log_cloudwatch_log_group_arn" {
  description = "The ARN of the CloudWatch Logs log group for VPC Flow Logs. (NIST 800-53: AU-2, AU-6, AU-12, SI-4)"
  value       = var.enable_flow_logs ? aws_cloudwatch_log_group.flow_log[0].arn : null
}

output "vpc_flow_log_iam_role_arn" {
  description = "The ARN of the IAM role used for pushing VPC Flow Logs to CloudWatch. (NIST 800-53: AC-3, IA-2, IA-5)"
  value       = var.enable_flow_logs ? aws_iam_role.vpc_flow_log[0].arn : null
}

# Security Outputs
output "default_network_acl_id" {
  description = "The ID of the default network ACL. (NIST 800-53: AC-4, SC-7)"
  value       = aws_vpc.this.default_network_acl_id
}

output "default_security_group_id" {
  description = "The ID of the default security group. (NIST 800-53: AC-4, SC-7)"
  value       = aws_vpc.this.default_security_group_id
}

# AZs and Subnets Mapping
output "azs" {
  description = "A list of availability zones specified as argument to this module. (NIST 800-53: CP-10, SC-7)"
  value       = local.azs
}

output "public_subnet_azs" {
  description = "A list of availability zones for public subnets. (NIST 800-53: CP-10, SC-7)"
  value       = aws_subnet.public[*].availability_zone
}

output "private_subnet_azs" {
  description = "A list of availability zones for private subnets. (NIST 800-53: CP-10, SC-7)"
  value       = aws_subnet.private[*].availability_zone
}

# Network ACL Outputs
output "default_network_acl_id_arn" {
  description = "The ARN of the default network ACL. (NIST 800-53: CM-8)"
  value       = var.enable_network_acl ? aws_default_network_acl.this[0].arn : null
}

# Additional Security Outputs
output "default_security_group_arn" {
  description = "The ARN of the default security group. (NIST 800-53: CM-8)"
  value       = aws_default_security_group.this.arn
}

output "vpc_enable_dns_hostnames" {
  description = "Whether or not the VPC has DNS hostname support. (NIST 800-53: CM-6, SC-7)"
  value       = aws_vpc.this.enable_dns_hostnames
}

output "vpc_enable_dns_support" {
  description = "Whether or not the VPC has DNS support. (NIST 800-53: CM-6, SC-7)"
  value       = aws_vpc.this.enable_dns_support
}
