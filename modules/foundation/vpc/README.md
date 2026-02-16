# VPC Module

This module creates a production-ready VPC with public and private subnets across multiple availability zones.

## Features

- Configurable number of AZs (up to 3 for high availability)
- Public and private subnets in each AZ
- NAT Gateways (one per AZ or shared)
- Internet Gateway for public subnets
- Route tables for public and private subnets
- VPC Flow Logs with CloudWatch Logs integration
- Configurable CIDR blocks and naming

## Usage

```hcl
module "vpc" {
  source = "git::https://github.com/your-org/terraform-jumpstart-aws.git//modules/foundation/vpc?ref=v1.0.0"

  name               = "production"
  cidr               = "10.0.0.0/16"
  azs                = ["us-west-2a", "us-west-2b", "us-west-2c"]
  private_subnets    = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  enable_nat_gateway = true
  single_nat_gateway = false
  
  tags = {
    Environment = "production"
    Terraform   = "true"
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
| name | Name to be used on all resources as identifier | string | - | yes |
| cidr | The CIDR block for the VPC | string | - | yes |
| azs | A list of availability zones in the region | list(string) | [] | no |
| public_subnets | A list of public subnets inside the VPC | list(string) | [] | no |
| private_subnets | A list of private subnets inside the VPC | list(string) | [] | no |
| enable_nat_gateway | Should be true if you want to provision NAT Gateways for your private subnets | bool | true | no |
| single_nat_gateway | Should be true if you want to provision a single shared NAT Gateway across all private subnets | bool | false | no |
| tags | A map of tags to add to all resources | map(string) | {} | no |

## Outputs

| Name | Description |
|------|-------------|
| vpc_id | The ID of the VPC |
| vpc_cidr_block | The CIDR block of the VPC |
| public_subnets | List of IDs of public subnets |
| private_subnets | List of IDs of private subnets |
| public_route_table_ids | List of IDs of public route tables |
| private_route_table_ids | List of IDs of private route tables |
| nat_public_ips | List of public Elastic IPs created for AWS NAT Gateway |
| igw_id | The ID of the Internet Gateway |
| natgw_ids | List of NAT Gateway IDs |

## License

[Specify your license here]
