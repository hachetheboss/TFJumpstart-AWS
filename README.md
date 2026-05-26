# TFJumpstart-AWS

A collection of reusable, production-grade Terraform modules and blueprints for AWS cloud infrastructure with NIST 800-53 compliance.

## Structure

- `modules/`: Reusable, atomic building blocks for AWS infrastructure
  - `foundation/`: Core infrastructure components (VPC, networking, etc.)
    - `vpc/`: Secure VPC module with NIST 800-53 compliance
    - `secure-foundation/`: Security baseline configurations
  - `security/`: Security-focused modules
    - `iam-factory/`: NIST 800-53 compliant IAM resource factory
- `blueprints/`: Ready-to-deploy solutions combining multiple modules
- `examples/`: Minimal examples showing how to use individual modules
- `tests/`: Test configurations and test cases ttddxvdavbsackjb

## Getting Started

1. Clone this repository
2. Navigate to the desired module or blueprint
3. Follow the specific README instructions for that component

## Requirements

- Terraform >= 1.0
- AWS CLI configured with appropriate credentials
- AWS account with necessary permissions

## Usage

See individual module/blueprint documentation for specific usage instructions.

### Example: Using the IAM Factory Module

```hcl
module "iam_factory" {
  source = "./modules/security/iam-factory"
  
  environment = "prod"
  data_classification = "confidential"
  default_owner_contact = "security@example.com"
  
  # Enable security features
  enable_password_policy = true
  enable_mfa_enforcement = true
  enable_access_key_rotation = true
}
```

## NIST 800-53 Compliance

This repository includes modules that help implement NIST 800-53 controls, including but not limited to:

- **Access Control (AC)**: AC-2, AC-3, AC-5, AC-6, AC-17
- **Identification and Authentication (IA)**: IA-2, IA-4, IA-5, IA-6, IA-7
- **Audit and Accountability (AU)**: AU-2, AU-3, AU-6, AU-12
- **System and Communications Protection (SC)**: SC-7, SC-12, SC-28
- **System and Information Integrity (SI)**: SI-4, SI-7

## Contributing

Contributions are welcome! Please see CONTRIBUTING.md for guidelines.

## License

[Specify your license here]
