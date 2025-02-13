# AWS Security Group Dependency Analyzer

A Python tool to analyze AWS security group dependencies and identify obsolete or unused security groups across multiple AWS services.

## Features

- 🔍 Analyzes security group dependencies across multiple AWS services
- 🚫 Identifies obsolete security groups not in use
- 🔗 Maps relationships between security groups
- 🌐 Supports multiple AWS regions
- 🛡️ Identifies security groups used only by ENIs
- 📊 Provides detailed or list-based output formats
- 🧵 Multi-threaded for improved performance
- 📝 Comprehensive logging

## Supported Services

- EC2 (Elastic Compute Cloud)
- ELB (Elastic Load Balancer)
- RDS (Relational Database Service)
- Redshift
- ElastiCache
- ENI (Elastic Network Interface)

## Prerequisites

- Python 3.7 or higher
- AWS credentials configured
- Required Python packages:
  ```
  boto3>=1.26.0
  ```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/marc-poljak/AWS-Security-Group-Dependency-Analyzer.git
   cd aws-sg-analyzer
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure AWS credentials using one of these methods:
   - AWS CLI: `aws configure`
   - Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
   - IAM role attached to EC2 instance
   - Credentials file: `~/.aws/credentials`

## Usage

### Basic Usage

```bash
python3 aws-sg-audit.py --region REGION_NAME [options]
```

### Command Line Options

```
--region REGION_NAME    AWS region to analyze (required)
--list                 Show only group IDs and names
--obsolete            Show security groups not used by any service
--eni-only            Show security groups only used by ENIs
security_group        Security group ID or name (optional)
```

### Examples

1. Show all security groups in a region:
   ```bash
   python3 aws-sg-audit.py --region eu-central-1
   ```

2. List obsolete security groups:
   ```bash
   python3 aws-sg-audit.py --region eu-central-1 --obsolete
   ```

3. Check specific security group:
   ```bash
   python3 aws-sg-audit.py --region eu-central-1 sg-1234567890
   ```

4. Show ENI-only security groups:
   ```bash
   python3 aws-sg-audit.py --region eu-central-1 --eni-only
   ```

5. Show simplified list output:
   ```bash
   python3 aws-sg-audit.py --region eu-central-1 --list
   ```

## Output Format

### Detailed View
```
sg-1234567890 (my-security-group)
├── sg-abcdef123 (dependent-group-1)
│   └── sg-xyz789 (dependent-group-2)
└── sg-456uvw (dependent-group-3)

Used by:
  ec2: i-0123456789abcdef0 (my-instance)
  rds: my-database
```

### List View
```
sg-1234567890 (my-security-group)
sg-abcdef123 (dependent-group-1)
sg-xyz789 (dependent-group-2)
```

## Security Considerations

- The script requires read-only permissions to AWS services
- Recommended IAM policy:
  ```json
  {
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": [
                  "ec2:Describe*",
                  "elasticloadbalancing:Describe*",
                  "rds:Describe*",
                  "redshift:Describe*",
                  "elasticache:Describe*"
              ],
              "Resource": "*"
          }
      ]
  }
  ```

## Error Handling

The script includes comprehensive error handling for:
- Invalid regions
- Invalid credentials
- Network connectivity issues
- API throttling
- Invalid security group IDs

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built using the [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) AWS SDK
- Inspired by the need for better AWS security group management

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.