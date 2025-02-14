# AWS Security Group Dependency Analyzer

A Python tool to analyze AWS security group dependencies and identify obsolete or unused security groups across multiple AWS services.

## ⚠️ Disclaimer

**USE AT YOUR OWN RISK**. This tool is provided "as is", without warranty of any kind, express or implied. Neither the authors nor contributors shall be liable for any damages or consequences arising from the use of this tool. Always:
- Test in a non-production environment first
- Verify results manually before taking action
- Maintain proper backups
- Follow your organization's security policies

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
   cd AWS-Security-Group-Dependency-Analyzer
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure AWS Authentication:

   There are several ways to authenticate with AWS:

   ### Option 1: AWS SSO with Config File
   Use this method if your organization uses AWS SSO. Set up in `~/.aws/config`:
   ```ini
   [profile my-sso-profile]
   sso_start_url = https://my-sso-portal.awsapps.com/start
   sso_region = eu-central-1
   sso_account_id = 123456789012
   sso_role_name = MyRole
   region = eu-central-1
   output = json
   ```

   Then authenticate:
   ```bash
   # Set your AWS profile and authenticate
   export AWS_PROFILE=my-sso-profile
   
   # Verify authentication or trigger SSO login if needed
   aws sts get-caller-identity --profile $AWS_PROFILE > /dev/null 2>&1 || aws sso login --profile $AWS_PROFILE
   ```

   ### Option 2: Access Keys with Credentials File
   Use this method if you have AWS access keys. Set up in `~/.aws/credentials`:
   ```ini
   [my-profile]
   aws_access_key_id = <your_access_key>
   aws_secret_access_key = <your_secret_key>
   ```

   Then simply use:
   ```bash
   export AWS_PROFILE=my-profile
   ```

   ### Option 3: Environment Variables
   Direct environment variable setup:
   ```bash
   export AWS_ACCESS_KEY_ID=<your_access_key>
   export AWS_SECRET_ACCESS_KEY=<your_secret_key>
   export AWS_DEFAULT_REGION=eu-central-1
   ```

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
- Development assisted by Claude (Anthropic), showcasing the potential of human-AI collaboration in creating robust, production-ready tools
- Original concept based on legacy AWS security group analysis tools
