# AWS Infrastructure Security MCP Server

[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/lucchesi-sec/aws-infrasec-mcp-server/graphs/commit-activity)
[![GitHub last commit](https://img.shields.io/github/last-commit/lucchesi-sec/aws-infrasec-mcp-server.svg)](https://github.com/lucchesi-sec/aws-infrasec-mcp-server/commits/main)
[![GitHub issues](https://img.shields.io/github/issues/lucchesi-sec/aws-infrasec-mcp-server.svg)](https://github.com/lucchesi-sec/aws-infrasec-mcp-server/issues)
[![GitHub forks](https://img.shields.io/github/forks/lucchesi-sec/aws-infrasec-mcp-server.svg)](https://github.com/lucchesi-sec/aws-infrasec-mcp-server/network/members)
[![GitHub stars](https://img.shields.io/github/stars/lucchesi-sec/aws-infrasec-mcp-server.svg)](https://github.com/lucchesi-sec/aws-infrasec-mcp-server/stargazers)
[![Made with TypeScript](https://img.shields.io/badge/Made%20with-TypeScript-1f425f.svg)](https://www.typescriptlang.org/)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A learning-focused Model Context Protocol (MCP) server that demonstrates AWS infrastructure security analysis capabilities. This project showcases MCP server development skills and AWS security knowledge for portfolio purposes.

## 🎯 Project Overview

This MCP server provides two core security analysis tools:
- **Security Group Analyzer**: Identifies misconfigurations in AWS Security Groups
- **Public Instance Scanner**: Analyzes EC2 instances for public exposure risks

Built with TypeScript and designed for educational purposes, this server demonstrates practical AWS security assessment capabilities while showcasing clean code architecture.

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- AWS CLI configured or AWS credentials
- TypeScript knowledge
- Basic understanding of AWS EC2 and Security Groups

### Installation

1. **Clone and Install Dependencies**
```bash
git clone <repository-url>
cd aws-infrasec-mcp-server
npm install
```

2. **Configure AWS Credentials**

Choose one of these methods:

**Option A: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID=your_access_key_id
export AWS_SECRET_ACCESS_KEY=your_secret_access_key
export AWS_REGION=us-east-1
```

**Option B: AWS Profile**
```bash
aws configure --profile infrasec-mcp
export AWS_PROFILE=infrasec-mcp
export AWS_REGION=us-east-1
```

**Option C: Create `.env` file**
```bash
cp .env.example .env
# Edit .env with your credentials
```

3. **Build the Project**
```bash
npm run build
```

4. **Test the Server**
```bash
npm start
```

## 🔧 MCP Client Configuration

### Claude Desktop Configuration

Add to your Claude Desktop configuration file:

```json
{
  "mcpServers": {
    "aws-infrasec": {
      "command": "node",
      "args": ["/path/to/aws-infrasec-mcp-server/build/index.js"],
      "env": {
        "AWS_REGION": "us-east-1",
        "AWS_ACCESS_KEY_ID": "your_access_key",
        "AWS_SECRET_ACCESS_KEY": "your_secret_key"
      }
    }
  }
}
```

### Using AWS Profile
```json
{
  "mcpServers": {
    "aws-infrasec": {
      "command": "node",
      "args": ["/path/to/aws-infrasec-mcp-server/build/index.js"],
      "env": {
        "AWS_PROFILE": "your-profile-name",
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

## 🛠️ Available Tools

### 1. Security Group Analyzer (`analyze_security_groups`)

Analyzes AWS Security Groups for common misconfigurations and security vulnerabilities.

**Input Parameters:**
- `region` (optional): AWS region to analyze
- `groupIds` (optional): Specific security group IDs to analyze
- `includeUnused` (optional): Include unused security groups analysis

**Example Usage:**
```bash
# Analyze all security groups in us-east-1
analyze_security_groups --region us-east-1

# Analyze specific security groups
analyze_security_groups --groupIds sg-123456789abcdef0,sg-987654321fedcba0

# Exclude unused security groups analysis
analyze_security_groups --includeUnused false
```

**Security Checks:**
- SSH (port 22) open to 0.0.0.0/0
- RDP (port 3389) open to 0.0.0.0/0
- Database ports (3306, 5432, 1433) exposed publicly
- Wide port ranges
- All traffic allowed rules
- Unused security groups

### 2. Public Instance Scanner (`scan_public_instances`)

Scans EC2 instances for public IP exposure and associated security risks.

**Input Parameters:**
- `region` (optional): AWS region to scan
- `includeSecurityGroups` (optional): Include security group analysis

**Example Usage:**
```bash
# Scan all public instances in us-east-1
scan_public_instances --region us-east-1

# Scan without security group analysis
scan_public_instances --includeSecurityGroups false
```

**Analysis Features:**
- Public IP detection
- Security group correlation
- Port exposure assessment
- Risk level calculation
- Actionable recommendations

## 🔒 AWS Permissions

### Required IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InfraSecMCPPermissions",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces"
      ],
      "Resource": "*"
    }
  ]
}
```

### Minimal Permissions Setup

1. Create IAM user or role
2. Attach the above policy
3. Generate access keys (for IAM user) or assign role (for EC2)

## 📊 Example Output

### Security Group Analysis
```json
{
  "analysisType": "Security Group Analysis",
  "region": "us-east-1",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "summary": {
    "totalGroups": 5,
    "highRiskFindings": 2,
    "mediumRiskFindings": 1,
    "lowRiskFindings": 0
  },
  "findings": [
    {
      "securityGroup": {
        "id": "sg-123456789abcdef0",
        "name": "web-server-sg"
      },
      "issue": {
        "type": "sg-ssh-world",
        "severity": "HIGH",
        "description": "SSH port 22 is accessible from anywhere (0.0.0.0/0)",
        "recommendation": "Restrict SSH access to specific IP ranges or use VPN/bastion host"
      },
      "affectedRule": {
        "port": 22,
        "protocol": "tcp",
        "source": "0.0.0.0/0"
      }
    }
  ]
}
```

### Public Instance Analysis
```json
{
  "analysisType": "Public Instance Analysis",
  "region": "us-east-1",
  "timestamp": "2024-01-15T10:35:00.000Z",
  "summary": {
    "totalInstances": 10,
    "publicInstances": 3,
    "exposedPorts": 8,
    "publicExposureRate": "30%"
  },
  "publicInstances": [
    {
      "instance": {
        "id": "i-0123456789abcdef0",
        "publicIp": "54.123.45.67",
        "riskLevel": "HIGH"
      },
      "security": {
        "associatedSecurityGroups": ["sg-123456789abcdef0"],
        "exposedPorts": [22, 80, 443],
        "criticalPortsExposed": [
          {"port": 22, "service": "SSH"}
        ]
      }
    }
  ]
}
```

## 🏗️ Project Structure

```
aws-infrasec-mcp-server/
├── src/
│   ├── index.ts                    # Main MCP server entry point
│   ├── tools/
│   │   ├── security-groups.ts      # Security group analysis tool
│   │   └── public-instances.ts     # Public instance scanning tool
│   ├── services/
│   │   ├── aws-client.ts           # AWS SDK client management
│   │   └── analyzer.ts             # Core security analysis logic
│   └── rules/
│       └── security-rules.json     # Security rule definitions
├── build/                          # Compiled TypeScript output
├── examples/
│   └── usage-examples.md           # Usage examples and demos
├── package.json                    # Project dependencies and scripts
├── tsconfig.json                   # TypeScript configuration
├── README.md                       # This file
└── .env.example                    # Environment variables template
```

## 🧪 Development

### Available Scripts
```bash
npm run build      # Compile TypeScript to JavaScript
npm run dev        # Run in development mode with ts-node
npm start          # Run compiled JavaScript
npm run clean      # Remove build directory
```

### Adding New Security Rules

Edit `src/rules/security-rules.json` to add new security rules:

```json
{
  "id": "your-rule-id",
  "name": "Rule Display Name",
  "description": "Rule description",
  "severity": "HIGH|MEDIUM|LOW",
  "port": 1234,
  "protocol": "tcp",
  "source": "0.0.0.0/0",
  "recommendation": "How to fix this issue"
}
```

## 🎓 Educational Value

This project demonstrates:

### Technical Skills
- **MCP Server Development**: Custom tools for AI workflows
- **AWS SDK Integration**: Production-ready cloud service integration
- **TypeScript Proficiency**: Type-safe, maintainable code
- **Error Handling**: Robust error management and user feedback
- **JSON Schema Validation**: Input validation and API design

### Security Knowledge
- **AWS Security Groups**: Understanding of network security fundamentals
- **Risk Assessment**: Ability to prioritize security findings
- **Best Practices**: Knowledge of AWS security best practices
- **Remediation Guidance**: Practical security improvement recommendations

### Software Engineering
- **Clean Architecture**: Separation of concerns and modularity
- **Documentation**: Comprehensive project documentation
- **Configuration Management**: Environment-based configuration
- **Testing Strategy**: Structure for comprehensive testing

## 🔍 Troubleshooting

### Common Issues

**1. AWS Authentication Errors**
```
Error: AWS Permission Denied
```
- Verify AWS credentials are configured correctly
- Check IAM permissions match required policy
- Ensure AWS region is set

**2. Network Connection Issues**
```
Error: AWS Connection Error
```
- Check internet connectivity
- Verify AWS region is accessible
- Check firewall settings

**3. TypeScript Compilation Errors**
```
Cannot find module '@aws-sdk/client-ec2'
```
- Run `npm install` to install dependencies
- Check Node.js version (requires 18+)

### Debug Mode

Enable detailed logging by setting:
```bash
export DEBUG=aws-infrasec-mcp-server
```

## 📋 TODO / Future Enhancements

- [ ] Add VPC configuration analysis
- [ ] Implement AWS Config integration
- [ ] Add compliance framework mapping (CIS, NIST)
- [ ] Create web dashboard for findings visualization
- [ ] Add cost optimization recommendations
- [ ] Implement automated remediation suggestions
- [ ] Add unit and integration tests
- [ ] Support for multiple AWS accounts
- [ ] CloudFormation/Terraform integration

## 📄 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

This is a learning/portfolio project, but suggestions and improvements are welcome! Please feel free to:
- Open issues for bugs or feature requests
- Submit pull requests for improvements
- Share feedback on code structure and best practices

## 🔗 Related Links

- [Model Context Protocol Documentation](https://modelcontextprotocol.io/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [AWS SDK for JavaScript v3](https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/)
- [TypeScript Documentation](https://www.typescriptlang.org/docs/)

---

**Note**: This project is designed for educational and portfolio purposes. Always follow your organization's security policies and best practices when using in production environments.