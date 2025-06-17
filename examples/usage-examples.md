# AWS Infrastructure Security MCP Server - Usage Examples

This document provides practical examples of how to use the AWS Infrastructure Security MCP Server tools.

## Prerequisites Setup

Before running these examples, ensure you have:

1. **AWS Credentials Configured**
```bash
# Option 1: Environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1

# Option 2: AWS Profile
export AWS_PROFILE=your-profile-name
export AWS_REGION=us-east-1
```

2. **MCP Server Running**
```bash
npm install
npm run build
npm start
```

## Tool Usage Examples

### 1. Security Group Analysis

#### Example 1: Analyze All Security Groups in Region
```bash
# Input
{
  "region": "us-east-1",
  "includeUnused": true
}
```

**Expected Output:**
```json
{
  "analysisType": "Security Group Analysis",
  "region": "us-east-1",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "summary": {
    "totalGroups": 8,
    "highRiskFindings": 3,
    "mediumRiskFindings": 2,
    "lowRiskFindings": 1,
    "riskDistribution": {
      "high": "3 findings",
      "medium": "2 findings", 
      "low": "1 findings"
    }
  },
  "findings": [
    {
      "securityGroup": {
        "id": "sg-0123456789abcdef0",
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
    },
    {
      "securityGroup": {
        "id": "sg-0987654321fedcba0",
        "name": "database-sg"
      },
      "issue": {
        "type": "sg-mysql-exposed",
        "severity": "HIGH", 
        "description": "MySQL port 3306 is accessible from the internet",
        "recommendation": "Place MySQL in private subnet and restrict access through application servers"
      },
      "affectedRule": {
        "port": 3306,
        "protocol": "tcp",
        "source": "0.0.0.0/0"
      }
    }
  ],
  "recommendations": [
    "🚨 Address 3 HIGH severity findings immediately",
    "🔒 Implement principle of least privilege for security group rules",
    "🛡️ Use specific IP ranges instead of 0.0.0.0/0 where possible",
    "🔍 Regular security group audits should be performed"
  ]
}
```

#### Example 2: Analyze Specific Security Groups
```bash
# Input
{
  "region": "us-west-2",
  "groupIds": ["sg-0123456789abcdef0", "sg-0987654321fedcba0"],
  "includeUnused": false
}
```

### 2. Public Instance Scanning

#### Example 1: Scan All Public Instances
```bash
# Input
{
  "region": "us-east-1",
  "includeSecurityGroups": true
}
```

**Expected Output:**
```json
{
  "analysisType": "Public Instance Analysis",
  "region": "us-east-1",
  "timestamp": "2024-01-15T10:35:00.000Z",
  "summary": {
    "totalInstances": 12,
    "publicInstances": 4,
    "exposedPorts": 15,
    "publicExposureRate": "33%",
    "averageExposedPorts": 4
  },
  "publicInstances": [
    {
      "instance": {
        "id": "i-0123456789abcdef0",
        "publicIp": "54.123.45.67",
        "riskLevel": "HIGH"
      },
      "security": {
        "associatedSecurityGroups": ["sg-0123456789abcdef0", "sg-0987654321fedcba0"],
        "exposedPorts": [22, 80, 443, 3306],
        "portCount": 4,
        "criticalPortsExposed": [
          {"port": 22, "service": "SSH"},
          {"port": 3306, "service": "MySQL"}
        ]
      },
      "recommendations": [
        "Restrict access to dangerous ports: 22, 3306",
        "Use Application Load Balancer or NAT Gateway for controlled access",
        "Consider moving to private subnet with VPN access"
      ]
    },
    {
      "instance": {
        "id": "i-0987654321fedcba0", 
        "publicIp": "54.234.56.78",
        "riskLevel": "MEDIUM"
      },
      "security": {
        "associatedSecurityGroups": ["sg-web-public"],
        "exposedPorts": [80, 443, 8080, 8443, 9000, 9001],
        "portCount": 6,
        "criticalPortsExposed": []
      },
      "recommendations": [
        "Consider reducing the number of exposed ports",
        "Use Application Load Balancer or NAT Gateway for controlled access"
      ]
    }
  ],
  "riskAssessment": {
    "overallRisk": "HIGH",
    "distribution": {
      "high": 1,
      "medium": 2,
      "low": 1
    },
    "criticalFindings": 2
  },
  "overallRecommendations": [
    "🚨 1 high-risk public instances require immediate attention",
    "🛡️ Consider moving critical services to private subnets",
    "🔒 Implement bastion hosts or VPN for administrative access",
    "⚠️ 15 ports exposed across all public instances",
    "🔧 Use Application Load Balancers to reduce direct instance exposure"
  ]
}
```

#### Example 2: Quick Scan Without Security Group Details
```bash
# Input
{
  "region": "eu-west-1",
  "includeSecurityGroups": false
}
```

## Common Scenarios and Interpretations

### Scenario 1: Web Application Environment
**Typical Findings:**
- SSH open to world (HIGH severity)
- HTTP/HTTPS publicly accessible (expected, LOW severity)
- Application ports exposed (MEDIUM severity)

**Interpretation:**
- SSH access should be restricted to admin IP ranges
- Web ports (80/443) are acceptable for public web servers
- Application-specific ports should be behind load balancers

### Scenario 2: Database Environment
**Typical Findings:**
- Database ports exposed to internet (HIGH severity)
- Management ports accessible (HIGH severity)
- Unused security groups (LOW severity)

**Interpretation:**
- Databases should never be directly accessible from internet
- Move to private subnets with application-tier access only
- Clean up unused security groups

### Scenario 3: Development Environment
**Typical Findings:**
- Multiple services exposed for testing (MEDIUM severity)
- Wide port ranges opened (MEDIUM severity)
- Development instances publicly accessible (MEDIUM-HIGH severity)

**Interpretation:**
- Development environments often have relaxed security
- Consider using VPN or IP restrictions for dev access
- Implement separate security policies for dev vs prod

## Integration Examples

### Example: Using with Claude Desktop

1. **Configure MCP Server**
```json
{
  "mcpServers": {
    "aws-infrasec": {
      "command": "node",
      "args": ["/path/to/aws-infrasec-mcp-server/build/index.js"],
      "env": {
        "AWS_REGION": "us-east-1",
        "AWS_PROFILE": "infrasec-demo"
      }
    }
  }
}
```

2. **Ask Claude to Analyze Your Infrastructure**
```
"Please analyze my AWS security groups for potential vulnerabilities in the us-east-1 region"
```

3. **Follow-up with Public Instance Analysis**
```
"Now scan for any EC2 instances that might be publicly exposed in the same region"
```

### Example: Automated Security Assessment

Create a script that runs both tools and generates a comprehensive report:

```bash
#!/bin/bash
echo "Starting AWS Infrastructure Security Assessment..."

# Run security group analysis
echo "Analyzing Security Groups..."
curl -X POST http://localhost:3000/analyze_security_groups \
  -H "Content-Type: application/json" \
  -d '{"region": "us-east-1"}' \
  > security-groups-report.json

# Run public instance scan
echo "Scanning Public Instances..."
curl -X POST http://localhost:3000/scan_public_instances \
  -H "Content-Type: application/json" \
  -d '{"region": "us-east-1"}' \
  > public-instances-report.json

echo "Assessment complete. Check report files."
```

## Troubleshooting Examples

### Issue: Permission Denied
```json
{
  "error": "AWS Permission Denied: UnauthorizedOperation: You are not authorized to perform this operation."
}
```

**Solution:**
- Verify IAM permissions include required EC2 describe actions
- Check AWS credentials are correctly configured
- Ensure the region is accessible with your credentials

### Issue: Invalid Security Group ID
```json
{
  "error": "AWS Resource Not Found: The security group 'sg-invalid123' does not exist"
}
```

**Solution:**
- Verify security group IDs are correct
- Check that security groups exist in the specified region
- Ensure proper region configuration

### Issue: No Public Instances Found
```json
{
  "summary": {
    "totalInstances": 5,
    "publicInstances": 0,
    "exposedPorts": 0
  }
}
```

**Interpretation:**
- All instances are in private subnets (good security posture)
- Or instances are stopped/terminated
- Or instances use NAT Gateway/Load Balancer (recommended architecture)

## Best Practices for Usage

1. **Regular Assessment Schedule**
   - Run security group analysis weekly
   - Scan public instances after any infrastructure changes
   - Review findings during security reviews

2. **Prioritization Strategy**
   - Address HIGH severity findings immediately
   - Plan MEDIUM severity fixes within sprint cycles
   - Review LOW severity findings during maintenance windows

3. **Documentation**
   - Keep records of findings and remediation actions
   - Track improvement trends over time
   - Use findings to improve IaC templates

4. **Integration with CI/CD**
   - Include security checks in deployment pipelines
   - Fail builds on HIGH severity findings
   - Generate security reports for each environment

This completes the usage examples for the AWS Infrastructure Security MCP Server.