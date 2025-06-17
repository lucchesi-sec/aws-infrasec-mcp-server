import { z } from 'zod';
import { getAWSClient } from '../services/aws-client.js';
import { SecurityAnalyzer } from '../services/analyzer.js';

// Input validation schema
const SecurityGroupAnalysisSchema = z.object({
  region: z.string().optional(),
  groupIds: z.array(z.string()).optional(),
  includeUnused: z.boolean().optional().default(true)
});

export type SecurityGroupAnalysisInput = z.infer<typeof SecurityGroupAnalysisSchema>;

export class SecurityGroupTool {
  name = 'analyze_security_groups';
  description = 'Analyze AWS Security Groups for potential security misconfigurations and vulnerabilities';

  inputSchema = {
    type: 'object',
    properties: {
      region: {
        type: 'string',
        description: 'AWS region to analyze (optional, defaults to configured region)',
        examples: ['us-east-1', 'us-west-2', 'eu-west-1']
      },
      groupIds: {
        type: 'array',
        items: { type: 'string' },
        description: 'Specific security group IDs to analyze (optional, analyzes all if not provided)',
        examples: [['sg-123456789abcdef0', 'sg-987654321fedcba0']]
      },
      includeUnused: {
        type: 'boolean',
        description: 'Whether to include analysis of unused security groups',
        default: true
      }
    },
    required: []
  } as const;

  async execute(input: unknown): Promise<any> {
    try {
      // Validate input
      const validatedInput = SecurityGroupAnalysisSchema.parse(input);
      
      // Get AWS client
      const awsClient = getAWSClient();
      const ec2Client = awsClient.getEC2Client();
      const region = validatedInput.region || awsClient.getRegion();

      // Test AWS connection
      const connectionTest = await awsClient.testConnection();
      if (!connectionTest) {
        throw new Error('Failed to connect to AWS. Please check your credentials and region configuration.');
      }

      // Initialize security analyzer
      const analyzer = new SecurityAnalyzer();

      // Perform security group analysis
      const analysisResult = await analyzer.analyzeSecurityGroups(
        ec2Client,
        region,
        validatedInput.groupIds
      );

      // Format results for better readability
      const formattedResult = {
        analysisType: 'Security Group Analysis',
        region: region,
        timestamp: new Date().toISOString(),
        summary: {
          ...analysisResult.summary,
          riskDistribution: {
            high: `${analysisResult.summary.highRiskFindings} findings`,
            medium: `${analysisResult.summary.mediumRiskFindings} findings`,
            low: `${analysisResult.summary.lowRiskFindings} findings`
          }
        },
        findings: analysisResult.findings.map(finding => ({
          securityGroup: {
            id: finding.securityGroupId,
            name: finding.securityGroupName
          },
          issue: {
            type: finding.ruleId,
            severity: finding.severity,
            description: finding.description,
            recommendation: finding.recommendation
          },
          affectedRule: finding.affectedRule ? {
            port: finding.affectedRule.port,
            protocol: finding.affectedRule.protocol,
            source: finding.affectedRule.source
          } : null
        })),
        recommendations: this.generateOverallRecommendations(analysisResult.findings)
      };

      return formattedResult;

    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new Error(`Input validation failed: ${error.errors.map(e => e.message).join(', ')}`);
      }
      
      if (error instanceof Error) {
        throw new Error(`Security group analysis failed: ${error.message}`);
      }
      
      throw new Error('An unexpected error occurred during security group analysis');
    }
  }

  private generateOverallRecommendations(findings: any[]): string[] {
    const recommendations: string[] = [];
    const highRiskCount = findings.filter(f => f.severity === 'HIGH').length;
    const mediumRiskCount = findings.filter(f => f.severity === 'MEDIUM').length;
    
    if (highRiskCount > 0) {
      recommendations.push(`🚨 Address ${highRiskCount} HIGH severity findings immediately`);
      recommendations.push('🔒 Implement principle of least privilege for security group rules');
      recommendations.push('🛡️ Use specific IP ranges instead of 0.0.0.0/0 where possible');
    }
    
    if (mediumRiskCount > 0) {
      recommendations.push(`⚠️ Review ${mediumRiskCount} MEDIUM severity findings`);
      recommendations.push('📋 Consider implementing a security group naming convention');
    }
    
    // General recommendations
    recommendations.push('🔍 Regular security group audits should be performed');
    recommendations.push('📊 Consider using AWS Config for continuous compliance monitoring');
    recommendations.push('🏗️ Implement Infrastructure as Code (IaC) for consistent security group management');
    
    return recommendations;
  }
}

// Export singleton instance
export const securityGroupTool = new SecurityGroupTool();