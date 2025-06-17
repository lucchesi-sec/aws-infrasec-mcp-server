import { z } from 'zod';
import { getAWSClient } from '../services/aws-client.js';
import { SecurityAnalyzer } from '../services/analyzer.js';

// Input validation schema
const PublicInstanceAnalysisSchema = z.object({
  region: z.string().optional(),
  includeSecurityGroups: z.boolean().optional().default(true)
});

export type PublicInstanceAnalysisInput = z.infer<typeof PublicInstanceAnalysisSchema>;

export class PublicInstanceTool {
  name = 'scan_public_instances';
  description = 'Scan EC2 instances for public IP exposure and associated security risks';

  inputSchema = {
    type: 'object',
    properties: {
      region: {
        type: 'string',
        description: 'AWS region to scan (optional, defaults to configured region)',
        examples: ['us-east-1', 'us-west-2', 'eu-west-1']
      },
      includeSecurityGroups: {
        type: 'boolean',
        description: 'Whether to include security group analysis for public instances',
        default: true
      }
    },
    required: []
  } as const;

  async execute(input: unknown): Promise<any> {
    try {
      // Validate input
      const validatedInput = PublicInstanceAnalysisSchema.parse(input);
      
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

      // Perform public instance analysis
      const analysisResult = await analyzer.analyzePublicInstances(ec2Client, region);

      // Format results for better readability
      const formattedResult = {
        analysisType: 'Public Instance Analysis',
        region: region,
        timestamp: new Date().toISOString(),
        summary: {
          ...analysisResult.summary,
          publicExposureRate: analysisResult.summary.totalInstances > 0 
            ? `${Math.round((analysisResult.summary.publicInstances / analysisResult.summary.totalInstances) * 100)}%`
            : '0%',
          averageExposedPorts: analysisResult.summary.publicInstances > 0
            ? Math.round(analysisResult.summary.exposedPorts / analysisResult.summary.publicInstances)
            : 0
        },
        publicInstances: analysisResult.publicInstances.map(instance => ({
          instance: {
            id: instance.instanceId,
            publicIp: instance.publicIp,
            riskLevel: instance.riskLevel
          },
          security: {
            associatedSecurityGroups: instance.securityGroups,
            exposedPorts: instance.exposedPorts,
            portCount: instance.exposedPorts.length,
            criticalPortsExposed: this.getCriticalPorts(instance.exposedPorts)
          },
          recommendations: instance.recommendations
        })),
        riskAssessment: this.generateRiskAssessment(analysisResult.publicInstances),
        overallRecommendations: this.generateOverallRecommendations(analysisResult)
      };

      return formattedResult;

    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new Error(`Input validation failed: ${error.errors.map(e => e.message).join(', ')}`);
      }
      
      if (error instanceof Error) {
        throw new Error(`Public instance analysis failed: ${error.message}`);
      }
      
      throw new Error('An unexpected error occurred during public instance analysis');
    }
  }

  private getCriticalPorts(exposedPorts: number[]): Array<{port: number, service: string}> {
    const criticalPortMap: {[key: number]: string} = {
      22: 'SSH',
      3389: 'RDP', 
      3306: 'MySQL',
      5432: 'PostgreSQL',
      1433: 'SQL Server',
      6379: 'Redis',
      27017: 'MongoDB',
      5984: 'CouchDB'
    };

    return exposedPorts
      .filter(port => criticalPortMap[port])
      .map(port => ({ port, service: criticalPortMap[port] }));
  }

  private generateRiskAssessment(publicInstances: any[]): any {
    const highRiskInstances = publicInstances.filter(i => i.riskLevel === 'HIGH').length;
    const mediumRiskInstances = publicInstances.filter(i => i.riskLevel === 'MEDIUM').length;
    const lowRiskInstances = publicInstances.filter(i => i.riskLevel === 'LOW').length;

    let overallRisk: 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
    if (highRiskInstances > 0) {
      overallRisk = 'HIGH';
    } else if (mediumRiskInstances > 0) {
      overallRisk = 'MEDIUM';
    }

    return {
      overallRisk,
      distribution: {
        high: highRiskInstances,
        medium: mediumRiskInstances,
        low: lowRiskInstances
      },
      criticalFindings: publicInstances.reduce((acc, instance) => {
        const criticalPorts = this.getCriticalPorts(instance.exposedPorts);
        return acc + criticalPorts.length;
      }, 0)
    };
  }

  private generateOverallRecommendations(result: any): string[] {
    const recommendations: string[] = [];
    const { publicInstances, summary } = result;

    if (summary.publicInstances === 0) {
      recommendations.push('✅ No public instances detected - good security posture');
      recommendations.push('🔍 Continue regular monitoring for new public instances');
      return recommendations;
    }

    // Risk-based recommendations
    const highRiskInstances = publicInstances.filter((i: any) => i.riskLevel === 'HIGH').length;
    if (highRiskInstances > 0) {
      recommendations.push(`🚨 ${highRiskInstances} high-risk public instances require immediate attention`);
      recommendations.push('🛡️ Consider moving critical services to private subnets');
      recommendations.push('🔒 Implement bastion hosts or VPN for administrative access');
    }

    // Port-specific recommendations
    const totalExposedPorts = summary.exposedPorts;
    if (totalExposedPorts > 0) {
      recommendations.push(`⚠️ ${totalExposedPorts} ports exposed across all public instances`);
      recommendations.push('🔧 Use Application Load Balancers to reduce direct instance exposure');
      recommendations.push('🌍 Consider CloudFront for web applications');
    }

    // General security recommendations
    recommendations.push('🏗️ Implement Infrastructure as Code for consistent security configurations');
    recommendations.push('📊 Set up CloudWatch alerts for new public instance creation');
    recommendations.push('🔄 Regular security assessments should be automated');

    return recommendations;
  }
}

// Export singleton instance
export const publicInstanceTool = new PublicInstanceTool();