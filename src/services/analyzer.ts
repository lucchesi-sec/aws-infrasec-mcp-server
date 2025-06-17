import * as path from 'path';
import * as fs from 'fs';
import { 
  SecurityGroup, 
  IpPermission, 
  Instance,
  DescribeSecurityGroupsCommand,
  DescribeInstancesCommand,
  EC2Client 
} from '@aws-sdk/client-ec2';

export interface SecurityRule {
  id: string;
  name: string;
  description: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  port?: number;
  protocol?: string;
  source?: string;
  recommendation: string;
}

export interface SecurityFinding {
  securityGroupId: string;
  securityGroupName: string;
  ruleId: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  recommendation: string;
  affectedRule?: {
    port: number | string;
    protocol: string;
    source: string;
  };
}

export interface AnalysisResult {
  summary: {
    totalGroups: number;
    highRiskFindings: number;
    mediumRiskFindings: number;
    lowRiskFindings: number;
  };
  findings: SecurityFinding[];
}

export interface PublicInstanceResult {
  summary: {
    totalInstances: number;
    publicInstances: number;
    exposedPorts: number;
  };
  publicInstances: Array<{
    instanceId: string;
    publicIp: string;
    securityGroups: string[];
    exposedPorts: number[];
    riskLevel: 'HIGH' | 'MEDIUM' | 'LOW';
    recommendations: string[];
  }>;
}

export class SecurityAnalyzer {
  private rules: SecurityRule[] = [];

  constructor() {
    this.loadSecurityRules();
  }

  private loadSecurityRules(): void {
    try {
      const rulesPath = path.join(__dirname, '..', 'rules', 'security-rules.json');
      const rulesData = fs.readFileSync(rulesPath, 'utf8');
      const rulesConfig = JSON.parse(rulesData);
      this.rules = rulesConfig.rules;
    } catch (error) {
      console.error('Failed to load security rules:', error);
      this.rules = [];
    }
  }

  async analyzeSecurityGroups(
    ec2Client: EC2Client,
    region: string,
    groupIds?: string[]
  ): Promise<AnalysisResult> {
    try {
      const command = new DescribeSecurityGroupsCommand({
        GroupIds: groupIds
      });
      
      const response = await ec2Client.send(command);
      const securityGroups = response.SecurityGroups || [];

      const findings: SecurityFinding[] = [];

      for (const sg of securityGroups) {
        const sgFindings = this.analyzeSingleSecurityGroup(sg);
        findings.push(...sgFindings);
      }

      // Check for unused security groups
      const unusedFindings = await this.findUnusedSecurityGroups(ec2Client, securityGroups);
      findings.push(...unusedFindings);

      const summary = this.generateSummary(findings, securityGroups.length);

      return {
        summary,
        findings
      };
    } catch (error) {
      console.error('Error analyzing security groups:', error);
      throw new Error(`Security group analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private analyzeSingleSecurityGroup(sg: SecurityGroup): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const sgId = sg.GroupId || 'unknown';
    const sgName = sg.GroupName || 'unknown';

    if (!sg.IpPermissions) return findings;

    for (const permission of sg.IpPermissions) {
      // Check for dangerous open ports
      const dangerousPortFindings = this.checkDangerousPorts(permission, sgId, sgName);
      findings.push(...dangerousPortFindings);

      // Check for wide port ranges
      const wideRangeFindings = this.checkWidePortRanges(permission, sgId, sgName);
      findings.push(...wideRangeFindings);

      // Check for all traffic rules
      const allTrafficFindings = this.checkAllTrafficRules(permission, sgId, sgName);
      findings.push(...allTrafficFindings);
    }

    return findings;
  }

  private checkDangerousPorts(
    permission: IpPermission, 
    sgId: string, 
    sgName: string
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const fromPort = permission.FromPort;
    const toPort = permission.ToPort;
    const protocol = permission.IpProtocol || 'unknown';

    if (!permission.IpRanges) return findings;

    for (const ipRange of permission.IpRanges) {
      const cidr = ipRange.CidrIp;
      
      if (cidr === '0.0.0.0/0') {
        // Check against dangerous port rules
        const dangerousRules = this.rules.filter(rule => 
          rule.port !== undefined && 
          rule.source === '0.0.0.0/0' && 
          rule.protocol === protocol
        );

        for (const rule of dangerousRules) {
          if (fromPort !== undefined && toPort !== undefined && rule.port !== undefined) {
            if (fromPort <= rule.port && rule.port <= toPort) {
              findings.push({
                securityGroupId: sgId,
                securityGroupName: sgName,
                ruleId: rule.id,
                severity: rule.severity,
                description: rule.description,
                recommendation: rule.recommendation,
                affectedRule: {
                  port: rule.port,
                  protocol: protocol,
                  source: cidr
                }
              });
            }
          }
        }
      }
    }

    return findings;
  }

  private checkWidePortRanges(
    permission: IpPermission, 
    sgId: string, 
    sgName: string
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const fromPort = permission.FromPort;
    const toPort = permission.ToPort;

    if (fromPort !== undefined && toPort !== undefined) {
      const portRange = toPort - fromPort;
      
      if (portRange > 100) { // Arbitrary threshold for "wide" range
        const wideRangeRule = this.rules.find(rule => rule.id === 'sg-wide-port-range');
        if (wideRangeRule) {
          findings.push({
            securityGroupId: sgId,
            securityGroupName: sgName,
            ruleId: wideRangeRule.id,
            severity: wideRangeRule.severity,
            description: `${wideRangeRule.description} (${fromPort}-${toPort})`,
            recommendation: wideRangeRule.recommendation,
            affectedRule: {
              port: `${fromPort}-${toPort}`,
              protocol: permission.IpProtocol || 'unknown',
              source: permission.IpRanges?.[0]?.CidrIp || 'unknown'
            }
          });
        }
      }
    }

    return findings;
  }

  private checkAllTrafficRules(
    permission: IpPermission, 
    sgId: string, 
    sgName: string
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    
    if (permission.IpProtocol === '-1') { // All protocols
      const allTrafficRule = this.rules.find(rule => rule.id === 'sg-all-traffic');
      if (allTrafficRule && permission.IpRanges?.some(range => range.CidrIp === '0.0.0.0/0')) {
        findings.push({
          securityGroupId: sgId,
          securityGroupName: sgName,
          ruleId: allTrafficRule.id,
          severity: allTrafficRule.severity,
          description: allTrafficRule.description,
          recommendation: allTrafficRule.recommendation,
          affectedRule: {
            port: 'all',
            protocol: 'all',
            source: '0.0.0.0/0'
          }
        });
      }
    }

    return findings;
  }

  private async findUnusedSecurityGroups(
    ec2Client: EC2Client,
    securityGroups: SecurityGroup[]
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    
    try {
      // Get all instances to check security group usage
      const instancesCommand = new DescribeInstancesCommand({});
      const instancesResponse = await ec2Client.send(instancesCommand);
      
      const usedSecurityGroups = new Set<string>();
      
      if (instancesResponse.Reservations) {
        for (const reservation of instancesResponse.Reservations) {
          if (reservation.Instances) {
            for (const instance of reservation.Instances) {
              if (instance.SecurityGroups) {
                for (const sg of instance.SecurityGroups) {
                  if (sg.GroupId) {
                    usedSecurityGroups.add(sg.GroupId);
                  }
                }
              }
            }
          }
        }
      }

      const unusedRule = this.rules.find(rule => rule.id === 'sg-unused');
      if (unusedRule) {
        for (const sg of securityGroups) {
          if (sg.GroupId && !usedSecurityGroups.has(sg.GroupId) && sg.GroupName !== 'default') {
            findings.push({
              securityGroupId: sg.GroupId,
              securityGroupName: sg.GroupName || 'unknown',
              ruleId: unusedRule.id,
              severity: unusedRule.severity,
              description: unusedRule.description,
              recommendation: unusedRule.recommendation
            });
          }
        }
      }
    } catch (error) {
      console.error('Error checking for unused security groups:', error);
    }

    return findings;
  }

  async analyzePublicInstances(
    ec2Client: EC2Client,
    region: string
  ): Promise<PublicInstanceResult> {
    try {
      const command = new DescribeInstancesCommand({});
      const response = await ec2Client.send(command);
      
      const allInstances: Instance[] = [];
      const publicInstances: Array<{
        instanceId: string;
        publicIp: string;
        securityGroups: string[];
        exposedPorts: number[];
        riskLevel: 'HIGH' | 'MEDIUM' | 'LOW';
        recommendations: string[];
      }> = [];

      if (response.Reservations) {
        for (const reservation of response.Reservations) {
          if (reservation.Instances) {
            allInstances.push(...reservation.Instances);
          }
        }
      }

      for (const instance of allInstances) {
        if (instance.PublicIpAddress && instance.State?.Name === 'running') {
          const securityGroupIds = instance.SecurityGroups?.map(sg => sg.GroupId!).filter(Boolean) || [];
          const exposedPorts = await this.getExposedPorts(ec2Client, securityGroupIds);
          const riskLevel = this.assessInstanceRisk(exposedPorts);
          const recommendations = this.generateInstanceRecommendations(exposedPorts);

          publicInstances.push({
            instanceId: instance.InstanceId!,
            publicIp: instance.PublicIpAddress,
            securityGroups: securityGroupIds,
            exposedPorts,
            riskLevel,
            recommendations
          });
        }
      }

      const totalExposedPorts = publicInstances.reduce((sum, instance) => sum + instance.exposedPorts.length, 0);

      return {
        summary: {
          totalInstances: allInstances.length,
          publicInstances: publicInstances.length,
          exposedPorts: totalExposedPorts
        },
        publicInstances
      };
    } catch (error) {
      console.error('Error analyzing public instances:', error);
      throw new Error(`Public instance analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async getExposedPorts(ec2Client: EC2Client, securityGroupIds: string[]): Promise<number[]> {
    const exposedPorts: number[] = [];
    
    try {
      const command = new DescribeSecurityGroupsCommand({
        GroupIds: securityGroupIds
      });
      
      const response = await ec2Client.send(command);
      const securityGroups = response.SecurityGroups || [];

      for (const sg of securityGroups) {
        if (sg.IpPermissions) {
          for (const permission of sg.IpPermissions) {
            if (permission.IpRanges?.some(range => range.CidrIp === '0.0.0.0/0')) {
              if (permission.FromPort !== undefined && permission.ToPort !== undefined) {
                for (let port = permission.FromPort; port <= permission.ToPort; port++) {
                  if (!exposedPorts.includes(port)) {
                    exposedPorts.push(port);
                  }
                }
              }
            }
          }
        }
      }
    } catch (error) {
      console.error('Error getting exposed ports:', error);
    }

    return exposedPorts.sort((a, b) => a - b);
  }

  private assessInstanceRisk(exposedPorts: number[]): 'HIGH' | 'MEDIUM' | 'LOW' {
    const dangerousPorts = [22, 3389, 3306, 5432, 1433, 6379];
    const hasDangerousPorts = exposedPorts.some(port => dangerousPorts.includes(port));
    
    if (hasDangerousPorts) {
      return 'HIGH';
    } else if (exposedPorts.length > 5) {
      return 'MEDIUM';
    } else if (exposedPorts.length > 0) {
      return 'LOW';
    }
    
    return 'LOW';
  }

  private generateInstanceRecommendations(exposedPorts: number[]): string[] {
    const recommendations: string[] = [];
    const dangerousPorts = [22, 3389, 3306, 5432, 1433, 6379];
    
    const exposedDangerousPorts = exposedPorts.filter(port => dangerousPorts.includes(port));
    
    if (exposedDangerousPorts.length > 0) {
      recommendations.push(`Restrict access to dangerous ports: ${exposedDangerousPorts.join(', ')}`);
    }
    
    if (exposedPorts.length > 5) {
      recommendations.push('Consider reducing the number of exposed ports');
    }
    
    if (exposedPorts.length > 0) {
      recommendations.push('Use Application Load Balancer or NAT Gateway for controlled access');
      recommendations.push('Consider moving to private subnet with VPN access');
    }
    
    return recommendations;
  }

  private generateSummary(findings: SecurityFinding[], totalGroups: number) {
    return {
      totalGroups,
      highRiskFindings: findings.filter(f => f.severity === 'HIGH').length,
      mediumRiskFindings: findings.filter(f => f.severity === 'MEDIUM').length,
      lowRiskFindings: findings.filter(f => f.severity === 'LOW').length
    };
  }
}