import { EC2Client, EC2ClientConfig } from '@aws-sdk/client-ec2';

export interface AWSConfig {
  region?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  profile?: string;
}

export class AWSClientService {
  private ec2Client: EC2Client;

  constructor(config?: AWSConfig) {
    const clientConfig: EC2ClientConfig = {
      region: config?.region || process.env.AWS_REGION || 'us-east-1',
    };

    // Handle different credential scenarios
    if (config?.accessKeyId && config?.secretAccessKey) {
      clientConfig.credentials = {
        accessKeyId: config.accessKeyId,
        secretAccessKey: config.secretAccessKey,
      };
    } else if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
      clientConfig.credentials = {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      };
    }
    // If no explicit credentials, AWS SDK will use default credential chain
    // (profile, IAM role, etc.)

    this.ec2Client = new EC2Client(clientConfig);
  }

  getEC2Client(): EC2Client {
    return this.ec2Client;
  }

  getRegion(): string {
    return this.ec2Client.config.region?.toString() || 'us-east-1';
  }

  async testConnection(): Promise<boolean> {
    try {
      const { DescribeRegionsCommand } = await import('@aws-sdk/client-ec2');
      await this.ec2Client.send(new DescribeRegionsCommand({}));
      return true;
    } catch (error) {
      console.error('AWS connection test failed:', error);
      return false;
    }
  }
}

// Singleton instance for the application
let awsClientInstance: AWSClientService | null = null;

export function getAWSClient(config?: AWSConfig): AWSClientService {
  if (!awsClientInstance) {
    awsClientInstance = new AWSClientService(config);
  }
  return awsClientInstance;
}

export function resetAWSClient(): void {
  awsClientInstance = null;
}