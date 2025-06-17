import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { securityGroupTool } from './tools/security-groups.js';
import { publicInstanceTool } from './tools/public-instances.js';

class AWSInfraSecMCPServer {
  private server: Server;

  constructor() {
    this.server = new Server(
      {
        name: 'aws-infrasec-mcp-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
    this.setupErrorHandling();
  }

  private setupToolHandlers(): void {
    // Register available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: securityGroupTool.name,
            description: securityGroupTool.description,
            inputSchema: securityGroupTool.inputSchema,
          },
          {
            name: publicInstanceTool.name,
            description: publicInstanceTool.description,
            inputSchema: publicInstanceTool.inputSchema,
          },
        ],
      };
    });

    // Handle tool execution
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case securityGroupTool.name:
            const sgResult = await securityGroupTool.execute(args);
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(sgResult, null, 2),
                },
              ],
            };

          case publicInstanceTool.name:
            const piResult = await publicInstanceTool.execute(args);
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(piResult, null, 2),
                },
              ],
            };

          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${name}`
            );
        }
      } catch (error) {
        // Handle different types of errors
        if (error instanceof McpError) {
          throw error;
        }

        // Handle AWS SDK errors
        if (error instanceof Error) {
          if (error.name === 'UnauthorizedOperation') {
            throw new McpError(
              ErrorCode.InvalidRequest,
              `AWS Permission Denied: ${error.message}. Please check your AWS credentials and IAM permissions.`
            );
          }
          
          if (error.name === 'InvalidUserID.NotFound' || error.name === 'InvalidGroupId.NotFound') {
            throw new McpError(
              ErrorCode.InvalidRequest,
              `AWS Resource Not Found: ${error.message}`
            );
          }

          if (error.name === 'NetworkingError' || error.name === 'TimeoutError') {
            throw new McpError(
              ErrorCode.InternalError,
              `AWS Connection Error: ${error.message}. Please check your network connection and AWS region.`
            );
          }

          // Generic error handling
          throw new McpError(
            ErrorCode.InternalError,
            `Tool execution failed: ${error.message}`
          );
        }

        // Unknown error
        throw new McpError(
          ErrorCode.InternalError,
          'An unexpected error occurred during tool execution'
        );
      }
    });
  }

  private setupErrorHandling(): void {
    // Handle uncaught errors
    process.on('uncaughtException', (error) => {
      console.error('Uncaught Exception:', error);
      process.exit(1);
    });

    process.on('unhandledRejection', (reason, promise) => {
      console.error('Unhandled Rejection at:', promise, 'reason:', reason);
      process.exit(1);
    });
  }

  async run(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);

    // Log server start (only to stderr to avoid interfering with MCP protocol)
    console.error('AWS Infrastructure Security MCP Server started successfully');
    console.error('Available tools:');
    console.error('  - analyze_security_groups: Analyze AWS Security Groups for misconfigurations');
    console.error('  - scan_public_instances: Scan EC2 instances for public exposure risks');
  }
}

// Main execution
async function main(): Promise<void> {
  try {
    // Validate required environment variables
    const requiredEnvVars = ['AWS_REGION'];
    const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);
    
    if (missingEnvVars.length > 0) {
      console.error('Missing required environment variables:', missingEnvVars.join(', '));
      console.error('Please set the following environment variables:');
      console.error('  - AWS_REGION: AWS region to use (e.g., us-east-1)');
      console.error('  - AWS_ACCESS_KEY_ID: AWS access key (or use AWS profile)');
      console.error('  - AWS_SECRET_ACCESS_KEY: AWS secret key (or use AWS profile)');
      console.error('  - AWS_PROFILE: AWS profile name (alternative to access keys)');
      process.exit(1);
    }

    const server = new AWSInfraSecMCPServer();
    await server.run();
  } catch (error) {
    console.error('Failed to start AWS Infrastructure Security MCP Server:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.error('Received SIGINT, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.error('Received SIGTERM, shutting down gracefully...');
  process.exit(0);
});

// Run the server
if (require.main === module) {
  main().catch((error) => {
    console.error('Server startup failed:', error);
    process.exit(1);
  });
}

export { AWSInfraSecMCPServer };