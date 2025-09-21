import { Controller, Get } from '@nestjs/common';
import { HealthCheck, HealthCheckService } from '@nestjs/terminus';
import { ConfigService } from '@nestjs/config';
import { ApiTags, ApiOperation, ApiResponse, ApiExcludeEndpoint } from '@nestjs/swagger';
import { DatabaseHealthIndicator } from './indicators/database.indicator';
import { RedisHealthIndicator } from './indicators/redis.indicator';
import { S3HealthIndicator } from './indicators/s3.indicator';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(
    private readonly health: HealthCheckService,
    private readonly configService: ConfigService,
    private readonly db: DatabaseHealthIndicator,
    private readonly redis: RedisHealthIndicator,
    private readonly s3: S3HealthIndicator,
  ) {}

  @Get()
  @HealthCheck()
  @ApiOperation({ 
    summary: 'Comprehensive health check',
    description: 'Performs health checks on all configured services (databases, Redis, S3)'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'All services are healthy',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', example: 'ok' },
        info: { type: 'object' },
        error: { type: 'object' },
        details: { type: 'object' }
      }
    }
  })
  @ApiResponse({ 
    status: 503, 
    description: 'One or more services are unhealthy',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', example: 'error' },
        info: { type: 'object' },
        error: { type: 'object' },
        details: { type: 'object' }
      }
    }
  })
  async check() {
    const checks = [];

    if (this.configService.get<boolean>('app.HEALTH_CHECK_DATABASE')) {
      // Only check auth database for now (others may not exist yet)
      checks.push(() => this.db.isHealthy('auth-database'));
    }

    if (this.configService.get<boolean>('app.HEALTH_CHECK_REDIS')) {
      checks.push(() => this.redis.isHealthy('redis'));
    }

    if (this.configService.get<boolean>('app.HEALTH_CHECK_S3')) {
      checks.push(() => this.s3.isHealthy('s3'));
    }

    try {
      return await this.health.check(checks);
    } catch (error) {
      // Return a more graceful error response
      return {
        status: 'error',
        info: {},
        error: {
          message: 'One or more health checks failed',
          details: error.message
        },
        details: {}
      };
    }
  }

  @Get('ready')
  @HealthCheck()
  @ApiOperation({ 
    summary: 'Readiness check',
    description: 'Checks if the application is ready to serve traffic (databases and Redis)'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Application is ready',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', example: 'ok' },
        info: { type: 'object' },
        error: { type: 'object' },
        details: { type: 'object' }
      }
    }
  })
  ready() {
    return this.health.check([
      () => this.db.isHealthy('auth-database'),
      () => this.redis.isHealthy('redis'),
    ]);
  }

  @Get('live')
  @ApiOperation({ 
    summary: 'Liveness check',
    description: 'Simple liveness check that returns basic application status'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Application is alive',
    schema: {
      type: 'object',
      properties: {
        data: {
          type: 'object',
          properties: {
            status: { type: 'string', example: 'ok' },
            timestamp: { type: 'string', format: 'date-time' },
            uptime: { type: 'number', description: 'Uptime in seconds' },
            version: { type: 'string', example: 'v1' },
            environment: { type: 'string', example: 'development' }
          }
        },
        meta: {
          type: 'object',
          properties: {
            timestamp: { type: 'string', format: 'date-time' },
            requestId: { type: 'string' },
            version: { type: 'string' }
          }
        }
      }
    }
  })
  live() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.API_VERSION || 'unknown',
      environment: process.env.NODE_ENV || 'unknown',
    };
  }
}
