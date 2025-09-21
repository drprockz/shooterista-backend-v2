import { Injectable } from '@nestjs/common';
import { HealthIndicator, HealthIndicatorResult, HealthCheckError } from '@nestjs/terminus';
import { ConfigService } from '@nestjs/config';
import { Redis } from 'ioredis';

@Injectable()
export class RedisHealthIndicator extends HealthIndicator {
  private redis: Redis;

  constructor(private readonly configService: ConfigService) {
    super();
    this.redis = new Redis(this.configService.get<string>('app.REDIS_URL'));
  }

  async isHealthy(key: string): Promise<HealthIndicatorResult> {
    try {
      const result = await this.redis.ping();
      
      if (result === 'PONG') {
        return this.getStatus(key, true, {
          message: 'Redis connection is healthy',
        });
      }
      
      throw new Error('Redis ping failed');
    } catch (error) {
      const result = this.getStatus(key, false, {
        message: `Redis connection failed: ${error.message}`,
      });
      throw new HealthCheckError(`${key} failed`, result);
    }
  }
}
