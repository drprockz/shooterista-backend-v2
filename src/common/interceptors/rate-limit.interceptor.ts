import { Injectable, NestInterceptor, ExecutionContext, CallHandler, HttpException, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Observable } from 'rxjs';
import { Redis } from 'ioredis';

@Injectable()
export class RateLimitInterceptor implements NestInterceptor {
  private redis: Redis;

  constructor(private readonly configService: ConfigService) {
    this.redis = new Redis(this.configService.get<string>('app.REDIS_URL'));
  }

  async intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<any>> {
    // Handle both HTTP and GraphQL contexts
    let request: any;
    let response: any;
    
    try {
      const httpContext = context.switchToHttp();
      request = httpContext.getRequest();
      response = httpContext.getResponse();
    } catch (error) {
      // For GraphQL context, get request from context
      const gqlContext = context.getArgs()[2];
      request = gqlContext?.req || gqlContext?.request || {};
      response = gqlContext?.res || gqlContext?.response || {};
    }

    const key = this.getKey(request);
    const limit = this.configService.get<number>('app.RATE_LIMIT_LIMIT');
    const ttl = this.configService.get<number>('app.RATE_LIMIT_TTL');

    const current = await this.redis.incr(key);
    
    if (current === 1) {
      await this.redis.expire(key, ttl);
    }

    if (current > limit) {
      const remaining = await this.redis.ttl(key);
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          message: 'Rate limit exceeded',
          retryAfter: remaining,
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    // Set rate limit headers
    if (request) {
      request.rateLimit = {
        limit,
        current,
        remaining: Math.max(0, limit - current),
      };
    }

    return next.handle();
  }

  private getKey(request: any): string {
    const ip = request.ip || request.connection?.remoteAddress || request.headers?.['x-forwarded-for'] || 'unknown';
    const userId = request.user?.id || 'anonymous';
    return `rate_limit:${ip}:${userId}`;
  }
}
