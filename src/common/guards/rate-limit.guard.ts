import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { Reflector } from '@nestjs/core';
import { RateLimitService } from '../../modules/auth/services/rate-limit.service';

export interface RateLimitConfig {
  type: string;
  identifier?: string; // If not provided, will use user email or IP
}

@Injectable()
export class RateLimitGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly rateLimitService: RateLimitService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const ctx = GqlExecutionContext.create(context);
    const request = ctx.getContext().req;
    
    const config = this.reflector.get<RateLimitConfig>('rateLimit', context.getHandler());
    
    if (!config) {
      return true; // No rate limiting required
    }

    const ipAddress = request.ip;
    const userAgent = request.headers['user-agent'];
    
    // Determine identifier for rate limiting
    let identifier: string;
    if (config.identifier) {
      identifier = config.identifier;
    } else if (request.user?.email) {
      identifier = request.user.email;
    } else {
      identifier = ipAddress || 'unknown';
    }

    const rateLimit = await this.rateLimitService.checkRateLimit(
      config.type,
      identifier,
      ipAddress,
    );

    if (!rateLimit.allowed) {
      throw new ForbiddenException(
        `Rate limit exceeded. Please try again in ${Math.ceil((rateLimit.resetTime.getTime() - Date.now()) / 1000)} seconds.`
      );
    }

    return true;
  }
}
