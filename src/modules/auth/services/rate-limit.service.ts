import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaAuthService } from '../prisma-auth.service';

export interface RateLimitConfig {
  maxAttempts: number;
  windowMs: number;
  blockDurationMs: number;
}

@Injectable()
export class RateLimitService {
  private readonly logger = new Logger(RateLimitService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly prismaAuth: PrismaAuthService,
  ) {}

  private getRateLimitConfigs(): Record<string, RateLimitConfig> {
    return {
      login: {
        maxAttempts: parseInt(this.configService.get<string>('app.RATE_LIMIT_LOGIN_MAX', '5')),
        windowMs: parseInt(this.configService.get<string>('app.RATE_LIMIT_LOGIN_WINDOW', '900000')), // 15 minutes
        blockDurationMs: parseInt(this.configService.get<string>('app.RATE_LIMIT_LOGIN_BLOCK', '3600000')), // 1 hour
      },
      registration: {
        maxAttempts: parseInt(this.configService.get<string>('app.RATE_LIMIT_LOGIN_MAX', '5')), // Use same as login for now
        windowMs: parseInt(this.configService.get<string>('app.RATE_LIMIT_LOGIN_WINDOW', '900000')), // 15 minutes
        blockDurationMs: parseInt(this.configService.get<string>('app.RATE_LIMIT_LOGIN_BLOCK', '3600000')), // 1 hour
      },
      passwordReset: {
        maxAttempts: parseInt(this.configService.get<string>('app.RATE_LIMIT_PASSWORD_RESET_MAX', '3')),
        windowMs: parseInt(this.configService.get<string>('app.RATE_LIMIT_PASSWORD_RESET_WINDOW', '3600000')), // 1 hour
        blockDurationMs: parseInt(this.configService.get<string>('app.RATE_LIMIT_PASSWORD_RESET_BLOCK', '3600000')), // 1 hour
      },
      emailVerification: {
        maxAttempts: parseInt(this.configService.get<string>('app.RATE_LIMIT_EMAIL_VERIFICATION_MAX', '5')),
        windowMs: parseInt(this.configService.get<string>('app.RATE_LIMIT_EMAIL_VERIFICATION_WINDOW', '3600000')), // 1 hour
        blockDurationMs: parseInt(this.configService.get<string>('app.RATE_LIMIT_EMAIL_VERIFICATION_BLOCK', '3600000')), // 1 hour
      },
      mfa: {
        maxAttempts: parseInt(this.configService.get<string>('app.RATE_LIMIT_MFA_MAX', '3')),
        windowMs: parseInt(this.configService.get<string>('app.RATE_LIMIT_MFA_WINDOW', '300000')), // 5 minutes
        blockDurationMs: parseInt(this.configService.get<string>('app.RATE_LIMIT_MFA_BLOCK', '900000')), // 15 minutes
      },
    };
  }

  async checkRateLimit(
    type: string,
    identifier: string,
    ipAddress?: string,
  ): Promise<{ allowed: boolean; remaining: number; resetTime: Date }> {
    const config = this.getRateLimitConfigs()[type];
    if (!config) {
      throw new Error(`Unknown rate limit type: ${type}`);
    }

    const now = new Date();
    const windowStart = new Date(now.getTime() - config.windowMs);
    
    // Create rate limit keys for both user and IP
    const userKey = `${type}:user:${identifier}`;
    const ipKey = `${type}:ip:${ipAddress || 'unknown'}`;

    // Check both user and IP rate limits
    const [userRateLimit, ipRateLimit] = await Promise.all([
      this.prismaAuth.getRateLimit(userKey),
      ipAddress ? this.prismaAuth.getRateLimit(ipKey) : null,
    ]);

    // Check if either user or IP is rate limited
    const userExceeded = userRateLimit && 
      userRateLimit.attempts >= config.maxAttempts && 
      userRateLimit.windowStart > windowStart;
    
    const ipExceeded = ipRateLimit && 
      ipRateLimit.attempts >= config.maxAttempts && 
      ipRateLimit.windowStart > windowStart;

    if (userExceeded || ipExceeded) {
      const resetTime = new Date(Math.max(
        userRateLimit?.windowStart.getTime() || 0,
        ipRateLimit?.windowStart.getTime() || 0
      ) + config.windowMs);

      this.logger.warn(`Rate limit exceeded for ${type}: ${identifier} (IP: ${ipAddress})`);
      
      return {
        allowed: false,
        remaining: 0,
        resetTime,
      };
    }

    // Increment rate limit counters
    await Promise.all([
      this.prismaAuth.incrementRateLimit(userKey, windowStart),
      ipAddress ? this.prismaAuth.incrementRateLimit(ipKey, windowStart) : Promise.resolve(),
    ]);

    const remaining = Math.max(0, config.maxAttempts - Math.max(
      userRateLimit?.attempts || 0,
      ipRateLimit?.attempts || 0
    ) - 1);

    return {
      allowed: true,
      remaining,
      resetTime: new Date(now.getTime() + config.windowMs),
    };
  }

  async resetRateLimit(type: string, identifier: string, ipAddress?: string): Promise<void> {
    const userKey = `${type}:user:${identifier}`;
    const ipKey = `${type}:ip:${ipAddress || 'unknown'}`;

    await Promise.all([
      this.prismaAuth.resetRateLimit(userKey),
      ipAddress ? this.prismaAuth.resetRateLimit(ipKey) : Promise.resolve(),
    ]);

    this.logger.log(`Rate limit reset for ${type}: ${identifier} (IP: ${ipAddress})`);
  }

  async isBlocked(type: string, identifier: string, ipAddress?: string): Promise<boolean> {
    const config = this.getRateLimitConfigs()[type];
    if (!config) {
      return false;
    }

    const now = new Date();
    const blockStart = new Date(now.getTime() - config.blockDurationMs);
    
    const userKey = `${type}:user:${identifier}`;
    const ipKey = `${type}:ip:${ipAddress || 'unknown'}`;

    const [userRateLimit, ipRateLimit] = await Promise.all([
      this.prismaAuth.getRateLimit(userKey),
      ipAddress ? this.prismaAuth.getRateLimit(ipKey) : null,
    ]);

    const userBlocked = userRateLimit && 
      userRateLimit.attempts >= config.maxAttempts && 
      userRateLimit.windowStart > blockStart;
    
    const ipBlocked = ipRateLimit && 
      ipRateLimit.attempts >= config.maxAttempts && 
      ipRateLimit.windowStart > blockStart;

    return userBlocked || ipBlocked;
  }

  async cleanupExpiredRateLimits(): Promise<void> {
    await this.prismaAuth.cleanupExpiredRateLimits();
  }
}
