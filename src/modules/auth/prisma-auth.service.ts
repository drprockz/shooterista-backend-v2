import { Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient as AuthPrismaClient } from '.prisma/auth';
import { ConfigService } from '@nestjs/config';
import { UserStatus, AuditAction, TokenType } from './dto/auth.types';

@Injectable()
export class PrismaAuthService extends AuthPrismaClient implements OnModuleInit {
  constructor(private readonly configService: ConfigService) {
    super({
      datasources: {
        db: {
          url: configService.get<string>('app.AUTH_DB_URL'),
        },
      },
      log: ['error', 'warn'],
    });
  }

  async onModuleInit() {
    try {
      await this.$connect();
      console.log('✅ Auth database connected successfully');
    } catch (error) {
      console.error('❌ Failed to connect to auth database:', error.message);
      // Retry connection after a delay
      setTimeout(async () => {
        try {
          await this.$connect();
          console.log('✅ Auth database reconnected successfully');
        } catch (retryError) {
          console.error('❌ Auth database reconnection failed:', retryError.message);
        }
      }, 5000);
    }
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }

  // User operations
  async findUserByEmail(email: string, tenantId?: string) {
    return this.user.findFirst({
      where: { 
        email,
        ...(tenantId && { tenantId }),
        isActive: true,
      },
      include: {
        // userRoles temporarily disabled
      },
    });
  }

  async findUserById(id: number, tenantId?: string) {
    return this.user.findFirst({
      where: { 
        id,
        ...(tenantId && { tenantId }),
        isActive: true,
      },
      include: {
        // userRoles temporarily disabled
      },
    });
  }

  async createUser(data: { 
    email: string; 
    password: string; 
    firstName?: string; 
    lastName?: string; 
    tenantId?: string;
    userType?: string;
  }) {
    return this.user.create({
      data: {
        ...data,
        userType: (data.userType as any) || 'ATHLETE', // Default to ATHLETE if not specified
        isActive: true, // Users are active by default, email verification is separate
      },
      include: {
        // userRoles temporarily disabled
      },
    });
  }

  async updateUser(id: number, data: Partial<{
    firstName: string;
    lastName: string;
    isEmailVerified: boolean;
    isMfaEnabled: boolean;
    mfaSecret: string;
    lastLoginAt: Date;
    passwordChangedAt: Date;
    status: UserStatus;
    password: string;
  }>) {
    return this.user.update({
      where: { id },
      data,
      include: {
        // userRoles temporarily disabled
      },
    });
  }

  // Refresh token operations
  async createRefreshToken(data: { userId: number; token: string; expiresAt: Date }) {
    return this.refreshToken.create({
      data,
    });
  }

  async findRefreshToken(userId: string, token: string) {
    return this.refreshToken.findFirst({
      where: {
        userId: parseInt(userId),
        token,
        expiresAt: {
          gt: new Date(),
        },
        revokedAt: null,
      },
    });
  }

  async revokeRefreshToken(userId: string, token: string) {
    return this.refreshToken.updateMany({
      where: {
        userId: parseInt(userId),
        token,
      },
      data: {
        revokedAt: new Date(),
      },
    });
  }

  async revokeAllRefreshTokens(userId: string) {
    return this.refreshToken.updateMany({
      where: {
        userId: parseInt(userId),
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    });
  }

  async cleanupExpiredTokens() {
    return this.refreshToken.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });
  }

  // Session operations
  async createSession(data: {
    userId: number;
    deviceInfo?: string;
    ipAddress?: string;
    userAgent?: string;
    expiresAt: Date;
  }) {
    return this.session.create({
      data,
    });
  }

  async findSession(sessionId: string) {
    return this.session.findUnique({
      where: { id: sessionId },
      include: {
        user: {
          include: {
            // userRoles temporarily disabled
          },
        },
      },
    });
  }

  async findUserSessions(userId: number, activeOnly: boolean = false) {
    return this.session.findMany({
      where: {
        userId,
        ...(activeOnly && { isActive: true }),
        expiresAt: {
          gt: new Date(),
        },
      },
      orderBy: { lastUsedAt: 'desc' },
    });
  }

  async updateSession(sessionId: string, data: { lastUsedAt?: Date; isActive?: boolean }) {
    return this.session.update({
      where: { id: sessionId },
      data,
    });
  }

  async revokeSession(sessionId: string) {
    return this.session.update({
      where: { id: sessionId },
      data: { isActive: false },
    });
  }

  async revokeAllUserSessions(userId: number) {
    return this.session.updateMany({
      where: { userId, isActive: true },
      data: { isActive: false },
    });
  }

  async cleanupExpiredSessions() {
    return this.session.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });
  }

  // Role and Permission operations
  // findRoleByName - TEMPORARILY DISABLED

  // RBAC methods - TEMPORARILY DISABLED
  // All role and permission methods have been removed to simplify the system

  // Password reset operations
  async createPasswordResetToken(data: {
    userId: number;
    token: string;
    expiresAt: Date;
  }) {
    return this.passwordResetToken.create({
      data,
    });
  }

  async findPasswordResetToken(token: string) {
    return this.passwordResetToken.findFirst({
      where: {
        token,
        expiresAt: {
          gt: new Date(),
        },
        usedAt: null,
      },
      include: {
        user: true,
      },
    });
  }

  async markPasswordResetTokenUsed(token: string) {
    return this.passwordResetToken.updateMany({
      where: { token },
      data: { usedAt: new Date() },
    });
  }

  async cleanupExpiredPasswordResetTokens() {
    return this.passwordResetToken.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });
  }

  // Email verification operations
  async createEmailVerificationToken(data: {
    userId: number;
    token: string;
    expiresAt: Date;
  }) {
    return this.emailVerificationToken.create({
      data,
    });
  }

  async findEmailVerificationToken(token: string) {
    return this.emailVerificationToken.findFirst({
      where: {
        token,
        expiresAt: {
          gt: new Date(),
        },
        usedAt: null,
      },
      include: {
        user: true,
      },
    });
  }

  async markEmailVerificationTokenUsed(token: string) {
    return this.emailVerificationToken.updateMany({
      where: { token },
      data: { usedAt: new Date() },
    });
  }

  async cleanupExpiredEmailVerificationTokens() {
    return this.emailVerificationToken.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });
  }

  // Token blacklisting
  async blacklistToken(data: {
    token: string;
    reason: string;
    expiresAt: Date;
  }) {
    return this.blacklistedToken.create({
      data,
    });
  }

  async isTokenBlacklisted(token: string) {
    const blacklisted = await this.blacklistedToken.findFirst({
      where: {
        token,
        expiresAt: {
          gt: new Date(),
        },
      },
    });
    return !!blacklisted;
  }

  async cleanupExpiredBlacklistedTokens() {
    return this.blacklistedToken.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });
  }

  // Rate limiting
  async getRateLimit(key: string) {
    return this.rateLimit.findUnique({
      where: { key },
    });
  }

  async incrementRateLimit(key: string, windowStart: Date) {
    return this.rateLimit.upsert({
      where: { key },
      update: {
        attempts: { increment: 1 },
        updatedAt: new Date(),
      },
      create: {
        key,
        attempts: 1,
        windowStart,
      },
    });
  }

  async resetRateLimit(key: string) {
    return this.rateLimit.deleteMany({
      where: { key },
    });
  }

  async cleanupExpiredRateLimits() {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    return this.rateLimit.deleteMany({
      where: {
        windowStart: {
          lt: oneHourAgo,
        },
      },
    });
  }

  // Audit logging
  async createAuditLog(data: {
    userId?: number;
    action: AuditAction;
    resource?: string;
    resourceId?: string;
    ipAddress?: string;
    userAgent?: string;
    metadata?: any;
    success?: boolean;
    tenantId?: string;
  }) {
    return this.auditLog.create({
      data: {
        ...data,
        metadata: data.metadata ? JSON.stringify(data.metadata) : null,
      },
    });
  }

  async getAuditLogs(filters: {
    userId?: number;
    action?: string;
    tenantId?: string;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
    offset?: number;
  }) {
    const where: any = {};
    
    if (filters.userId) where.userId = filters.userId;
    if (filters.action) where.action = filters.action;
    if (filters.tenantId) where.tenantId = filters.tenantId;
    if (filters.startDate || filters.endDate) {
      where.createdAt = {};
      if (filters.startDate) where.createdAt.gte = filters.startDate;
      if (filters.endDate) where.createdAt.lte = filters.endDate;
    }

    const [logs, totalCount] = await Promise.all([
      this.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: filters.limit || 50,
        skip: filters.offset || 0,
        include: {
          user: {
            select: {
              id: true,
              email: true,
              firstName: true,
              lastName: true,
            },
          },
        },
      }),
      this.auditLog.count({ where }),
    ]);

    return { logs, totalCount };
  }

  // Cleanup operations
  async cleanupExpiredData() {
    await Promise.all([
      this.cleanupExpiredTokens(),
      this.cleanupExpiredSessions(),
      this.cleanupExpiredPasswordResetTokens(),
      this.cleanupExpiredEmailVerificationTokens(),
      this.cleanupExpiredBlacklistedTokens(),
      this.cleanupExpiredRateLimits(),
    ]);
  }
}
