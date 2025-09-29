import { Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient as AuthPrismaClient } from '.prisma/auth';
// Using string literals for Prisma enums until import issue is resolved
type PrismaProfileStatus = 'DRAFT' | 'SUBMITTED' | 'APPROVED' | 'REJECTED';
type PrismaProfileSection = 'PERSONAL' | 'CONTACT' | 'EDUCATION' | 'JOB' | 'EVENT';
import { ConfigService } from '@nestjs/config';
import { UserStatus, AuditAction, TokenType, ProfileStatus, ProfileSection } from './dto/auth.types';

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
    isFirstLogin?: boolean;
    profileCompletion?: number;
      profileStatus?: PrismaProfileStatus;
    modulesUnlocked?: boolean;
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
    isFirstLogin: boolean;
    profileCompletion: number;
    profileStatus: PrismaProfileStatus;
    modulesUnlocked: boolean;
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

  // Profile Completion Operations
  async findUserProfile(userId: number) {
    return this.userProfile.findUnique({
      where: { userId },
    });
  }

  async findUserProfileDrafts(userId: number) {
    return this.userProfileDraft.findMany({
      where: { userId },
      orderBy: { lastSavedAt: 'desc' },
    });
  }

  async upsertUserProfileDraft(data: {
    userId: number;
    section: PrismaProfileSection;
    draftData: any;
    lastSavedAt: Date;
  }) {
    return this.userProfileDraft.upsert({
      where: {
        userId_section: {
          userId: data.userId,
          section: data.section,
        },
      },
      update: {
        draftData: data.draftData,
        lastSavedAt: data.lastSavedAt,
      },
      create: data,
    });
  }

  async moveDraftsToProfile(userId: number) {
    const drafts = await this.findUserProfileDrafts(userId);
    
    if (drafts.length === 0) {
      return null;
    }

    // Create or update user profile with draft data
    const profileData: any = {
      userId,
      dataVersion: 1,
      submittedAt: new Date(),
    };

    // Map drafts to profile sections
    for (const draft of drafts) {
      switch (draft.section) {
        case 'PERSONAL':
          profileData.personalData = draft.draftData;
          profileData.personalComplete = this.isSectionComplete(draft.draftData, 'personal');
          profileData.personalUpdatedAt = new Date();
          profileData.personalUpdatedBy = userId;
          break;
        case 'CONTACT':
          profileData.contactData = draft.draftData;
          profileData.contactComplete = this.isSectionComplete(draft.draftData, 'contact');
          profileData.contactUpdatedAt = new Date();
          profileData.contactUpdatedBy = userId;
          break;
        case 'EDUCATION':
          profileData.educationData = draft.draftData;
          profileData.educationComplete = this.isSectionComplete(draft.draftData, 'education');
          profileData.educationUpdatedAt = new Date();
          profileData.educationUpdatedBy = userId;
          break;
        case 'JOB':
          profileData.jobData = draft.draftData;
          profileData.jobComplete = this.isSectionComplete(draft.draftData, 'job');
          profileData.jobUpdatedAt = new Date();
          profileData.jobUpdatedBy = userId;
          break;
        case 'EVENT':
          profileData.eventData = draft.draftData;
          profileData.eventComplete = this.isSectionComplete(draft.draftData, 'event');
          profileData.eventUpdatedAt = new Date();
          profileData.eventUpdatedBy = userId;
          break;
      }
    }

    // Upsert the profile
    const profile = await this.userProfile.upsert({
      where: { userId },
      update: profileData,
      create: profileData,
    });

    // Clear drafts after moving to profile
    await this.userProfileDraft.deleteMany({
      where: { userId },
    });

    return profile;
  }

  async updateUserProfile(userId: number, data: {
    approvedAt?: Date;
    approvedBy?: number;
    rejectedAt?: Date;
    rejectedBy?: number;
    rejectionReason?: string;
  }) {
    return this.userProfile.update({
      where: { userId },
      data,
    });
  }

  private isSectionComplete(data: any, section: string): boolean {
    // Basic completion logic - can be enhanced based on business requirements
    if (!data || typeof data !== 'object') {
      return false;
    }

    const requiredFields: { [key: string]: string[] } = {
      personal: ['firstName', 'lastName'],
      contact: ['email', 'phone'],
      education: ['highestQualification'],
      job: ['occupation'],
      event: ['primaryDiscipline'],
    };

    const fields = requiredFields[section] || [];
    return fields.every(field => data[field] && data[field].trim() !== '');
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
