import { Injectable, Logger } from '@nestjs/common';
import { PrismaAuthService } from '../prisma-auth.service';
import { AuditAction } from '../dto/auth.types';

export interface AuditLogData {
  userId?: number;
  action: AuditAction;
  resource?: string;
  resourceId?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: any;
  success?: boolean;
  tenantId?: string;
}

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(private readonly prismaAuth: PrismaAuthService) {}

  async log(data: AuditLogData): Promise<void> {
    try {
      await this.prismaAuth.createAuditLog(data);
      
      // Log to console for development
      if (process.env.NODE_ENV === 'development') {
        this.logger.log(`AUDIT: ${data.action} - User: ${data.userId} - Success: ${data.success} - IP: ${data.ipAddress}`);
      }
    } catch (error) {
      this.logger.error('Failed to create audit log', error);
    }
  }

  async logLogin(userId: number, success: boolean, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: success ? AuditAction.LOGIN : AuditAction.LOGIN_FAILED,
      resource: 'user',
      resourceId: userId.toString(),
      ipAddress,
      userAgent,
      metadata,
      success,
    });
  }

  async logLogout(userId: number, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: AuditAction.LOGOUT,
      resource: 'user',
      resourceId: userId.toString(),
      ipAddress,
      userAgent,
      metadata,
      success: true,
    });
  }

  async logPasswordChange(userId: number, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: AuditAction.PASSWORD_CHANGE,
      resource: 'user',
      resourceId: userId.toString(),
      ipAddress,
      userAgent,
      metadata,
      success: true,
    });
  }

  async logPasswordResetRequest(userId: number, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: AuditAction.PASSWORD_RESET_REQUEST,
      resource: 'user',
      resourceId: userId.toString(),
      ipAddress,
      userAgent,
      metadata,
      success: true,
    });
  }

  async logPasswordResetComplete(userId: number, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: AuditAction.PASSWORD_RESET_COMPLETE,
      resource: 'user',
      resourceId: userId.toString(),
      ipAddress,
      userAgent,
      metadata,
      success: true,
    });
  }

  async logEmailVerificationRequest(userId: number, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: AuditAction.EMAIL_VERIFICATION_REQUEST,
      resource: 'user',
      resourceId: userId.toString(),
      ipAddress,
      userAgent,
      metadata,
      success: true,
    });
  }

  async logEmailVerificationComplete(userId: number, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: AuditAction.EMAIL_VERIFICATION_COMPLETE,
      resource: 'user',
      resourceId: userId.toString(),
      ipAddress,
      userAgent,
      metadata,
      success: true,
    });
  }

  async logMfaEnabled(userId: number, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: AuditAction.MFA_ENABLED,
      resource: 'user',
      resourceId: userId.toString(),
      ipAddress,
      userAgent,
      metadata,
      success: true,
    });
  }

  async logMfaDisabled(userId: number, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: AuditAction.MFA_DISABLED,
      resource: 'user',
      resourceId: userId.toString(),
      ipAddress,
      userAgent,
      metadata,
      success: true,
    });
  }

  async logMfaVerification(userId: number, success: boolean, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: success ? AuditAction.MFA_VERIFICATION : AuditAction.MFA_VERIFICATION_FAILED,
      resource: 'user',
      resourceId: userId.toString(),
      ipAddress,
      userAgent,
      metadata,
      success,
    });
  }

  async logSessionCreated(userId: number, sessionId: string, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: AuditAction.SESSION_CREATED,
      resource: 'session',
      resourceId: sessionId,
      ipAddress,
      userAgent,
      metadata,
      success: true,
    });
  }

  async logSessionRevoked(userId: number, sessionId: string, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: AuditAction.SESSION_REVOKED,
      resource: 'session',
      resourceId: sessionId,
      ipAddress,
      userAgent,
      metadata,
      success: true,
    });
  }

  async logRoleAssigned(userId: number, roleId: string, assignedBy: number, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: AuditAction.ROLE_ASSIGNED,
      resource: 'role',
      resourceId: roleId,
      ipAddress,
      userAgent,
      metadata: {
        ...metadata,
        assignedBy,
      },
      success: true,
    });
  }

  async logRoleRemoved(userId: number, roleId: string, removedBy: number, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: AuditAction.ROLE_REMOVED,
      resource: 'role',
      resourceId: roleId,
      ipAddress,
      userAgent,
      metadata: {
        ...metadata,
        removedBy,
      },
      success: true,
    });
  }

  async logAccountLocked(userId: number, reason: string, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: AuditAction.ACCOUNT_LOCKED,
      resource: 'user',
      resourceId: userId.toString(),
      ipAddress,
      userAgent,
      metadata: {
        ...metadata,
        reason,
      },
      success: true,
    });
  }

  async logAccountUnlocked(userId: number, unlockedBy: number, ipAddress?: string, userAgent?: string, metadata?: any): Promise<void> {
    await this.log({
      userId,
      action: AuditAction.ACCOUNT_UNLOCKED,
      resource: 'user',
      resourceId: userId.toString(),
      ipAddress,
      userAgent,
      metadata: {
        ...metadata,
        unlockedBy,
      },
      success: true,
    });
  }
}
