import { Injectable, UnauthorizedException, BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';
import { PrismaAuthService } from './prisma-auth.service';
import { MfaService } from './services/mfa.service';
import { EmailService } from './services/email.service';
import { RateLimitService } from './services/rate-limit.service';
import { AuditService } from './services/audit.service';
import { 
  CreateUserInput, 
  LoginInput, 
  RefreshTokenInput, 
  AdminLoginInput,
  MfaVerificationInput,
  PasswordResetRequestInput,
  PasswordResetInput,
  ChangePasswordInput,
  EmailVerificationInput,
  ResendEmailVerificationInput,
  MfaSetupInput,
  MfaDisableInput,
  SessionRevokeInput,
  AuditLogsInput,
  PermissionCheckInput,
  RoleAssignmentInput,
  RoleRemovalInput,
  UserUpdateInput,
  SessionListInput,
} from './dto/auth.input';
import { 
  AuthPayload, 
  TokenRefreshPayload, 
  User, 
  Role, 
  Permission, 
  Session, 
  AuditLog, 
  MfaSetup, 
  PasswordResetResponse, 
  EmailVerificationResponse, 
  SessionListResponse, 
  AuditLogResponse, 
  PermissionCheckResponse,
  UserStatus,
  MfaType,
  TokenType,
  AuditAction,
  SessionStatus,
} from './dto/auth.types';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly prismaAuth: PrismaAuthService,
    private readonly mfaService: MfaService,
    private readonly emailService: EmailService,
    private readonly rateLimitService: RateLimitService,
    private readonly auditService: AuditService,
  ) {}

  // Registration
  async register(input: CreateUserInput, ipAddress?: string, userAgent?: string): Promise<AuthPayload> {
    // Check rate limiting
    const rateLimit = await this.rateLimitService.checkRateLimit('registration', input.email, ipAddress);
    if (!rateLimit.allowed) {
      throw new ForbiddenException('Too many registration attempts. Please try again later.');
    }

    const existingUser = await this.prismaAuth.findUserByEmail(input.email, input.tenantId);
    if (existingUser) {
      throw new BadRequestException('User already exists');
    }

    const hashedPassword = await this.hashPassword(input.password);
    const user = await this.prismaAuth.createUser({
      ...input,
      password: hashedPassword,
    });

    // Create email verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await this.prismaAuth.createEmailVerificationToken({
      userId: user.id,
      token: verificationToken,
      expiresAt,
    });

    // Send verification email
    await this.emailService.sendEmailVerification(user.email, verificationToken, user.firstName);
    await this.emailService.sendWelcomeEmail(user.email, user.firstName);

    // Log audit event
    await this.auditService.logEmailVerificationRequest(user.id, ipAddress, userAgent, {
      tenantId: input.tenantId,
    });

    // Generate tokens
    const tokens = await this.generateTokens(user.id, user.email, input.tenantId);
    await this.storeRefreshToken(user.id, tokens.refreshToken);

    // Create session
    const session = await this.createSession(user.id, {
      deviceInfo: userAgent,
      ipAddress,
      userAgent,
    });

    // Log session creation
    await this.auditService.logSessionCreated(user.id, session.id, ipAddress, userAgent);

    return {
      user: this.mapUserToGraphQL(user),
      ...tokens,
    };
  }

  // Login
  async login(input: LoginInput, ipAddress?: string, userAgent?: string): Promise<AuthPayload> {
    // Check rate limiting
    const rateLimit = await this.rateLimitService.checkRateLimit('login', input.email, ipAddress);
    if (!rateLimit.allowed) {
      await this.auditService.log({
        action: AuditAction.LOGIN_FAILED,
        ipAddress,
        userAgent,
        metadata: { email: input.email, reason: 'rate_limited' },
        success: false,
        tenantId: input.tenantId,
      });
      throw new ForbiddenException('Too many login attempts. Please try again later.');
    }

    const user = await this.prismaAuth.findUserByEmail(input.email, input.tenantId);
    if (!user) {
      await this.auditService.logLogin(0, false, ipAddress, userAgent, { email: input.email });
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await this.verifyPassword(input.password, user.password);
    if (!isPasswordValid) {
      await this.auditService.logLogin(user.id, false, ipAddress, userAgent, { email: input.email });
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if user is active
    if (!user.isActive) {
      await this.auditService.logLogin(user.id, false, ipAddress, userAgent, { 
        email: input.email, 
        reason: 'account_inactive',
        status: user.isActive ? 'ACTIVE' : 'INACTIVE',
      });
      throw new ForbiddenException('Account is not active');
    }

    // Update last login
    await this.prismaAuth.updateUser(user.id, { lastLoginAt: new Date() });

    // Reset rate limit on successful login
    await this.rateLimitService.resetRateLimit('login', input.email, ipAddress);

    // Generate tokens
    const tokens = await this.generateTokens(user.id, user.email, input.tenantId);
    await this.storeRefreshToken(user.id, tokens.refreshToken);

    // Create session
    const session = await this.createSession(user.id, {
      deviceInfo: input.deviceInfo,
      ipAddress,
      userAgent,
    });

    // Log successful login
    await this.auditService.logLogin(user.id, true, ipAddress, userAgent, {
      sessionId: session.id,
      tenantId: input.tenantId,
    });

    // Log session creation
    await this.auditService.logSessionCreated(user.id, session.id, ipAddress, userAgent);

    const response: AuthPayload = {
      user: this.mapUserToGraphQL(user),
      ...tokens,
    };

    // Check if MFA is required
    if (user.isMfaEnabled) {
      response.mfaRequired = true;
      response.mfaType = MfaType.TOTP; // Default to TOTP for now
    }

    return response;
  }

  // Admin Login
  async loginAsAdmin(input: AdminLoginInput, ipAddress?: string, userAgent?: string): Promise<AuthPayload> {
    // Check rate limiting
    const rateLimit = await this.rateLimitService.checkRateLimit('login', input.email, ipAddress);
    if (!rateLimit.allowed) {
      throw new ForbiddenException('Too many login attempts. Please try again later.');
    }

    const user = await this.prismaAuth.findUserByEmail(input.email, input.tenantId);
    if (!user) {
      await this.auditService.logLogin(0, false, ipAddress, userAgent, { email: input.email, type: 'admin' });
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await this.verifyPassword(input.password, user.password);
    if (!isPasswordValid) {
      await this.auditService.logLogin(user.id, false, ipAddress, userAgent, { email: input.email, type: 'admin' });
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if user has admin role
    const hasAdminPermission = await this.prismaAuth.checkUserPermission(
      user.id, 
      'admin', 
      'access', 
      input.tenantId
    );

    if (!hasAdminPermission) {
      await this.auditService.logLogin(user.id, false, ipAddress, userAgent, { 
        email: input.email, 
        type: 'admin',
        reason: 'insufficient_permissions',
      });
      throw new ForbiddenException('Insufficient permissions for admin access');
    }

    // Update last login
    await this.prismaAuth.updateUser(user.id, { lastLoginAt: new Date() });

    // Reset rate limit on successful login
    await this.rateLimitService.resetRateLimit('login', input.email, ipAddress);

    // Generate tokens with admin permissions
    const tokens = await this.generateTokens(user.id, user.email, input.tenantId, true);
    await this.storeRefreshToken(user.id, tokens.refreshToken);

    // Create session
    const session = await this.createSession(user.id, {
      deviceInfo: input.deviceInfo,
      ipAddress,
      userAgent,
    });

    // Log successful admin login
    await this.auditService.logLogin(user.id, true, ipAddress, userAgent, {
      sessionId: session.id,
      tenantId: input.tenantId,
      type: 'admin',
    });

    // Log session creation
    await this.auditService.logSessionCreated(user.id, session.id, ipAddress, userAgent);

    return {
      user: this.mapUserToGraphQL(user),
      ...tokens,
    };
  }

  // MFA Verification
  async verifyMfa(input: MfaVerificationInput, userId: number, ipAddress?: string, userAgent?: string): Promise<AuthPayload> {
    const user = await this.prismaAuth.findUserById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Check rate limiting
    const rateLimit = await this.rateLimitService.checkRateLimit('mfa', user.email, ipAddress);
    if (!rateLimit.allowed) {
      throw new ForbiddenException('Too many MFA attempts. Please try again later.');
    }

    let isValid = false;

    if (input.type === MfaType.TOTP) {
      if (!user.mfaSecret) {
        throw new BadRequestException('MFA not set up for this user');
      }
      isValid = this.mfaService.verifyTOTP(input.token, user.mfaSecret);
    } else if (input.type === MfaType.EMAIL) {
      // In a real implementation, you would verify the email OTP from your storage
      // For now, we'll just validate the format
      isValid = this.mfaService.validateMfaToken(input.token, MfaType.EMAIL);
    }

    if (!isValid) {
      await this.auditService.logMfaVerification(userId, false, ipAddress, userAgent, {
        type: input.type,
      });
      throw new UnauthorizedException('Invalid MFA token');
    }

    // Reset rate limit on successful verification
    await this.rateLimitService.resetRateLimit('mfa', user.email, ipAddress);

    // Log successful MFA verification
    await this.auditService.logMfaVerification(userId, true, ipAddress, userAgent, {
      type: input.type,
    });

    // Generate new tokens after MFA verification
    const tokens = await this.generateTokens(user.id, user.email, user.tenantId);
    await this.storeRefreshToken(user.id, tokens.refreshToken);

    return {
      user: this.mapUserToGraphQL(user),
      ...tokens,
    };
  }

  // Refresh Tokens
  async refreshTokens(input: RefreshTokenInput, ipAddress?: string, userAgent?: string): Promise<TokenRefreshPayload> {
    try {
      const payload = this.jwtService.verify(input.refreshToken, {
        secret: this.configService.get<string>('app.JWT_SECRET'),
      });

      if (payload.type !== TokenType.REFRESH) {
        throw new UnauthorizedException('Invalid token type');
      }

      // Check if token is blacklisted
      const isBlacklisted = await this.prismaAuth.isTokenBlacklisted(input.refreshToken);
      if (isBlacklisted) {
        throw new UnauthorizedException('Token has been revoked');
      }

      const storedToken = await this.prismaAuth.findRefreshToken(payload.sub, input.refreshToken);
      if (!storedToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      const user = await this.prismaAuth.findUserById(parseInt(payload.sub), payload.tenantId);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Revoke old refresh token
      await this.prismaAuth.revokeRefreshToken(payload.sub, input.refreshToken);

      // Generate new tokens
      const tokens = await this.generateTokens(user.id, user.email, payload.tenantId);
      await this.storeRefreshToken(user.id, tokens.refreshToken);

      // Update session
      if (payload.sessionId) {
        await this.prismaAuth.updateSession(payload.sessionId, { lastUsedAt: new Date() });
      }

      return tokens;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  // Logout
  async logout(userId: string, refreshToken: string, ipAddress?: string, userAgent?: string): Promise<boolean> {
    // Blacklist the refresh token
    const tokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    await this.prismaAuth.blacklistToken({
      token: refreshToken,
      reason: 'logout',
      expiresAt: tokenExpiry,
    });

    await this.prismaAuth.revokeRefreshToken(userId, refreshToken);

    // Log logout
    await this.auditService.logLogout(parseInt(userId), ipAddress, userAgent);

    return true;
  }

  // Logout All Sessions
  async logoutAll(userId: string, ipAddress?: string, userAgent?: string): Promise<boolean> {
    // Get all active sessions
    const sessions = await this.prismaAuth.findUserSessions(parseInt(userId), true);
    
    // Revoke all sessions
    await this.prismaAuth.revokeAllUserSessions(parseInt(userId));
    await this.prismaAuth.revokeAllRefreshTokens(userId);

    // Log session revocations
    for (const session of sessions) {
      await this.auditService.logSessionRevoked(parseInt(userId), session.id, ipAddress, userAgent);
    }

    return true;
  }

  // Get Current User Profile
  async me(userId: number, tenantId?: string): Promise<User> {
    const user = await this.prismaAuth.findUserById(userId, tenantId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.mapUserToGraphQL(user);
  }

  // Password Reset Request
  async requestPasswordReset(input: PasswordResetRequestInput, ipAddress?: string, userAgent?: string): Promise<PasswordResetResponse> {
    // Check rate limiting
    const rateLimit = await this.rateLimitService.checkRateLimit('passwordReset', input.email, ipAddress);
    if (!rateLimit.allowed) {
      throw new ForbiddenException('Too many password reset attempts. Please try again later.');
    }

    const user = await this.prismaAuth.findUserByEmail(input.email, input.tenantId);
    if (!user) {
      // Don't reveal if user exists or not
      return {
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent.',
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
      };
    }

    // Create password reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await this.prismaAuth.createPasswordResetToken({
      userId: user.id,
      token: resetToken,
      expiresAt,
    });

    // Send password reset email
    await this.emailService.sendPasswordReset(user.email, resetToken, user.firstName);

    // Log password reset request
    await this.auditService.logPasswordResetRequest(user.id, ipAddress, userAgent, {
      tenantId: input.tenantId,
    });

    return {
      success: true,
      message: 'Password reset link has been sent to your email.',
      expiresAt,
    };
  }

  // Password Reset
  async resetPassword(input: PasswordResetInput, ipAddress?: string, userAgent?: string): Promise<boolean> {
    const resetToken = await this.prismaAuth.findPasswordResetToken(input.token);
    if (!resetToken) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    // Hash new password
    const hashedPassword = await this.hashPassword(input.newPassword);

    // Update user password
    await this.prismaAuth.updateUser(resetToken.userId, {
      password: hashedPassword,
      passwordChangedAt: new Date(),
    });

    // Mark token as used
    await this.prismaAuth.markPasswordResetTokenUsed(input.token);

    // Revoke all existing sessions and tokens
    await this.prismaAuth.revokeAllUserSessions(resetToken.userId);
    await this.prismaAuth.revokeAllRefreshTokens(resetToken.userId.toString());

    // Log password reset completion
    await this.auditService.logPasswordResetComplete(resetToken.userId, ipAddress, userAgent);

    return true;
  }

  // Change Password
  async changePassword(input: ChangePasswordInput, userId: number, ipAddress?: string, userAgent?: string): Promise<boolean> {
    const user = await this.prismaAuth.findUserById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Verify current password
    const isCurrentPasswordValid = await this.verifyPassword(input.currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    // Hash new password
    const hashedPassword = await this.hashPassword(input.newPassword);

    // Update password
    await this.prismaAuth.updateUser(userId, {
      password: hashedPassword,
      passwordChangedAt: new Date(),
    });

    // Revoke all existing sessions and tokens
    await this.prismaAuth.revokeAllUserSessions(userId);
    await this.prismaAuth.revokeAllRefreshTokens(userId.toString());

    // Log password change
    await this.auditService.logPasswordChange(userId, ipAddress, userAgent);

    return true;
  }

  // Email Verification
  async verifyEmail(input: EmailVerificationInput, ipAddress?: string, userAgent?: string): Promise<boolean> {
    const verificationToken = await this.prismaAuth.findEmailVerificationToken(input.token);
    if (!verificationToken) {
      throw new BadRequestException('Invalid or expired verification token');
    }

    // Update user email verification status
    await this.prismaAuth.updateUser(verificationToken.userId, {
      isEmailVerified: true,
      status: UserStatus.ACTIVE,
    });

    // Mark token as used
    await this.prismaAuth.markEmailVerificationTokenUsed(input.token);

    // Log email verification completion
    await this.auditService.logEmailVerificationComplete(verificationToken.userId, ipAddress, userAgent);

    return true;
  }

  // Resend Email Verification
  async resendEmailVerification(input: ResendEmailVerificationInput, ipAddress?: string, userAgent?: string): Promise<EmailVerificationResponse> {
    // Check rate limiting
    const rateLimit = await this.rateLimitService.checkRateLimit('emailVerification', input.email, ipAddress);
    if (!rateLimit.allowed) {
      throw new ForbiddenException('Too many verification email requests. Please try again later.');
    }

    const user = await this.prismaAuth.findUserByEmail(input.email, input.tenantId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.isEmailVerified) {
      throw new BadRequestException('Email is already verified');
    }

    // Create new verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await this.prismaAuth.createEmailVerificationToken({
      userId: user.id,
      token: verificationToken,
      expiresAt,
    });

    // Send verification email
    await this.emailService.sendEmailVerification(user.email, verificationToken, user.firstName);

    // Log email verification request
    await this.auditService.logEmailVerificationRequest(user.id, ipAddress, userAgent, {
      tenantId: input.tenantId,
    });

    return {
      success: true,
      message: 'Verification email has been sent.',
      expiresAt,
    };
  }

  // MFA Setup
  async setupMfa(input: MfaSetupInput, userId: number): Promise<MfaSetup> {
    const user = await this.prismaAuth.findUserById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.isMfaEnabled) {
      throw new BadRequestException('MFA is already enabled');
    }

    if (input.type === MfaType.TOTP) {
      const secret = this.mfaService.generateSecret();
      const qrCodeUrl = await this.mfaService.generateQRCode(secret, user.email);
      const backupCodes = this.mfaService.generateBackupCodes();

      // Store secret temporarily (user needs to verify before enabling)
      await this.prismaAuth.updateUser(userId, { mfaSecret: secret });

      return {
        secret,
        qrCodeUrl,
        backupCodes,
      };
    }

    throw new BadRequestException('Unsupported MFA type');
  }

  // Enable MFA
  async enableMfa(input: MfaVerificationInput, userId: number, ipAddress?: string, userAgent?: string): Promise<boolean> {
    const user = await this.prismaAuth.findUserById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.isMfaEnabled) {
      throw new BadRequestException('MFA is already enabled');
    }

    if (!user.mfaSecret) {
      throw new BadRequestException('MFA setup not completed');
    }

    // Verify the token
    const isValid = this.mfaService.verifyTOTP(input.token, user.mfaSecret);
    if (!isValid) {
      throw new UnauthorizedException('Invalid MFA token');
    }

    // Enable MFA
    await this.prismaAuth.updateUser(userId, { isMfaEnabled: true });

    // Log MFA enabled
    await this.auditService.logMfaEnabled(userId, ipAddress, userAgent, {
      type: input.type,
    });

    return true;
  }

  // Disable MFA
  async disableMfa(input: MfaDisableInput, userId: number, ipAddress?: string, userAgent?: string): Promise<boolean> {
    const user = await this.prismaAuth.findUserById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!user.isMfaEnabled) {
      throw new BadRequestException('MFA is not enabled');
    }

    // Verify current password
    const isPasswordValid = await this.verifyPassword(input.password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Password is incorrect');
    }

    // Verify MFA token
    const isValid = this.mfaService.validateMfaToken(input.token, input.type, user.mfaSecret);
    if (!isValid) {
      throw new UnauthorizedException('Invalid MFA token');
    }

    // Disable MFA
    await this.prismaAuth.updateUser(userId, { 
      isMfaEnabled: false, 
      mfaSecret: null,
    });

    // Log MFA disabled
    await this.auditService.logMfaDisabled(userId, ipAddress, userAgent, {
      type: input.type,
    });

    return true;
  }

  // Session Management
  async getSessions(userId: number, input: SessionListInput): Promise<SessionListResponse> {
    const sessions = await this.prismaAuth.findUserSessions(userId, input.activeOnly);
    
    const totalCount = sessions.length;
    const activeCount = sessions.filter(s => s.isActive).length;

    return {
      sessions: sessions.map(session => this.mapSessionToGraphQL(session)),
      totalCount,
      activeCount,
    };
  }

  async revokeSession(input: SessionRevokeInput, userId: number, ipAddress?: string, userAgent?: string): Promise<boolean> {
    const session = await this.prismaAuth.findSession(input.sessionId);
    if (!session) {
      throw new NotFoundException('Session not found');
    }

    if (session.userId !== userId) {
      throw new ForbiddenException('You can only revoke your own sessions');
    }

    await this.prismaAuth.revokeSession(input.sessionId);

    // Log session revocation
    await this.auditService.logSessionRevoked(userId, input.sessionId, ipAddress, userAgent);

    return true;
  }

  // Permission Management
  async checkPermission(input: PermissionCheckInput, userId: number): Promise<PermissionCheckResponse> {
    const hasPermission = await this.prismaAuth.checkUserPermission(
      userId, 
      input.resource, 
      input.action, 
      input.tenantId
    );

    const [permissions, roles] = await Promise.all([
      this.prismaAuth.getUserPermissions(userId, input.tenantId),
      this.prismaAuth.getUserRoles(userId, input.tenantId),
    ]);

    return {
      hasPermission,
      userPermissions: permissions.map(p => this.mapPermissionToGraphQL(p)),
      userRoles: roles.map(r => this.mapRoleToGraphQL(r.role)),
    };
  }

  // Role Management
  async assignRole(input: RoleAssignmentInput, assignedBy: number, ipAddress?: string, userAgent?: string): Promise<boolean> {
    const user = await this.prismaAuth.findUserById(parseInt(input.userId));
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const role = await this.prismaAuth.findRoleById(parseInt(input.roleId));
    if (!role) {
      throw new NotFoundException('Role not found');
    }

    await this.prismaAuth.assignRoleToUser({
      userId: parseInt(input.userId),
      roleId: parseInt(input.roleId),
      tenantId: input.tenantId,
    });

    // Log role assignment
    await this.auditService.logRoleAssigned(parseInt(input.userId), input.roleId, assignedBy, ipAddress, userAgent);

    return true;
  }

  async removeRole(input: RoleRemovalInput, removedBy: number, ipAddress?: string, userAgent?: string): Promise<boolean> {
    const user = await this.prismaAuth.findUserById(parseInt(input.userId));
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const role = await this.prismaAuth.findRoleById(parseInt(input.roleId));
    if (!role) {
      throw new NotFoundException('Role not found');
    }

    await this.prismaAuth.removeRoleFromUser({
      userId: parseInt(input.userId),
      roleId: parseInt(input.roleId),
      tenantId: input.tenantId,
    });

    // Log role removal
    await this.auditService.logRoleRemoved(parseInt(input.userId), input.roleId, removedBy, ipAddress, userAgent);

    return true;
  }

  // User Management
  async updateUser(input: UserUpdateInput, userId: number, ipAddress?: string, userAgent?: string): Promise<User> {
    const user = await this.prismaAuth.findUserById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const updatedUser = await this.prismaAuth.updateUser(userId, input);

    return this.mapUserToGraphQL(updatedUser);
  }

  // Audit Logs
  async getAuditLogs(input: AuditLogsInput, requesterId: number): Promise<AuditLogResponse> {
    // Check if user has permission to view audit logs
    const hasPermission = await this.prismaAuth.checkUserPermission(
      requesterId, 
      'audit', 
      'read'
    );

    if (!hasPermission) {
      throw new ForbiddenException('Insufficient permissions to view audit logs');
    }

    const { logs, totalCount } = await this.prismaAuth.getAuditLogs({
      userId: input.userId ? parseInt(input.userId) : undefined,
      action: input.action,
      tenantId: input.tenantId,
      startDate: input.startDate ? new Date(input.startDate) : undefined,
      endDate: input.endDate ? new Date(input.endDate) : undefined,
      limit: input.limit,
      offset: input.offset,
    });

    return {
      logs: logs.map(log => this.mapAuditLogToGraphQL(log)),
      totalCount,
    };
  }

  // Token Validation
  async validateUser(payload: any) {
    const user = await this.prismaAuth.findUserById(parseInt(payload.sub), payload.tenantId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Check if token is blacklisted
    const isBlacklisted = await this.prismaAuth.isTokenBlacklisted(payload.jti || '');
    if (isBlacklisted) {
      throw new UnauthorizedException('Token has been revoked');
    }

    return {
      id: user.id.toString(),
      email: user.email,
      tenantId: user.tenantId,
      roles: payload.roles || [],
      permissions: payload.permissions || [],
    };
  }

  // Helper Methods
  private async createSession(userId: number, data: {
    deviceInfo?: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<any> {
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

    return this.prismaAuth.createSession({
      userId,
      ...data,
      expiresAt,
    });
  }

  private async generateTokens(userId: number, email: string, tenantId?: string, isAdmin: boolean = false) {
    const jti = crypto.randomUUID();
    const now = Math.floor(Date.now() / 1000);

    const payload = {
      sub: userId.toString(),
      email,
      iat: now,
      type: TokenType.ACCESS,
      tenantId,
      jti,
    };

    const refreshPayload = {
      ...payload,
      type: TokenType.REFRESH,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        expiresIn: this.configService.get<string>('app.JWT_EXPIRES_IN'),
      }),
      this.jwtService.signAsync(refreshPayload, {
        expiresIn: this.configService.get<string>('app.JWT_REFRESH_EXPIRES_IN'),
      }),
    ]);

    return {
      accessToken,
      refreshToken,
      expiresIn: this.parseExpirationTime(this.configService.get<string>('app.JWT_EXPIRES_IN')),
    };
  }

  private async storeRefreshToken(userId: number, refreshToken: string): Promise<void> {
    const expiresAt = new Date();
    const expirationTime = this.parseExpirationTime(
      this.configService.get<string>('app.JWT_REFRESH_EXPIRES_IN')
    );
    expiresAt.setSeconds(expiresAt.getSeconds() + expirationTime);

    await this.prismaAuth.createRefreshToken({
      userId,
      token: refreshToken,
      expiresAt,
    });
  }

  private async hashPassword(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16,
      timeCost: 3,
      parallelism: 1,
    });
  }

  private async verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
    try {
      return await argon2.verify(hashedPassword, password);
    } catch {
      return false;
    }
  }

  private parseExpirationTime(expiration: string): number {
    const unit = expiration.slice(-1);
    const value = parseInt(expiration.slice(0, -1));
    
    switch (unit) {
      case 's': return value;
      case 'm': return value * 60;
      case 'h': return value * 60 * 60;
      case 'd': return value * 60 * 60 * 24;
      default: return 900; // 15 minutes default
    }
  }

  // Mapping methods
  private mapUserToGraphQL(user: any): User {
    return {
      id: user.id.toString(),
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      isEmailVerified: user.isEmailVerified,
      isMfaEnabled: user.isMfaEnabled,
      lastLoginAt: user.lastLoginAt,
      passwordChangedAt: user.passwordChangedAt,
      status: user.status,
      tenantId: user.tenantId,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      roles: user.userRoles?.map((ur: any) => this.mapRoleToGraphQL(ur.role)) || [],
      permissions: user.userRoles?.flatMap((ur: any) => 
        ur.role.rolePermissions?.map((rp: any) => this.mapPermissionToGraphQL(rp.permission)) || []
      ) || [],
    };
  }

  private mapRoleToGraphQL(role: any): Role {
    return {
      id: role.id.toString(),
      name: role.name,
      description: role.description,
      isActive: role.isActive,
      tenantId: role.tenantId,
      createdAt: role.createdAt,
      updatedAt: role.updatedAt,
      permissions: role.rolePermissions?.map((rp: any) => this.mapPermissionToGraphQL(rp.permission)) || [],
    };
  }

  private mapPermissionToGraphQL(permission: any): Permission {
    return {
      id: permission.id.toString(),
      name: permission.name,
      description: permission.description,
      resource: permission.resource,
      action: permission.action,
      isActive: permission.isActive,
      createdAt: permission.createdAt,
      updatedAt: permission.updatedAt,
    };
  }

  private mapSessionToGraphQL(session: any): Session {
    return {
      id: session.id,
      userId: session.userId.toString(),
      deviceInfo: session.deviceInfo,
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
      isActive: session.isActive,
      lastUsedAt: session.lastUsedAt,
      createdAt: session.createdAt,
      expiresAt: session.expiresAt,
      status: session.isActive ? SessionStatus.ACTIVE : SessionStatus.REVOKED,
    };
  }

  private mapAuditLogToGraphQL(log: any): AuditLog {
    return {
      id: log.id.toString(),
      userId: log.userId?.toString(),
      action: log.action,
      resource: log.resource,
      resourceId: log.resourceId,
      ipAddress: log.ipAddress,
      userAgent: log.userAgent,
      metadata: log.metadata,
      success: log.success,
      tenantId: log.tenantId,
      createdAt: log.createdAt,
    };
  }
}
