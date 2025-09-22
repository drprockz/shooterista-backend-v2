import { Injectable, UnauthorizedException, BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';
import { PrismaAuthService } from './prisma-auth.service';
import { MfaService } from './services/mfa.service';
import { NotificationsService } from '../../infra/notifications/notifications.service';
import { TenantContextService } from '../../infra/tenant-context/tenant-context.service';
import { RateLimitService } from './services/rate-limit.service';
import { AuditService } from './services/audit.service';
import { OTPService } from './services/otp.service';
// import { ProfileCompletionService } from './services/profile-completion.service';
// import { ConsentService } from './services/consent.service';
// import { SecurityService } from './services/security.service';
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
  UserUpdateInput,
  SessionListInput,
} from './dto/auth.input';
import { 
  AuthPayload, 
  TokenRefreshPayload, 
  User, 
  Session, 
  AuditLog, 
  MfaSetup, 
  PasswordResetResponse, 
  EmailVerificationResponse, 
  SessionListResponse, 
  AuditLogResponse, 
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
    private readonly notificationsService: NotificationsService,
    private readonly tenantContextService: TenantContextService,
    private readonly rateLimitService: RateLimitService,
    private readonly auditService: AuditService,
    private readonly otpService: OTPService,
    // private readonly profileCompletionService: ProfileCompletionService,
    // private readonly consentService: ConsentService,
    // private readonly securityService: SecurityService,
  ) {}

  // Registration
  async register(input: CreateUserInput, ipAddress?: string, userAgent?: string): Promise<AuthPayload> {
    // Check rate limiting
    const rateLimit = await this.rateLimitService.checkRateLimit('registration', input.email, ipAddress);
    if (!rateLimit.allowed) {
      throw new ForbiddenException('Too many registration attempts. Please try again later.');
    }

    // Check for suspicious IP - temporarily disabled
    // const isSuspicious = await this.securityService.isSuspiciousIP(ipAddress || '');
    // if (isSuspicious) {
    //   await this.auditService.log({
    //     action: AuditAction.LOGIN_FAILED,
    //     ipAddress,
    //     userAgent,
    //     metadata: { email: input.email, reason: 'suspicious_ip' },
    //     success: false,
    //     tenantId: input.tenantId,
    //   });
    //   throw new ForbiddenException('Registration blocked due to suspicious activity');
    // }

    const existingUser = await this.prismaAuth.findUserByEmail(input.email, input.tenantId);
    if (existingUser) {
      throw new BadRequestException('User already exists');
    }

    // Validate consent if required
    if (input.acceptTerms === false || input.acceptPrivacy === false) {
      throw new BadRequestException('Terms and privacy acceptance is required');
    }

    const hashedPassword = await this.hashPassword(input.password);
    const user = await this.prismaAuth.createUser({
      ...input,
      password: hashedPassword,
    });

    // Record consent - temporarily disabled
    // if (input.acceptTerms && input.acceptPrivacy) {
    //   await this.consentService.recordConsent(
    //     user.id,
    //     input.acceptTerms,
    //     input.acceptPrivacy,
    //     ipAddress,
    //     userAgent
    //   );
    // }

    // Create email verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await this.prismaAuth.createEmailVerificationToken({
      userId: user.id,
      token: verificationToken,
      expiresAt,
    });

    // Generate OTP for email verification
    const { code: otpCode, expiresAt: otpExpiresAt } = this.otpService.createOTP(input.email);

    // Send notifications via NotificationsService
    const tenantMeta = this.tenantContextService.getTenantMeta({ tenantId: input.tenantId });
    
    await this.notificationsService.sendWelcomeEmail(user.email, user.firstName, tenantMeta);
    await this.notificationsService.sendOTPEmail(user.email, otpCode, user.firstName, tenantMeta);

    // Log audit event
    await this.auditService.logEmailVerificationRequest(user.id, ipAddress, userAgent, {
      tenantId: input.tenantId,
    });

    // Check profile completion - temporarily disabled
    // const profileStatus = await this.profileCompletionService.checkProfileCompletion(user.id);
    const profileStatus = { isComplete: true }; // Default to complete for now

    // Generate tokens
    const tokens = await this.generateTokens(user.id, user.email, input.tenantId);
    await this.storeRefreshToken(user.id, tokens.refreshToken);

    // Create session
    const session = await this.createSession(user.id, {
      deviceInfo: input.deviceInfo,
      ipAddress,
      userAgent,
    });

    // Log session creation
    await this.auditService.logSessionCreated(user.id, session.id, ipAddress, userAgent);

    return {
      user: this.mapUserToGraphQL(user),
      ...tokens,
      profileComplete: profileStatus.isComplete,
      requiresConsent: !(input.acceptTerms && input.acceptPrivacy),
      sessionId: session.id,
    };
  }

  // Login
  async login(input: LoginInput, ipAddress?: string, userAgent?: string, res?: any): Promise<AuthPayload> {
    const startTime = Date.now();
    
    console.log('🔐 Login attempt:', {
      email: input.email,
      tenantId: input.tenantId,
      ipAddress,
      userAgent: userAgent?.substring(0, 50) + '...',
      timestamp: new Date().toISOString()
    });
    
    // Check rate limiting
    const rateLimit = await this.rateLimitService.checkRateLimit('login', input.email, ipAddress);
    if (!rateLimit.allowed) {
      console.log('❌ Rate limit exceeded for:', input.email);
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

    // Check for suspicious IP - temporarily disabled
    // const isSuspicious = await this.securityService.isSuspiciousIP(ipAddress || '');
    // if (isSuspicious) {
    //   await this.auditService.log({
    //     action: AuditAction.LOGIN_FAILED,
    //     ipAddress,
    //     userAgent,
    //     metadata: { email: input.email, reason: 'suspicious_ip' },
    //     success: false,
    //     tenantId: input.tenantId,
    //   });
    //   throw new ForbiddenException('Login blocked due to suspicious activity');
    // }

    const user = await this.prismaAuth.findUserByEmail(input.email, input.tenantId);
    if (!user) {
      console.log('❌ User not found:', input.email, 'tenant:', input.tenantId);
      await this.auditService.logLogin(0, false, ipAddress, userAgent, { email: input.email });
      throw new UnauthorizedException('Invalid credentials');
    }

    console.log('✅ User found:', { id: user.id, email: user.email, isActive: user.isActive, isEmailVerified: user.isEmailVerified });

    const isPasswordValid = await this.verifyPassword(input.password, user.password);
    if (!isPasswordValid) {
      console.log('❌ Invalid password for user:', user.email);
      await this.auditService.logLogin(user.id, false, ipAddress, userAgent, { email: input.email });
      throw new UnauthorizedException('Invalid credentials');
    }

    console.log('✅ Password verified for user:', user.email);

    // Check if user is active
    if (!user.isActive) {
      await this.auditService.logLogin(user.id, false, ipAddress, userAgent, { 
        email: input.email, 
        reason: 'account_inactive',
        status: user.isActive ? 'ACTIVE' : 'INACTIVE',
      });
      throw new ForbiddenException('Account is not active');
    }

    // Check email verification
    if (!user.isEmailVerified) {
      await this.auditService.logLogin(user.id, false, ipAddress, userAgent, { 
        email: input.email, 
        reason: 'email_not_verified',
      });
      throw new ForbiddenException('Please verify your email address before logging in');
    }

    // Check consent - temporarily disabled
    // const hasValidConsent = await this.consentService.hasValidConsent(user.id);
    // if (!hasValidConsent) {
    //   await this.auditService.logLogin(user.id, false, ipAddress, userAgent, { 
    //     email: input.email, 
    //     reason: 'consent_required',
    //   });
    //   throw new ForbiddenException('Please accept the terms and privacy policy');
    // }

    // Update last login
    await this.prismaAuth.updateUser(user.id, { lastLoginAt: new Date() });

    // Reset rate limit on successful login
    await this.rateLimitService.resetRateLimit('login', input.email, ipAddress);

    // Check profile completion - temporarily disabled
    // const profileStatus = await this.profileCompletionService.checkProfileCompletion(user.id);
    const profileStatus = { isComplete: true }; // Default to complete for now

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
      profileComplete: profileStatus.isComplete,
      sessionId: session.id,
    };

    // Check if MFA is required
    if (user.isMfaEnabled) {
      response.mfaRequired = true;
      response.mfaType = MfaType.TOTP; // Default to TOTP for now
    }

    // Log authentication latency
    const authLatency = Date.now() - startTime;
    await this.auditService.log({
      action: AuditAction.LOGIN,
      userId: user.id,
      ipAddress,
      userAgent,
      metadata: { latency: authLatency },
      success: true,
      tenantId: input.tenantId,
    });

    console.log('🎉 Login successful:', {
      userId: user.id,
      email: user.email,
      sessionId: session.id,
      hasAccessToken: !!tokens.accessToken,
      hasRefreshToken: !!tokens.refreshToken,
      authLatency: `${authLatency}ms`
    });

    // Set cookies if response object is provided
    if (res) {
      this.setAuthCookies(res, tokens, input.tenantId);
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

    // Admin access - simplified without permission checks for now

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
    const tokens = await this.generateTokens(user.id, user.email);
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
    // Send password reset notification
    const tenantMeta = this.tenantContextService.getTenantMeta({ tenantId: input.tenantId });
    await this.notificationsService.send({
      templateKey: 'otp-email', // Reuse OTP template for password reset
      data: { code: resetToken, firstName: user.firstName },
      to: [user.email],
      tenantMeta,
    });

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

    // Send email verification notification
    const tenantMeta = this.tenantContextService.getTenantMeta({ tenantId: input.tenantId });
    await this.notificationsService.send({
      templateKey: 'otp-email',
      data: { code: verificationToken, firstName: user.firstName },
      to: [user.email],
      tenantMeta,
    });

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

  // Permission and Role Management - TEMPORARILY DISABLED
  // These methods have been removed to simplify the system
  // They can be re-added when RBAC is needed

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
    // Permission check removed for simplification

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
      roles: payload.roles || [],
      permissions: payload.permissions || [],
    };
  }

  // Helper Methods
  private setAuthCookies(response: any, tokens: { accessToken: string; refreshToken: string }, tenantId?: string) {
    const isDevelopment = this.configService.get<string>('app.NODE_ENV') === 'development';
    const isSecure = !isDevelopment; // Only secure in production
    
    // Set access token cookie
    response.cookie('access_token', tokens.accessToken, {
      httpOnly: true,
      secure: isSecure,
      sameSite: isDevelopment ? 'lax' : 'strict',
      maxAge: this.parseExpirationTime(this.configService.get<string>('app.JWT_EXPIRES_IN')) * 1000,
      path: '/',
      domain: isDevelopment ? undefined : this.configService.get<string>('app.COOKIE_DOMAIN'),
    });

    // Set refresh token cookie
    response.cookie('refresh_token', tokens.refreshToken, {
      httpOnly: true,
      secure: isSecure,
      sameSite: isDevelopment ? 'lax' : 'strict',
      maxAge: this.parseExpirationTime(this.configService.get<string>('app.JWT_REFRESH_EXPIRES_IN')) * 1000,
      path: '/',
      domain: isDevelopment ? undefined : this.configService.get<string>('app.COOKIE_DOMAIN'),
    });

    // Set tenant cookie if provided
    if (tenantId) {
      response.cookie('tenant_id', tenantId, {
        httpOnly: false, // Allow frontend to read tenant ID
        secure: isSecure,
        sameSite: isDevelopment ? 'lax' : 'strict',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        path: '/',
        domain: isDevelopment ? undefined : this.configService.get<string>('app.COOKIE_DOMAIN'),
      });
    }

    console.log('🍪 Auth cookies set:', {
      hasAccessToken: !!tokens.accessToken,
      hasRefreshToken: !!tokens.refreshToken,
      tenantId,
      secure: isSecure,
      sameSite: isDevelopment ? 'lax' : 'strict'
    });
  }

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
      userType: user.userType || 'ATHLETE', // Default to ATHLETE if not set
      isEmailVerified: user.isEmailVerified,
      isMfaEnabled: user.isMfaEnabled,
      lastLoginAt: user.lastLoginAt,
      passwordChangedAt: user.passwordChangedAt,
      status: user.status,
      tenantId: user.tenantId,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      roles: [], // Temporarily disabled
      permissions: [], // Temporarily disabled
    };
  }

  // Role and Permission mapping methods - TEMPORARILY DISABLED
  // These methods have been removed to simplify the system

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

  // Enhanced Authentication Methods

  // OTP Verification
  async verifyOTP(input: any, ipAddress?: string, userAgent?: string): Promise<any> {
    const result = this.otpService.verifyOTP(input.email, input.otp);
    
    if (!result.valid) {
      await this.auditService.log({
        action: AuditAction.MFA_VERIFICATION_FAILED,
        ipAddress,
        userAgent,
        metadata: { email: input.email, reason: result.reason },
        success: false,
      });
      throw new UnauthorizedException(result.reason || 'Invalid OTP');
    }

    await this.auditService.log({
      action: AuditAction.MFA_VERIFICATION,
      ipAddress,
      userAgent,
      metadata: { email: input.email },
      success: true,
    });

    return {
      success: true,
      message: 'OTP verified successfully',
    };
  }

  // Profile Completion - temporarily disabled
  // async checkProfileCompletion(userId: number): Promise<any> {
  //   return await this.profileCompletionService.checkProfileCompletion(userId);
  // }

  // async updateProfile(userId: number, profileData: any): Promise<any> {
  //   return await this.profileCompletionService.updateProfile(userId, profileData);
  // }

  // async canAccessModule(userId: number, moduleName: string): Promise<boolean> {
  //   return await this.profileCompletionService.canAccessModule(userId, moduleName);
  // }

  // Consent Management - temporarily disabled
  // async checkConsent(userId: number): Promise<boolean> {
  //   return await this.consentService.hasValidConsent(userId);
  // }

  // async recordConsent(userId: number, consentData: any, ipAddress?: string, userAgent?: string): Promise<any> {
  //   return await this.consentService.recordConsent(
  //     userId,
  //     consentData.acceptTerms,
  //     consentData.acceptPrivacy,
  //     ipAddress,
  //     userAgent
  //   );
  // }

  // async getConsentRequirements(): Promise<any> {
  //   return await this.consentService.getConsentRequirements();
  // }

  // Security and Health - temporarily disabled
  // async getSecurityMetrics(): Promise<any> {
  //   return await this.securityService.getSecurityMetrics();
  // }

  // async performSecurityCheck(): Promise<any> {
  //   return await this.securityService.performSecurityCheck();
  // }

  // async getSecurityRecommendations(): Promise<string[]> {
  //   return await this.securityService.getSecurityRecommendations();
  // }

  // Enhanced Email Verification with OTP
  async verifyEmailWithOTP(input: any, ipAddress?: string, userAgent?: string): Promise<boolean> {
    // Verify OTP first
    const otpResult = this.otpService.verifyOTP(input.email, input.otp);
    if (!otpResult.valid) {
      throw new UnauthorizedException(otpResult.reason || 'Invalid OTP');
    }

    // Then verify email token
    return await this.verifyEmail(input, ipAddress, userAgent);
  }

  // Resend OTP
  async resendOTP(email: string, ipAddress?: string, userAgent?: string, tenantId?: string): Promise<any> {
    const { code, expiresAt, resendAfter } = this.otpService.resendOTP(email);
    
    // Send OTP notification
    const tenantMeta = this.tenantContextService.getTenantMeta({ tenantId });
    await this.notificationsService.sendOTPEmail(email, code, undefined, tenantMeta);
    
    await this.auditService.log({
      action: AuditAction.EMAIL_VERIFICATION_REQUEST,
      ipAddress,
      userAgent,
      metadata: { email, type: 'otp_resend' },
      success: true,
    });

    return {
      success: true,
      message: 'OTP resent successfully',
      expiresAt,
      resendAfter,
    };
  }

  // Session Management Enhancement
  async getSessionInfo(sessionId: string): Promise<any> {
    const session = await this.prismaAuth.findSession(sessionId);
    if (!session) {
      throw new NotFoundException('Session not found');
    }

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
    };
  }

  // Cleanup expired data - temporarily disabled
  // async cleanupExpiredData(): Promise<void> {
  //   await Promise.all([
  //     this.otpService.cleanupExpiredOTPs(),
  //     this.securityService.cleanupSecurityData(),
  //     this.prismaAuth.cleanupExpiredTokens(),
  //   ]);
  // }

  // Health check - temporarily disabled
  // async healthCheck(): Promise<any> {
  //   const [metrics, securityStatus] = await Promise.all([
  //     this.getSecurityMetrics(),
  //     this.performSecurityCheck(),
  //   ]);

  //   return {
  //     status: 'healthy',
  //     timestamp: new Date(),
  //     metrics,
  //     security: securityStatus,
  //     services: {
  //       otp: this.otpService.getStats(),
  //       profile: 'active',
  //       consent: 'active',
  //       security: 'active',
  //     },
  //   };
  // }

  // Development-only test email method
  async sendTestEmail(to: string, tenantId?: string): Promise<any> {
    if (process.env.NODE_ENV !== 'development') {
      throw new Error('Test email only available in development');
    }

    const tenantMeta = this.tenantContextService.getTenantMeta({ tenantId });
    
    return await this.notificationsService.send({
      templateKey: 'welcome-email',
      data: { firstName: 'Test User' },
      to: [to],
      tenantMeta,
    });
  }
}
