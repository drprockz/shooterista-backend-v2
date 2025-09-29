import { Resolver, Query, Mutation, Args, Context } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthGuard } from '@/common/guards/auth.guard';
import { CorrelationService } from '@/common/services/correlation.service';
import { 
  CreateUserInput, 
  LoginInput, 
  RefreshTokenInput, 
  LogoutInput,
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
  OTPVerificationInput,
  SaveProfileDraftInput,
  SubmitProfileInput,
  AdminApproveProfileInput,
  AdminRejectProfileInput,
  RequestEmailOtpInput,
  VerifyEmailOtpInput,
} from './dto/auth.input';
import { 
  AuthPayload, 
  TokenRefreshPayload, 
  User,
  MfaSetup,
  PasswordResetResponse,
  EmailVerificationResponse,
  SessionListResponse,
  AuditLogResponse,
  OTPResponse,
  ProfileCompletionStatus,
  UserProfile,
  UserProfileDraft,
  ProfileDraftResponse,
  ProfileSubmissionResponse,
  AdminProfileActionResponse,
  HealthMetrics,
  SecurityStatus,
} from './dto/auth.types';

@Resolver()
export class AuthResolver {
  constructor(
    private readonly authService: AuthService,
    private readonly correlationService: CorrelationService,
  ) {}

  @Query(() => String)
  async health(): Promise<string> {
    return 'Auth service is healthy';
  }

  @Query(() => String)
  async test(): Promise<string> {
    return 'Test query works';
  }

  // Authentication Mutations
  @Mutation(() => AuthPayload)
  async register(
    @Args('input') input: CreateUserInput,
    @Context() context: any,
  ): Promise<AuthPayload> {
    const req = context.req;
    const requestContext = context.requestContext;
    
    console.log('🔍 [DEBUG] Register resolver called with requestId:', requestContext?.requestId);
    console.log('🔍 [DEBUG] Input email:', input.email);
    
    // Create child logger with correlation context
    const logger = this.correlationService.createChildLogger(
      new (require('@nestjs/common').Logger)(AuthResolver.name),
      requestContext
    );

    // Log entry with payload keys only (no values)
    const payloadKeys = Object.keys(input).filter(key => 
      ['email', 'firstName', 'lastName', 'acceptTerms', 'acceptPrivacy', 'emailVerificationToken', 'tenantId'].includes(key)
    );
    
    console.log('🔍 [DEBUG] About to log register.start');
    logger.log({
      event: 'register.start',
      operationName: 'register',
      tenantId: input.tenantId,
      email: input.email,
      payload_keys: payloadKeys,
    });

    try {
      console.log('🔍 [DEBUG] About to call authService.register');
      const result = await this.authService.register(input, req.ip, req.headers['user-agent'], requestContext);
      
      console.log('🔍 [DEBUG] Register successful, logging success');
      logger.log({
        event: 'register.success',
        operationName: 'register',
        tenantId: input.tenantId,
        email: input.email,
        userId: result.user?.id,
        elapsed_ms: Date.now() - requestContext.startTime,
        initial_flags: {
          isFirstLogin: result.user?.isFirstLogin,
          profileStatus: result.user?.profileStatus,
          profileCompletion: result.user?.profileCompletion,
          modulesUnlocked: result.user?.modulesUnlocked,
        },
      });

      return result;
    } catch (error) {
      console.log('🔍 [DEBUG] Register error caught:', error.message);
      logger.error({
        event: 'register.error',
        operationName: 'register',
        tenantId: input.tenantId,
        email: input.email,
        elapsed_ms: Date.now() - requestContext.startTime,
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : 'Unknown error',
          stack_present: error instanceof Error ? !!error.stack : false,
        },
      });
      
      throw error;
    }
  }

  @Mutation(() => AuthPayload)
  async login(
    @Args('input') input: LoginInput,
    @Context() context: any,
  ): Promise<AuthPayload> {
    const req = context.req;
    const res = context.res;
    
    console.log('🔍 GraphQL Login mutation called:', {
      email: input.email,
      tenantId: input.tenantId,
      ip: req.ip,
      userAgent: req.headers['user-agent']?.substring(0, 50) + '...',
      headers: {
        'content-type': req.headers['content-type'],
        'origin': req.headers['origin'],
        'x-tenant-id': req.headers['x-tenant-id']
      }
    });
    
    const result = await this.authService.login(input, req.ip, req.headers['user-agent'], res);
    
    console.log('🔍 GraphQL Login result:', {
      hasUser: !!result.user,
      hasAccessToken: !!result.accessToken,
      hasRefreshToken: !!result.refreshToken,
      userId: result.user?.id,
      sessionId: result.sessionId
    });
    
    return result;
  }

  @Mutation(() => AuthPayload)
  async loginAsAdmin(
    @Args('input') input: AdminLoginInput,
    @Context('req') req: any,
  ): Promise<AuthPayload> {
    return this.authService.loginAsAdmin(input, req.ip, req.headers['user-agent']);
  }

  @Mutation(() => AuthPayload)
  async verifyMfa(
    @Args('input') input: MfaVerificationInput,
    @Context('req') req: any,
  ): Promise<AuthPayload> {
    // This would typically be called after login when MFA is required
    // The userId would come from a temporary session or token
    throw new Error('MFA verification requires user context - implement temporary session handling');
  }

  @Mutation(() => TokenRefreshPayload)
  async refreshToken(
    @Args('input') input: RefreshTokenInput,
    @Context('req') req: any,
  ): Promise<TokenRefreshPayload> {
    return this.authService.refreshTokens(input, req.ip, req.headers['user-agent']);
  }

  @Mutation(() => Boolean)
  @UseGuards(AuthGuard)
  async logout(
    @Args('input') input: LogoutInput, 
    @Context('req') req: any,
  ): Promise<boolean> {
    return this.authService.logout(req.user.id, input.refreshToken, req.ip, req.headers['user-agent']);
  }

  @Mutation(() => Boolean)
  @UseGuards(AuthGuard)
  async logoutAll(@Context('req') req: any): Promise<boolean> {
    return this.authService.logoutAll(req.user.id, req.ip, req.headers['user-agent']);
  }

  // User Queries
  @Query(() => User)
  @UseGuards(AuthGuard)
  async me(@Context('req') req: any): Promise<User> {
    return this.authService.me(req.user.id, req.user.tenantId);
  }

  // Profile Completion Queries
  @Query(() => ProfileCompletionStatus)
  @UseGuards(AuthGuard)
  async getProfileCompletion(@Context('req') req: any): Promise<ProfileCompletionStatus> {
    return this.authService.getProfileCompletion(req.user.id);
  }

  @Query(() => UserProfile, { nullable: true })
  @UseGuards(AuthGuard)
  async getMyProfile(@Context('req') req: any): Promise<UserProfile | null> {
    return this.authService.getUserProfile(req.user.id);
  }

  @Query(() => [UserProfileDraft])
  @UseGuards(AuthGuard)
  async getMyProfileDrafts(@Context('req') req: any): Promise<UserProfileDraft[]> {
    return this.authService.getUserProfileDrafts(req.user.id);
  }

  // Password Management
  @Mutation(() => PasswordResetResponse)
  async requestPasswordReset(
    @Args('input') input: PasswordResetRequestInput,
    @Context('req') req: any,
  ): Promise<PasswordResetResponse> {
    return this.authService.requestPasswordReset(input, req.ip, req.headers['user-agent']);
  }

  @Mutation(() => Boolean)
  async resetPassword(
    @Args('input') input: PasswordResetInput,
    @Context('req') req: any,
  ): Promise<boolean> {
    return this.authService.resetPassword(input, req.ip, req.headers['user-agent']);
  }

  @Mutation(() => Boolean)
  @UseGuards(AuthGuard)
  async changePassword(
    @Args('input') input: ChangePasswordInput,
    @Context('req') req: any,
  ): Promise<boolean> {
    return this.authService.changePassword(input, req.user.id, req.ip, req.headers['user-agent']);
  }

  // Email Verification
  @Mutation(() => Boolean)
  async verifyEmail(
    @Args('input') input: EmailVerificationInput,
    @Context('req') req: any,
  ): Promise<boolean> {
    return this.authService.verifyEmail(input, req.ip, req.headers['user-agent']);
  }

  @Mutation(() => EmailVerificationResponse)
  async resendEmailVerification(
    @Args('input') input: ResendEmailVerificationInput,
    @Context('req') req: any,
  ): Promise<EmailVerificationResponse> {
    return this.authService.resendEmailVerification(input, req.ip, req.headers['user-agent']);
  }

  // MFA Management
  @Mutation(() => MfaSetup)
  @UseGuards(AuthGuard)
  async setupMfa(
    @Args('input') input: MfaSetupInput,
    @Context('req') req: any,
  ): Promise<MfaSetup> {
    return this.authService.setupMfa(input, req.user.id);
  }

  @Mutation(() => Boolean)
  @UseGuards(AuthGuard)
  async enableMfa(
    @Args('input') input: MfaVerificationInput,
    @Context('req') req: any,
  ): Promise<boolean> {
    return this.authService.enableMfa(input, req.user.id, req.ip, req.headers['user-agent']);
  }

  @Mutation(() => Boolean)
  @UseGuards(AuthGuard)
  async disableMfa(
    @Args('input') input: MfaDisableInput,
    @Context('req') req: any,
  ): Promise<boolean> {
    return this.authService.disableMfa(input, req.user.id, req.ip, req.headers['user-agent']);
  }

  // Session Management
  @Query(() => SessionListResponse)
  @UseGuards(AuthGuard)
  async getSessions(
    @Args('input') input: SessionListInput,
    @Context('req') req: any,
  ): Promise<SessionListResponse> {
    return this.authService.getSessions(req.user.id, input);
  }

  @Mutation(() => Boolean)
  @UseGuards(AuthGuard)
  async revokeSession(
    @Args('input') input: SessionRevokeInput,
    @Context('req') req: any,
  ): Promise<boolean> {
    return this.authService.revokeSession(input, req.user.id, req.ip, req.headers['user-agent']);
  }

  // Permission and Role Management - TEMPORARILY DISABLED
  // These methods have been removed to simplify the system

  // User Management
  @Mutation(() => User)
  @UseGuards(AuthGuard)
  async updateUser(
    @Args('input') input: UserUpdateInput,
    @Context('req') req: any,
  ): Promise<User> {
    return this.authService.updateUser(input, req.user.id, req.ip, req.headers['user-agent']);
  }

  // Audit Logs (Admin only)
  @Query(() => AuditLogResponse)
  @UseGuards(AuthGuard)
  async getAuditLogs(
    @Args('input') input: AuditLogsInput,
    @Context('req') req: any,
  ): Promise<AuditLogResponse> {
    return this.authService.getAuditLogs(input, req.user.id);
  }

  // Enhanced Authentication Features

  // OTP Verification
  @Mutation(() => OTPResponse)
  async verifyOTP(
    @Args('input') input: OTPVerificationInput,
    @Context('req') req: any,
  ): Promise<OTPResponse> {
    return this.authService.verifyOTP(input, req.ip, req.headers['user-agent']);
  }

  @Mutation(() => OTPResponse)
  async resendOTP(
    @Args('email') email: string,
    @Context('req') req: any,
  ): Promise<OTPResponse> {
    const tenantId = req.headers['x-tenant-id'] || req.user?.tenantId;
    return this.authService.resendOTP(email, req.ip, req.headers['user-agent'], tenantId);
  }

  // Email OTP for Registration
  @Mutation(() => OTPResponse)
  async requestEmailOtp(
    @Args('input') input: RequestEmailOtpInput,
    @Context('req') req: any,
  ): Promise<OTPResponse> {
    return this.authService.requestEmailOtp(input, req.ip, req.headers['user-agent']);
  }

  @Mutation(() => OTPResponse)
  async verifyEmailOtp(
    @Args('input') input: VerifyEmailOtpInput,
    @Context('req') req: any,
  ): Promise<OTPResponse> {
    return this.authService.verifyEmailOtp(input, req.ip, req.headers['user-agent']);
  }

  // Profile Completion Mutations
  @Mutation(() => ProfileDraftResponse)
  @UseGuards(AuthGuard)
  async saveProfileDraft(
    @Args('input') input: SaveProfileDraftInput,
    @Context('req') req: any,
  ): Promise<ProfileDraftResponse> {
    return this.authService.saveProfileDraft(req.user.id, input, req.ip, req.headers['user-agent']);
  }

  @Mutation(() => ProfileSubmissionResponse)
  @UseGuards(AuthGuard)
  async submitProfile(
    @Args('input') input: SubmitProfileInput,
    @Context('req') req: any,
  ): Promise<ProfileSubmissionResponse> {
    return this.authService.submitProfile(req.user.id, input, req.ip, req.headers['user-agent']);
  }

  // Admin Profile Management
  @Mutation(() => AdminProfileActionResponse)
  @UseGuards(AuthGuard)
  async adminApproveProfile(
    @Args('input') input: AdminApproveProfileInput,
    @Context('req') req: any,
  ): Promise<AdminProfileActionResponse> {
    return this.authService.adminApproveProfile(req.user.id, input, req.ip, req.headers['user-agent']);
  }

  @Mutation(() => AdminProfileActionResponse)
  @UseGuards(AuthGuard)
  async adminRejectProfile(
    @Args('input') input: AdminRejectProfileInput,
    @Context('req') req: any,
  ): Promise<AdminProfileActionResponse> {
    return this.authService.adminRejectProfile(req.user.id, input, req.ip, req.headers['user-agent']);
  }

  // Consent Management - temporarily disabled
  // @Query(() => Boolean)
  // @UseGuards(AuthGuard)
  // async checkConsent(@Context('req') req: any): Promise<boolean> {
  //   return this.authService.checkConsent(req.user.id);
  // }

  // @Mutation(() => ConsentResponse)
  // @UseGuards(AuthGuard)
  // async recordConsent(
  //   @Args('input') input: ConsentInput,
  //   @Context('req') req: any,
  // ): Promise<ConsentResponse> {
  //   return this.authService.recordConsent(req.user.id, input, req.ip, req.headers['user-agent']);
  // }

  // @Query(() => Object)
  // async getConsentRequirements(): Promise<any> {
  //   return this.authService.getConsentRequirements();
  // }

  // Security and Health - temporarily disabled
  // @Query(() => HealthMetrics)
  // @UseGuards(AuthGuard)
  // async getSecurityMetrics(): Promise<HealthMetrics> {
  //   return this.authService.getSecurityMetrics();
  // }

  // @Query(() => SecurityStatus)
  // @UseGuards(AuthGuard)
  // async performSecurityCheck(): Promise<SecurityStatus> {
  //   return this.authService.performSecurityCheck();
  // }

  // @Query(() => [String])
  // @UseGuards(AuthGuard)
  // async getSecurityRecommendations(): Promise<string[]> {
  //   return this.authService.getSecurityRecommendations();
  // }

  // @Query(() => Object)
  // async healthCheck(): Promise<any> {
  //   return this.authService.healthCheck();
  // }

  // Enhanced Email Verification
  @Mutation(() => Boolean)
  async verifyEmailWithOTP(
    @Args('input') input: OTPVerificationInput,
    @Context('req') req: any,
  ): Promise<boolean> {
    return this.authService.verifyEmailWithOTP(input, req.ip, req.headers['user-agent']);
  }

  // Session Management Enhancement
  @Query(() => String)
  @UseGuards(AuthGuard)
  async getSessionInfo(
    @Args('sessionId') sessionId: string,
    @Context('req') req: any,
  ): Promise<string> {
    const result = await this.authService.getSessionInfo(sessionId);
    return JSON.stringify(result);
  }

  // Cleanup (Admin only)
  // @Mutation(() => Boolean)
  // @UseGuards(AuthGuard)
  // async cleanupExpiredData(@Context('req') req: any): Promise<boolean> {
  //   await this.authService.cleanupExpiredData();
  //   return true;
  // }

  // Development-only test email mutation
  @Mutation(() => String)
  async sendTestEmail(
    @Args('to') to: string,
    @Context('req') req: any,
  ): Promise<string> {
    // Only allow in development
    if (process.env.NODE_ENV !== 'development') {
      throw new Error('Test email only available in development');
    }

    const tenantId = req.headers['x-tenant-id'] || req.user?.tenantId;
    const result = await this.authService.sendTestEmail(to, tenantId);
    
    return result.success 
      ? `Test email sent successfully to ${to}. MessageId: ${result.messageId}`
      : `Test email failed: ${result.error}`;
  }
}
