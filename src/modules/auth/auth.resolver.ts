import { Resolver, Query, Mutation, Args, Context } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthGuard } from '@/common/guards/auth.guard';
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
  MfaSetup,
  PasswordResetResponse,
  EmailVerificationResponse,
  SessionListResponse,
  AuditLogResponse,
  PermissionCheckResponse,
} from './dto/auth.types';

@Resolver()
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

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
    @Context('req') req: any,
  ): Promise<AuthPayload> {
    return this.authService.register(input, req.ip, req.headers['user-agent']);
  }

  @Mutation(() => AuthPayload)
  async login(
    @Args('input') input: LoginInput,
    @Context('req') req: any,
  ): Promise<AuthPayload> {
    return this.authService.login(input, req.ip, req.headers['user-agent']);
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

  // Permission Management
  @Query(() => PermissionCheckResponse)
  @UseGuards(AuthGuard)
  async checkPermission(
    @Args('input') input: PermissionCheckInput,
    @Context('req') req: any,
  ): Promise<PermissionCheckResponse> {
    return this.authService.checkPermission(input, req.user.id);
  }

  // Role Management (Admin only)
  @Mutation(() => Boolean)
  @UseGuards(AuthGuard)
  async assignRole(
    @Args('input') input: RoleAssignmentInput,
    @Context('req') req: any,
  ): Promise<boolean> {
    return this.authService.assignRole(input, req.user.id, req.ip, req.headers['user-agent']);
  }

  @Mutation(() => Boolean)
  @UseGuards(AuthGuard)
  async removeRole(
    @Args('input') input: RoleRemovalInput,
    @Context('req') req: any,
  ): Promise<boolean> {
    return this.authService.removeRole(input, req.user.id, req.ip, req.headers['user-agent']);
  }

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
}
