import { Controller, Post, Get, Body, Request, Response, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiBody } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { AuthGuard } from '@/common/guards/auth.guard';
import { 
  CreateUserInput, 
  LoginInput, 
  RefreshTokenInput, 
  LogoutInput,
  ChangePasswordInput,
  PasswordResetRequestInput,
  PasswordResetInput,
  EmailVerificationInput,
  ResendEmailVerificationInput,
  MfaSetupInput,
  MfaVerificationInput,
  MfaDisableInput,
} from './dto/auth.input';
import { 
  AuthPayload, 
  TokenRefreshPayload, 
  User,
  MfaSetup,
  PasswordResetResponse,
  EmailVerificationResponse,
} from './dto/auth.types';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ 
    summary: 'Register new user',
    description: 'Create a new user account with email and password'
  })
  @ApiResponse({ 
    status: 201, 
    description: 'User successfully registered',
    type: AuthPayload 
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Invalid input or user already exists' 
  })
  @ApiBody({ type: CreateUserInput })
  async register(
    @Body() input: CreateUserInput,
    @Request() req: any,
  ): Promise<AuthPayload> {
    return this.authService.register(input, req.ip, req.headers['user-agent']);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ 
    summary: 'User login',
    description: 'Authenticate user with email and password'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Login successful',
    type: AuthPayload 
  })
  @ApiResponse({ 
    status: 401, 
    description: 'Invalid credentials' 
  })
  @ApiBody({ type: LoginInput })
  async login(
    @Body() input: LoginInput,
    @Request() req: any,
    @Response() res: any,
  ): Promise<AuthPayload> {
    console.log('🔍 REST Login endpoint called:', {
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
    
    console.log('🔍 REST Login result:', {
      hasUser: !!result.user,
      hasAccessToken: !!result.accessToken,
      hasRefreshToken: !!result.refreshToken,
      userId: result.user?.id,
      sessionId: result.sessionId
    });
    
    return result;
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ 
    summary: 'Refresh access token',
    description: 'Generate new access token using refresh token'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Token refreshed successfully',
    type: TokenRefreshPayload 
  })
  @ApiResponse({ 
    status: 401, 
    description: 'Invalid refresh token' 
  })
  @ApiBody({ type: RefreshTokenInput })
  async refreshToken(
    @Body() input: RefreshTokenInput,
    @Request() req: any,
  ): Promise<TokenRefreshPayload> {
    return this.authService.refreshTokens(input, req.ip, req.headers['user-agent']);
  }

  @Post('logout')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'User logout',
    description: 'Logout user and invalidate tokens'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Logout successful' 
  })
  @ApiBody({ type: LogoutInput })
  async logout(
    @Body() input: LogoutInput, 
    @Request() req: any,
  ): Promise<boolean> {
    return this.authService.logout(req.user.id, input.refreshToken, req.ip, req.headers['user-agent']);
  }

  @Post('logout-all')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Logout from all sessions',
    description: 'Logout user from all active sessions'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Logged out from all sessions' 
  })
  async logoutAll(@Request() req: any): Promise<boolean> {
    return this.authService.logoutAll(req.user.id, req.ip, req.headers['user-agent']);
  }

  @Get('me')
  @UseGuards(AuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Get current user',
    description: 'Get current authenticated user information'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'User information retrieved',
    type: User 
  })
  async me(@Request() req: any): Promise<User> {
    return this.authService.me(req.user.id);
  }

  @Post('password/change')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Change password',
    description: 'Change user password'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Password changed successfully' 
  })
  @ApiBody({ type: ChangePasswordInput })
  async changePassword(
    @Body() input: ChangePasswordInput,
    @Request() req: any,
  ): Promise<boolean> {
    return this.authService.changePassword(input, req.user.id, req.ip, req.headers['user-agent']);
  }

  @Post('password/reset/request')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ 
    summary: 'Request password reset',
    description: 'Send password reset email'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Password reset email sent',
    type: PasswordResetResponse 
  })
  @ApiBody({ type: PasswordResetRequestInput })
  async requestPasswordReset(
    @Body() input: PasswordResetRequestInput,
    @Request() req: any,
  ): Promise<PasswordResetResponse> {
    return this.authService.requestPasswordReset(input, req.ip, req.headers['user-agent']);
  }

  @Post('password/reset')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ 
    summary: 'Reset password',
    description: 'Reset password using reset token'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Password reset successfully' 
  })
  @ApiBody({ type: PasswordResetInput })
  async resetPassword(
    @Body() input: PasswordResetInput,
    @Request() req: any,
  ): Promise<boolean> {
    return this.authService.resetPassword(input, req.ip, req.headers['user-agent']);
  }

  @Post('email/verify')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ 
    summary: 'Verify email',
    description: 'Verify email address using verification token'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Email verified successfully' 
  })
  @ApiBody({ type: EmailVerificationInput })
  async verifyEmail(
    @Body() input: EmailVerificationInput,
    @Request() req: any,
  ): Promise<boolean> {
    return this.authService.verifyEmail(input, req.ip, req.headers['user-agent']);
  }

  @Post('email/resend')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ 
    summary: 'Resend email verification',
    description: 'Resend email verification'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Verification email sent',
    type: EmailVerificationResponse 
  })
  @ApiBody({ type: ResendEmailVerificationInput })
  async resendEmailVerification(
    @Body() input: ResendEmailVerificationInput,
    @Request() req: any,
  ): Promise<EmailVerificationResponse> {
    return this.authService.resendEmailVerification(input, req.ip, req.headers['user-agent']);
  }

  @Post('mfa/setup')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Setup MFA',
    description: 'Setup multi-factor authentication'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'MFA setup information',
    type: MfaSetup 
  })
  @ApiBody({ type: MfaSetupInput })
  async setupMfa(
    @Body() input: MfaSetupInput,
    @Request() req: any,
  ): Promise<MfaSetup> {
    return this.authService.setupMfa(input, req.user.id);
  }

  @Post('mfa/enable')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Enable MFA',
    description: 'Enable multi-factor authentication'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'MFA enabled successfully' 
  })
  @ApiBody({ type: MfaVerificationInput })
  async enableMfa(
    @Body() input: MfaVerificationInput,
    @Request() req: any,
  ): Promise<boolean> {
    return this.authService.enableMfa(input, req.user.id, req.ip, req.headers['user-agent']);
  }

  @Post('mfa/disable')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Disable MFA',
    description: 'Disable multi-factor authentication'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'MFA disabled successfully' 
  })
  @ApiBody({ type: MfaDisableInput })
  async disableMfa(
    @Body() input: MfaDisableInput,
    @Request() req: any,
  ): Promise<boolean> {
    return this.authService.disableMfa(input, req.user.id, req.ip, req.headers['user-agent']);
  }
}
