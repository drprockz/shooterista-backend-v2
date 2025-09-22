import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);

  constructor(private readonly configService: ConfigService) {}

  async sendEmailVerification(email: string, token: string, firstName?: string): Promise<void> {
    const verificationUrl = `${this.configService.get<string>('app.FRONTEND_URL')}/verify-email?token=${token}`;
    
    // In a real implementation, you would integrate with an email service like SendGrid, AWS SES, etc.
    this.logger.log(`Email verification sent to ${email}: ${verificationUrl}`);
    
    // For development, we'll just log the verification URL
    console.log(`
    ========================================
    EMAIL VERIFICATION
    ========================================
    To: ${email}
    Subject: Verify your email address
    
    Hello ${firstName || 'User'},
    
    Please click the link below to verify your email address:
    ${verificationUrl}
    
    This link will expire in 24 hours.
    
    If you didn't create an account, please ignore this email.
    ========================================
    `);
  }

  async sendPasswordReset(email: string, token: string, firstName?: string): Promise<void> {
    const resetUrl = `${this.configService.get<string>('app.FRONTEND_URL')}/reset-password?token=${token}`;
    
    this.logger.log(`Password reset email sent to ${email}: ${resetUrl}`);
    
    console.log(`
    ========================================
    PASSWORD RESET
    ========================================
    To: ${email}
    Subject: Reset your password
    
    Hello ${firstName || 'User'},
    
    You requested to reset your password. Click the link below to reset it:
    ${resetUrl}
    
    This link will expire in 1 hour.
    
    If you didn't request this, please ignore this email.
    ========================================
    `);
  }

  async sendMfaCode(email: string, code: string, firstName?: string): Promise<void> {
    this.logger.log(`MFA code sent to ${email}: ${code}`);
    
    console.log(`
    ========================================
    MFA CODE
    ========================================
    To: ${email}
    Subject: Your verification code
    
    Hello ${firstName || 'User'},
    
    Your verification code is: ${code}
    
    This code will expire in 5 minutes.
    
    If you didn't request this, please ignore this email.
    ========================================
    `);
  }

  async sendWelcomeEmail(email: string, firstName?: string): Promise<void> {
    this.logger.log(`Welcome email sent to ${email}`);
    
    console.log(`
    ========================================
    WELCOME EMAIL
    ========================================
    To: ${email}
    Subject: Welcome to Shooterista!
    
    Hello ${firstName || 'User'},
    
    Welcome to Shooterista! Your account has been created successfully.
    
    Please verify your email address to get started.
    
    Best regards,
    The Shooterista Team
    ========================================
    `);
  }
}
