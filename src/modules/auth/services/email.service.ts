import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NotificationService } from '../../../infra/notifications/notification.service';
import { EmailMessage, NotificationContext } from '../../../infra/notifications/ports/notification.ports';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly notificationService: NotificationService,
  ) {}

  async sendEmailVerification(email: string, token: string, firstName?: string, tenantId?: string): Promise<void> {
    const verificationUrl = `${this.configService.get<string>('app.FRONTEND_URL')}/verify-email?token=${token}`;
    
    const message: EmailMessage = {
      to: email,
      subject: 'Verify your email address',
      content: this.getEmailVerificationText(firstName, verificationUrl),
      htmlContent: this.getEmailVerificationHtml(firstName, verificationUrl),
    };

    const context: NotificationContext = {
      tenantId,
      requestId: `email_verification_${Date.now()}`,
    };

    try {
      const result = await this.notificationService.sendEmail(message, context);
      if (result.success) {
        this.logger.log(`📧 Email verification sent to ${email}. MessageId: ${result.messageId}`);
      } else {
        this.logger.error(`Failed to send email verification to ${email}: ${result.error}`);
        throw new Error(`Email verification failed: ${result.error}`);
      }
    } catch (error) {
      this.logger.error(`Error sending email verification: ${error instanceof Error ? error.message : 'Unknown error'}`);
      throw error;
    }
  }

  async sendPasswordReset(email: string, token: string, firstName?: string, tenantId?: string): Promise<void> {
    const resetUrl = `${this.configService.get<string>('app.FRONTEND_URL')}/reset-password?token=${token}`;
    
    const message: EmailMessage = {
      to: email,
      subject: 'Reset your password',
      content: this.getPasswordResetText(firstName, resetUrl),
      htmlContent: this.getPasswordResetHtml(firstName, resetUrl),
    };

    const context: NotificationContext = {
      tenantId,
      requestId: `password_reset_${Date.now()}`,
    };

    try {
      const result = await this.notificationService.sendEmail(message, context);
      if (result.success) {
        this.logger.log(`📧 Password reset email sent to ${email}. MessageId: ${result.messageId}`);
      } else {
        this.logger.error(`Failed to send password reset email to ${email}: ${result.error}`);
        throw new Error(`Password reset email failed: ${result.error}`);
      }
    } catch (error) {
      this.logger.error(`Error sending password reset email: ${error instanceof Error ? error.message : 'Unknown error'}`);
      throw error;
    }
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

  async sendOTP(email: string, code: string, firstName?: string, tenantId?: string): Promise<void> {
    const message: EmailMessage = {
      to: email,
      subject: 'Your verification code',
      content: this.getOTPText(firstName, code),
      htmlContent: this.getOTPHtml(firstName, code),
    };

    const context: NotificationContext = {
      tenantId,
      requestId: `otp_${Date.now()}`,
    };

    try {
      const result = await this.notificationService.sendEmail(message, context);
      if (result.success) {
        this.logger.log(`📧 OTP sent to ${email}. MessageId: ${result.messageId}`);
      } else {
        this.logger.error(`Failed to send OTP to ${email}: ${result.error}`);
        throw new Error(`OTP email failed: ${result.error}`);
      }
    } catch (error) {
      this.logger.error(`Error sending OTP email: ${error instanceof Error ? error.message : 'Unknown error'}`);
      throw error;
    }
  }

  async sendWelcomeEmail(email: string, firstName?: string, tenantId?: string): Promise<void> {
    const message: EmailMessage = {
      to: email,
      subject: 'Welcome to Shooterista!',
      content: this.getWelcomeText(firstName),
      htmlContent: this.getWelcomeHtml(firstName),
    };

    const context: NotificationContext = {
      tenantId,
      requestId: `welcome_${Date.now()}`,
    };

    try {
      const result = await this.notificationService.sendEmail(message, context);
      if (result.success) {
        this.logger.log(`📧 Welcome email sent to ${email}. MessageId: ${result.messageId}`);
      } else {
        this.logger.error(`Failed to send welcome email to ${email}: ${result.error}`);
        throw new Error(`Welcome email failed: ${result.error}`);
      }
    } catch (error) {
      this.logger.error(`Error sending welcome email: ${error instanceof Error ? error.message : 'Unknown error'}`);
      throw error;
    }
  }

  // Helper methods for email templates
  private getEmailVerificationText(firstName?: string, verificationUrl?: string): string {
    return `
Hello ${firstName || 'User'},

Please click the link below to verify your email address:
${verificationUrl}

This link will expire in 24 hours.

If you didn't create an account, please ignore this email.

Best regards,
The Shooterista Team
    `.trim();
  }

  private getEmailVerificationHtml(firstName?: string, verificationUrl?: string): string {
    return `
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #3B82F6;">Verify Your Email Address</h1>
    <p>Hello ${firstName || 'User'},</p>
    <p>Please click the button below to verify your email address:</p>
    <div style="text-align: center; margin: 30px 0;">
      <a href="${verificationUrl}" style="background-color: #3B82F6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Verify Email Address</a>
    </div>
    <p>This link will expire in 24 hours.</p>
    <p>If you didn't create an account, please ignore this email.</p>
    <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
    <p style="color: #666; font-size: 14px;">Best regards,<br>The Shooterista Team</p>
  </div>
</body>
</html>
    `.trim();
  }

  private getPasswordResetText(firstName?: string, resetUrl?: string): string {
    return `
Hello ${firstName || 'User'},

You requested to reset your password. Click the link below to reset it:
${resetUrl}

This link will expire in 1 hour.

If you didn't request this, please ignore this email.

Best regards,
The Shooterista Team
    `.trim();
  }

  private getPasswordResetHtml(firstName?: string, resetUrl?: string): string {
    return `
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #3B82F6;">Reset Your Password</h1>
    <p>Hello ${firstName || 'User'},</p>
    <p>You requested to reset your password. Click the button below to reset it:</p>
    <div style="text-align: center; margin: 30px 0;">
      <a href="${resetUrl}" style="background-color: #EF4444; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Reset Password</a>
    </div>
    <p>This link will expire in 1 hour.</p>
    <p>If you didn't request this, please ignore this email.</p>
    <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
    <p style="color: #666; font-size: 14px;">Best regards,<br>The Shooterista Team</p>
  </div>
</body>
</html>
    `.trim();
  }

  private getOTPText(firstName?: string, code?: string): string {
    return `
Hello ${firstName || 'User'},

Your email verification code is: ${code}

This code will expire in 5 minutes.

Enter this code to verify your email address.

If you didn't request this, please ignore this email.

Best regards,
The Shooterista Team
    `.trim();
  }

  private getOTPHtml(firstName?: string, code?: string): string {
    return `
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #3B82F6;">Your Verification Code</h1>
    <p>Hello ${firstName || 'User'},</p>
    <p>Your email verification code is:</p>
    <div style="text-align: center; margin: 30px 0;">
      <div style="background-color: #F3F4F6; border: 2px dashed #3B82F6; padding: 20px; border-radius: 8px; display: inline-block;">
        <span style="font-size: 32px; font-weight: bold; color: #3B82F6; letter-spacing: 4px;">${code}</span>
      </div>
    </div>
    <p>This code will expire in 5 minutes.</p>
    <p>Enter this code to verify your email address.</p>
    <p>If you didn't request this, please ignore this email.</p>
    <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
    <p style="color: #666; font-size: 14px;">Best regards,<br>The Shooterista Team</p>
  </div>
</body>
</html>
    `.trim();
  }

  private getWelcomeText(firstName?: string): string {
    return `
Hello ${firstName || 'User'},

Welcome to Shooterista! Your account has been created successfully.

Please verify your email address to get started.

Best regards,
The Shooterista Team
    `.trim();
  }

  private getWelcomeHtml(firstName?: string): string {
    return `
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #3B82F6;">Welcome to Shooterista!</h1>
    <p>Hello ${firstName || 'User'},</p>
    <p>Welcome to Shooterista! Your account has been created successfully.</p>
    <p>Please verify your email address to get started.</p>
    <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
    <p style="color: #666; font-size: 14px;">Best regards,<br>The Shooterista Team</p>
  </div>
</body>
</html>
    `.trim();
  }
}
