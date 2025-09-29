import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SendEmailPort, SendEmailParams, SendEmailResult } from '../ports/send-email.port';
import * as nodemailer from 'nodemailer';
import { Transporter } from 'nodemailer';

@Injectable()
export class SmtpEmailAdapter implements SendEmailPort {
  private readonly logger = new Logger(SmtpEmailAdapter.name);
  private transporter: Transporter | null = null;

  constructor(private readonly configService: ConfigService) {}

  async send(params: SendEmailParams): Promise<SendEmailResult> {
    const startTime = Date.now();
    const requestId = this.generateRequestId();
    
    try {
      this.logger.debug(`Starting SMTP email send`, {
        event: 'smtp_send_start',
        templateKey: params.templateKey,
        requestId,
        recipients: params.to.length,
        transport: 'smtp'
      });

      // Check if email is disabled
      const emailEnabled = this.configService.get<boolean>('app.EMAIL_ENABLED', false);
      if (!emailEnabled) {
        this.logger.log(`Email sending disabled, skipping`, {
          event: 'email_disabled',
          templateKey: params.templateKey,
          requestId,
          skipped: true
        });
        
        return {
          success: true,
          messageId: null,
          error: null,
          provider: 'smtp',
          timestamp: new Date(),
        };
      }

      const transporter = await this.getTransporter();
      const messageId = `smtp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      // Prepare nodemailer options
      const mailOptions: any = {
        from: params.tenantMeta?.fromEmail || this.configService.get<string>('app.EMAIL_FROM'),
        to: params.to.join(', '),
        subject: params.subject,
        text: params.text,
        html: params.html,
        messageId: `<${messageId}@shooterista.com>`,
      };

      // Add reply-to if specified
      if (params.tenantMeta?.replyToEmail) {
        mailOptions.replyTo = params.tenantMeta.replyToEmail;
      }

      // Send email
      const info = await transporter.sendMail(mailOptions);
      
      const duration = Date.now() - startTime;
      this.logger.log(`SMTP email sent successfully`, {
        event: 'smtp_send_success',
        templateKey: params.templateKey,
        requestId,
        duration_ms: duration,
        recipients: params.to.length,
        messageId: info.messageId || messageId,
        transport: 'smtp'
      });

      return {
        success: true,
        messageId: info.messageId || messageId,
        provider: 'smtp',
        timestamp: new Date(),
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      this.logger.error(`SMTP email send failed`, {
        event: 'smtp_send_error',
        templateKey: params.templateKey,
        requestId,
        duration_ms: duration,
        recipients: params.to.length,
        transport: 'smtp',
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : 'Unknown error',
          stack_present: error instanceof Error ? !!error.stack : false
        }
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        provider: 'smtp',
        timestamp: new Date(),
      };
    }
  }

  private generateRequestId(): string {
    return `smtp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private async getTransporter(): Promise<Transporter> {
    if (this.transporter) {
      return this.transporter;
    }

    // Only read from .env.development in dev
    const nodeEnv = process.env.NODE_ENV || 'development';
    if (nodeEnv === 'development') {
      console.log('[ENV] Loaded from .env.development');
    }

    const smtpConfig = {
      host: this.configService.get<string>('app.SMTP_HOST'),
      port: this.configService.get<number>('app.SMTP_PORT'),
      secure: this.configService.get<boolean>('app.SMTP_SECURE'),
      username: this.configService.get<string>('app.SMTP_USERNAME'),
      password: this.configService.get<string>('app.SMTP_PASSWORD'),
    };

    // Fail fast if required SMTP vars are missing in dev
    if (nodeEnv === 'development') {
      const requiredVars = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USERNAME', 'SMTP_PASSWORD'];
      const missingVars = requiredVars.filter(varName => !process.env[varName]);
      
      if (missingVars.length > 0) {
        throw new Error(`Missing required SMTP environment variables: ${missingVars.join(', ')}`);
      }
    }

    if (!smtpConfig.host) {
      throw new Error('SMTP configuration is missing');
    }

    // Create transporter
    this.transporter = nodemailer.createTransport({
      host: smtpConfig.host,
      port: smtpConfig.port,
      secure: smtpConfig.secure,
      auth: smtpConfig.username && smtpConfig.password ? {
        user: smtpConfig.username,
        pass: smtpConfig.password,
      } : undefined,
    } as any);

    // Verify connection
    try {
      await this.transporter.verify();
      this.logger.log('SMTP connection verified successfully');
    } catch (error) {
      this.logger.error(`SMTP connection verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      throw error;
    }

    return this.transporter;
  }
}