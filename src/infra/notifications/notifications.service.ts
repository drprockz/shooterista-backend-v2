import { Injectable, Logger, Inject } from '@nestjs/common';
import { SendEmailPort, SendEmailParams, SendEmailResult } from './ports/send-email.port';
import { RenderTemplatePort, RenderTemplateResult } from './ports/render-template.port';
import { TenantContextService, TenantMeta } from '../tenant-context/tenant-context.service';

export interface NotificationParams {
  templateKey: 'welcome-email' | 'otp-email';
  data: Record<string, any>;
  to: string[];
  tenantMeta?: TenantMeta;
  idempotencyKey?: string;
}

@Injectable()
export class NotificationsService {
  private readonly logger = new Logger(NotificationsService.name);

  constructor(
    @Inject('SEND_EMAIL_PORT') private readonly sendEmailPort: SendEmailPort,
    @Inject('RENDER_TEMPLATE_PORT') private readonly renderTemplatePort: RenderTemplatePort,
    private readonly tenantContextService: TenantContextService,
  ) {}

  async send(params: NotificationParams): Promise<SendEmailResult> {
    const startTime = Date.now();
    const requestId = this.generateRequestId();
    
    try {
      this.logger.debug(`Starting email send`, {
        event: 'email_send_start',
        templateKey: params.templateKey,
        requestId,
        recipients: params.to.length,
        hasData: !!params.data,
        hasTenantMeta: !!params.tenantMeta
      });

      // Resolve tenant meta if not provided
      const tenantMeta = params.tenantMeta || this.getDefaultTenantMeta();
      
      // Render template
      const renderedTemplate = await this.renderTemplatePort.render(
        params.templateKey,
        params.data,
        tenantMeta
      );

      // Prepare email parameters
      const emailParams: SendEmailParams = {
        to: params.to,
        subject: this.getSubjectForTemplate(params.templateKey, params.data),
        html: renderedTemplate.html,
        text: renderedTemplate.text,
        templateKey: params.templateKey,
        data: params.data,
        tenantMeta,
      };

      // Send email
      const result = await this.sendEmailPort.send(emailParams);

      const duration = Date.now() - startTime;
      this.logger.log(`Email sent successfully`, {
        event: 'email_send_success',
        templateKey: params.templateKey,
        requestId,
        duration_ms: duration,
        recipients: params.to.length,
        success: result.success,
        messageId: result.messageId
      });

      return result;
    } catch (error) {
      const duration = Date.now() - startTime;
      this.logger.error(`Error sending email`, {
        event: 'email_send_error',
        templateKey: params.templateKey,
        requestId,
        duration_ms: duration,
        recipients: params.to.length,
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : 'Unknown error',
          stack_present: error instanceof Error ? !!error.stack : false
        }
      });

      // Return a failed result instead of throwing
      return {
        success: false,
        messageId: null,
        error: error instanceof Error ? error.message : 'Unknown error',
        provider: 'unknown',
        timestamp: new Date(),
      };
    }
  }

  private generateRequestId(): string {
    return `email_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Utility method for domain modules
  async sendWelcomeEmail(email: string, firstName: string, tenantMeta?: TenantMeta): Promise<SendEmailResult> {
    return this.send({
      templateKey: 'welcome-email',
      data: { firstName },
      to: [email],
      tenantMeta,
    });
  }

  async sendOTPEmail(email: string, code: string, firstName?: string, tenantMeta?: TenantMeta): Promise<SendEmailResult> {
    console.log(`📧 [NOTIFICATIONS] sendOTPEmail called for: ${email}`);
    console.log(`📧 [NOTIFICATIONS] OTP Code: ${code}`);
    console.log(`📧 [NOTIFICATIONS] First Name: ${firstName || 'User'}`);
    console.log(`📧 [NOTIFICATIONS] Tenant Meta:`, tenantMeta);
    
    try {
      const result = await this.send({
        templateKey: 'otp-email',
        data: { code, firstName: firstName || 'User' },
        to: [email],
        tenantMeta,
      });
      
      console.log(`📧 [NOTIFICATIONS] sendOTPEmail result:`, result);
      return result;
    } catch (error) {
      console.log(`❌ [NOTIFICATIONS] sendOTPEmail error:`, error.message);
      throw error;
    }
  }

  private getDefaultTenantMeta(): TenantMeta {
    return {
      brandColors: {
        primary: '#3B82F6',
        secondary: '#1E40AF',
      },
      fromEmail: 'noreply@shooterista.com',
      provider: 'smtp',
    };
  }

  private getSubjectForTemplate(templateKey: string, data: any): string {
    switch (templateKey) {
      case 'welcome-email':
        return 'Welcome to Shooterista!';
      case 'otp-email':
        return 'Your Verification Code';
      default:
        return 'Email from Shooterista';
    }
  }

  // Rate limiting hooks (optional: no-op placeholder)
  async checkRateLimit(email: string, templateKey: string): Promise<boolean> {
    // TODO: Implement rate limiting logic
    return true;
  }

  // Idempotency key handling (optional meta field)
  async isDuplicateRequest(idempotencyKey: string): Promise<boolean> {
    // TODO: Implement idempotency checking
    return false;
  }
}
