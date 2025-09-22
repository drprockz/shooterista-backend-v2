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
    try {
      this.logger.debug(`Sending notification: ${params.templateKey} to ${params.to.join(', ')}`);

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

      // Audit/log
      this.logger.log(`Notification sent: ${params.templateKey} to ${params.to.join(', ')} - Success: ${result.success}`);

      return result;
    } catch (error) {
      this.logger.error(`Failed to send notification: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        provider: 'unknown',
        timestamp: new Date(),
      };
    }
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
    return this.send({
      templateKey: 'otp-email',
      data: { code, firstName: firstName || 'User' },
      to: [email],
      tenantMeta,
    });
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
