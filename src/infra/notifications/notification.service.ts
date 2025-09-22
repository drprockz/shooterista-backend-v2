import { Injectable, Logger, Inject } from '@nestjs/common';
import { 
  INotificationService, 
  EmailMessage, 
  NotificationContext, 
  NotificationResult, 
  EmailDeliveryStatus,
  NotificationProvider,
  NotificationCapabilities 
} from './ports/notification.ports';
import { EmailProvider } from './ports/notification.ports';
import { NotificationConfigService } from './notification-config.service';

@Injectable()
export class NotificationService implements INotificationService {
  private readonly logger = new Logger(NotificationService.name);

  constructor(
    @Inject('EMAIL_ADAPTER') private readonly emailProvider: EmailProvider,
    private readonly configService: NotificationConfigService,
  ) {}

  async sendEmail(message: EmailMessage, context?: NotificationContext): Promise<NotificationResult> {
    try {
      this.logger.debug(`Sending email to ${Array.isArray(message.to) ? message.to.join(', ') : message.to}`);
      
      // Apply tenant-specific configuration
      const enrichedMessage = await this.enrichMessage(message, context);
      
      // Validate message
      const validation = this.validateMessage(enrichedMessage);
      if (!validation.valid) {
        throw new Error(`Email validation failed: ${validation.errors.join(', ')}`);
      }

      // Send email
      const result = await this.emailProvider.sendEmail(enrichedMessage, context);
      
      this.logger.log(`Email sent successfully. MessageId: ${result.messageId}`);
      return result;
    } catch (error) {
      this.logger.error(`Failed to send email: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date(),
        provider: this.emailProvider.name,
      };
    }
  }

  async sendBulkEmails(messages: EmailMessage[], context?: NotificationContext): Promise<NotificationResult[]> {
    try {
      this.logger.debug(`Sending ${messages.length} bulk emails`);
      
      // Check bulk capabilities
      const capabilities = this.emailProvider.capabilities;
      if (!capabilities.supportsBulk) {
        this.logger.warn('Provider does not support bulk sending, sending individually');
        return Promise.all(messages.map(message => this.sendEmail(message, context)));
      }

      // Enrich all messages
      const enrichedMessages = await Promise.all(
        messages.map(message => this.enrichMessage(message, context))
      );

      // Validate all messages
      for (const message of enrichedMessages) {
        const validation = this.validateMessage(message);
        if (!validation.valid) {
          throw new Error(`Email validation failed: ${validation.errors.join(', ')}`);
        }
      }

      // Send bulk emails
      const results = await this.emailProvider.sendBulkEmails(enrichedMessages, context);
      
      this.logger.log(`Bulk emails sent successfully. ${results.filter(r => r.success).length}/${results.length} successful`);
      return results;
    } catch (error) {
      this.logger.error(`Failed to send bulk emails: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return messages.map(() => ({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date(),
        provider: this.emailProvider.name,
      }));
    }
  }

  async sendTemplatedEmail(
    templateId: string,
    to: string | string[],
    variables: Record<string, any>,
    context?: NotificationContext,
  ): Promise<NotificationResult> {
    try {
      this.logger.debug(`Sending templated email ${templateId} to ${Array.isArray(to) ? to.join(', ') : to}`);
      
      // Get template (in a real implementation, this would come from a template service)
      const template = await this.getTemplate(templateId);
      
      // Render template
      const renderedTemplate = this.renderTemplate(template, variables);
      
      // Create email message
      const message: EmailMessage = {
        to,
        subject: renderedTemplate.subject,
        content: renderedTemplate.textContent || '',
        htmlContent: renderedTemplate.htmlContent,
        metadata: {
          templateId,
          variables,
        },
      };

      return await this.sendEmail(message, context);
    } catch (error) {
      this.logger.error(`Failed to send templated email: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date(),
        provider: this.emailProvider.name,
      };
    }
  }

  validateEmailAddress(email: string): boolean {
    return this.emailProvider.validateEmailAddress(email);
  }

  getProviderInfo(): NotificationProvider {
    return {
      name: this.emailProvider.name,
      version: this.emailProvider.version,
      capabilities: this.emailProvider.capabilities,
    };
  }

  async getDeliveryStatus(messageId: string): Promise<EmailDeliveryStatus> {
    try {
      return await this.emailProvider.getDeliveryStatus(messageId);
    } catch (error) {
      this.logger.error(`Failed to get delivery status for ${messageId}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return {
        messageId,
        status: 'unknown',
        timestamp: new Date(),
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  // Health check
  async healthCheck(): Promise<{ healthy: boolean; provider: string; error?: string }> {
    try {
      const health = await this.configService.checkProviderHealth();
      return {
        healthy: health.healthy,
        provider: health.provider,
        error: health.error,
      };
    } catch (error) {
      return {
        healthy: false,
        provider: this.emailProvider.name,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  // Private helper methods
  private async enrichMessage(message: EmailMessage, context?: NotificationContext): Promise<EmailMessage> {
    const config = this.configService.getConfig();
    const tenantConfig = this.configService.getTenantConfig(context?.tenantId);
    const tenantBranding = this.configService.getTenantBranding(context?.tenantId);

    // Apply default configuration
    const enrichedMessage: EmailMessage = {
      ...message,
      from: message.from || config.email.defaultFrom,
      replyTo: message.replyTo || config.email.defaultReplyTo,
    };

    // Apply tenant-specific branding to HTML content
    if (enrichedMessage.htmlContent && tenantBranding) {
      enrichedMessage.htmlContent = this.applyTenantBranding(enrichedMessage.htmlContent, tenantBranding);
    }

    // Add tenant-specific headers
    if (context?.tenantId) {
      enrichedMessage.headers = {
        ...enrichedMessage.headers,
        'X-Tenant-ID': context.tenantId,
        'X-Request-ID': context.requestId || '',
      };
    }

    return enrichedMessage;
  }

  private validateMessage(message: EmailMessage): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Validate recipients
    if (!message.to || (Array.isArray(message.to) && message.to.length === 0)) {
      errors.push('Recipients are required');
    }

    // Validate subject
    if (!message.subject || message.subject.trim().length === 0) {
      errors.push('Subject is required');
    }

    // Validate content
    if (!message.content && !message.htmlContent) {
      errors.push('Email content is required');
    }

    // Validate email addresses
    const recipients = Array.isArray(message.to) ? message.to : [message.to];
    for (const recipient of recipients) {
      if (!this.validateEmailAddress(recipient)) {
        errors.push(`Invalid email address: ${recipient}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  private async getTemplate(templateId: string): Promise<any> {
    // In a real implementation, this would fetch from a template service
    // For now, return a mock template
    const templates: Record<string, any> = {
      'welcome': {
        id: 'welcome',
        name: 'Welcome Email',
        subject: 'Welcome to {{appName}}!',
        htmlTemplate: `
          <html>
            <body>
              <h1>Welcome to {{appName}}, {{firstName}}!</h1>
              <p>Thank you for joining us.</p>
            </body>
          </html>
        `,
        textTemplate: 'Welcome to {{appName}}, {{firstName}}! Thank you for joining us.',
        variables: ['appName', 'firstName'],
      },
      'email-verification': {
        id: 'email-verification',
        name: 'Email Verification',
        subject: 'Verify your email address',
        htmlTemplate: `
          <html>
            <body>
              <h1>Verify your email address</h1>
              <p>Click the link below to verify your email:</p>
              <a href="{{verificationUrl}}">Verify Email</a>
            </body>
          </html>
        `,
        textTemplate: 'Verify your email address. Click here: {{verificationUrl}}',
        variables: ['verificationUrl'],
      },
      'password-reset': {
        id: 'password-reset',
        name: 'Password Reset',
        subject: 'Reset your password',
        htmlTemplate: `
          <html>
            <body>
              <h1>Reset your password</h1>
              <p>Click the link below to reset your password:</p>
              <a href="{{resetUrl}}">Reset Password</a>
            </body>
          </html>
        `,
        textTemplate: 'Reset your password. Click here: {{resetUrl}}',
        variables: ['resetUrl'],
      },
    };

    const template = templates[templateId];
    if (!template) {
      throw new Error(`Template not found: ${templateId}`);
    }

    return template;
  }

  private renderTemplate(template: any, variables: Record<string, any>): { subject: string; htmlContent: string; textContent: string } {
    let subject = template.subject;
    let htmlContent = template.htmlTemplate || '';
    let textContent = template.textTemplate || '';

    // Replace variables in templates
    for (const [key, value] of Object.entries(variables)) {
      const placeholder = `{{${key}}}`;
      subject = subject.replace(new RegExp(placeholder, 'g'), String(value));
      htmlContent = htmlContent.replace(new RegExp(placeholder, 'g'), String(value));
      textContent = textContent.replace(new RegExp(placeholder, 'g'), String(value));
    }

    return { subject, htmlContent, textContent };
  }

  private applyTenantBranding(htmlContent: string, branding: any): string {
    if (!branding) return htmlContent;

    // Apply branding styles
    const brandedHtml = htmlContent.replace(
      '<body>',
      `<body style="font-family: ${branding.fontFamily || 'Inter, sans-serif'}; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
          ${branding.logoUrl ? `<img src="${branding.logoUrl}" alt="Logo" style="max-width: 200px; margin-bottom: 20px;">` : ''}
      `
    ).replace(
      '</body>',
      `        </div>
      </body>`
    );

    return brandedHtml;
  }
}
