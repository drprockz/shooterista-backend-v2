import { Injectable, Logger } from '@nestjs/common';
import { EmailProvider, EmailMessage, NotificationContext, NotificationResult, EmailDeliveryStatus } from '../ports/notification.ports';
import { NotificationConfigService } from '../notification-config.service';

@Injectable()
export class ConsoleEmailAdapter implements EmailProvider {
  private readonly logger = new Logger(ConsoleEmailAdapter.name);

  constructor(private readonly configService: NotificationConfigService) {}

  get name(): string {
    return 'console';
  }

  get version(): string {
    return '1.0.0';
  }

  get capabilities() {
    return {
      supportsHtml: true,
      supportsAttachments: false,
      supportsTemplates: true,
      supportsBulk: true,
      maxRecipients: 1000,
      maxAttachmentSize: 0,
      supportedAttachmentTypes: [],
    };
  }

  async sendEmail(message: EmailMessage, context?: NotificationContext): Promise<NotificationResult> {
    const messageId = `console_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    this.logger.log(`📧 EMAIL SENT (Console Adapter)`);
    this.logger.log(`Message ID: ${messageId}`);
    this.logger.log(`To: ${Array.isArray(message.to) ? message.to.join(', ') : message.to}`);
    this.logger.log(`From: ${message.from || 'noreply@shooterista.com'}`);
    this.logger.log(`Subject: ${message.subject}`);
    
    if (context?.tenantId) {
      this.logger.log(`Tenant: ${context.tenantId}`);
    }
    
    if (context?.requestId) {
      this.logger.log(`Request ID: ${context.requestId}`);
    }

    // Log email content
    console.log(`
    ========================================
    EMAIL CONTENT
    ========================================
    ${message.htmlContent || message.content}
    ========================================
    `);

    // Log attachments if any
    if (message.attachments && message.attachments.length > 0) {
      this.logger.log(`Attachments: ${message.attachments.length} files`);
      message.attachments.forEach((attachment, index) => {
        this.logger.log(`  ${index + 1}. ${attachment.filename} (${attachment.contentType})`);
      });
    }

    return {
      success: true,
      messageId,
      provider: this.name,
      timestamp: new Date(),
    };
  }

  async sendBulkEmails(messages: EmailMessage[], context?: NotificationContext): Promise<NotificationResult[]> {
    this.logger.log(`📧 BULK EMAIL SENT (Console Adapter) - ${messages.length} messages`);
    
    const results: NotificationResult[] = [];
    
    for (let i = 0; i < messages.length; i++) {
      const message = messages[i];
      const messageId = `console_bulk_${Date.now()}_${i}_${Math.random().toString(36).substr(2, 9)}`;
      
      this.logger.log(`  ${i + 1}. To: ${Array.isArray(message.to) ? message.to.join(', ') : message.to} | Subject: ${message.subject}`);
      
      results.push({
        success: true,
        messageId,
        provider: this.name,
        timestamp: new Date(),
      });
    }

    return results;
  }

  validateEmailAddress(email: string): boolean {
    // Basic email validation regex
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  async getDeliveryStatus(messageId: string): Promise<EmailDeliveryStatus> {
    // Console adapter always reports as delivered
    return {
      messageId,
      status: 'delivered',
      timestamp: new Date(),
    };
  }
}
