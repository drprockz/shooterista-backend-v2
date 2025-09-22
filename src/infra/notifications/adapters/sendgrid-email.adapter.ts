import { Injectable, Logger } from '@nestjs/common';
import { EmailProvider, EmailMessage, NotificationContext, NotificationResult, EmailDeliveryStatus } from '../ports/notification.ports';
import { NotificationConfigService } from '../notification-config.service';
import * as sgMail from '@sendgrid/mail';

@Injectable()
export class SendGridEmailAdapter implements EmailProvider {
  private readonly logger = new Logger(SendGridEmailAdapter.name);
  private initialized = false;

  constructor(private readonly configService: NotificationConfigService) {}

  get name(): string {
    return 'sendgrid';
  }

  get version(): string {
    return '1.0.0';
  }

  get capabilities() {
    return {
      supportsHtml: true,
      supportsAttachments: true,
      supportsTemplates: true,
      supportsBulk: true,
      maxRecipients: 1000, // SendGrid limit per email
      maxAttachmentSize: 25 * 1024 * 1024, // 25MB
      supportedAttachmentTypes: ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain', 'application/zip', 'text/csv'],
    };
  }

  async sendEmail(message: EmailMessage, context?: NotificationContext): Promise<NotificationResult> {
    try {
      await this.initialize();
      const messageId = `sendgrid_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      // Prepare SendGrid email
      const msg: any = {
        to: Array.isArray(message.to) ? message.to : [message.to],
        from: {
          email: message.from || this.configService.getConfig().email.defaultFrom,
          name: this.configService.getConfig().sendgrid?.fromName || 'Shooterista',
        },
        subject: message.subject,
        text: message.content,
        html: message.htmlContent,
        customArgs: {
          messageId,
          tenantId: context?.tenantId || '',
          requestId: context?.requestId || '',
        },
      };

      // Add reply-to if specified
      if (message.replyTo) {
        msg.replyTo = {
          email: message.replyTo,
        };
      }

      // Add CC if specified
      if (message.cc) {
        msg.cc = Array.isArray(message.cc) ? message.cc : [message.cc];
      }

      // Add BCC if specified
      if (message.bcc) {
        msg.bcc = Array.isArray(message.bcc) ? message.bcc : [message.bcc];
      }

      // Add custom headers
      if (message.headers) {
        msg.headers = message.headers;
      }

      // Add attachments if specified
      if (message.attachments && message.attachments.length > 0) {
        msg.attachments = message.attachments.map(attachment => ({
          filename: attachment.filename,
          content: Buffer.isBuffer(attachment.content) 
            ? attachment.content.toString('base64')
            : Buffer.from(attachment.content).toString('base64'),
          type: attachment.contentType,
          disposition: attachment.disposition || 'attachment',
          contentId: attachment.cid,
        }));
      }

      // Add tracking settings
      msg.trackingSettings = {
        clickTracking: {
          enable: true,
          enableText: false,
        },
        openTracking: {
          enable: true,
        },
      };

      this.logger.debug(`Sending SendGrid email to ${msg.to.join(', ')}`);

      // Send email
      const [response] = await sgMail.send(msg);

      this.logger.log(`SendGrid email sent successfully. Message ID: ${(response as any).headers?.['x-message-id'] || messageId}`);

      return {
        success: true,
        messageId: (response as any).headers?.['x-message-id'] as string || messageId,
        provider: this.name,
        timestamp: new Date(),
      };
    } catch (error) {
      this.logger.error(`Failed to send SendGrid email: ${error instanceof Error ? error.message : 'Unknown error'}`);
      
      // Handle SendGrid specific errors
      if (error && typeof error === 'object' && 'response' in error) {
        const sgError = error as any;
        if (sgError.response && sgError.response.body && sgError.response.body.errors) {
          const errorMessages = sgError.response.body.errors.map((err: any) => err.message).join(', ');
          return {
            success: false,
            error: `SendGrid error: ${errorMessages}`,
            provider: this.name,
            timestamp: new Date(),
          };
        }
      }

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        provider: this.name,
        timestamp: new Date(),
      };
    }
  }

  async sendBulkEmails(messages: EmailMessage[], context?: NotificationContext): Promise<NotificationResult[]> {
    try {
      await this.initialize();
      this.logger.log(`Sending ${messages.length} emails via SendGrid bulk API`);

      // Prepare bulk email data
      const bulkMessages = messages.map((message, index) => {
        const messageId = `sendgrid_bulk_${Date.now()}_${index}_${Math.random().toString(36).substr(2, 9)}`;
        
        return {
          to: Array.isArray(message.to) ? message.to : [message.to],
          from: {
            email: message.from || this.configService.getConfig().email.defaultFrom,
            name: this.configService.getConfig().sendgrid?.fromName || 'Shooterista',
          },
          subject: message.subject,
          text: message.content,
          html: message.htmlContent,
          customArgs: {
            messageId,
            tenantId: context?.tenantId || '',
            requestId: context?.requestId || '',
          },
        };
      });

      // Send bulk emails
      const responses = await sgMail.send(bulkMessages);

      // Process responses
      const results: NotificationResult[] = responses.map((response, index) => ({
        success: true,
        messageId: (response as any).headers?.['x-message-id'] as string || `sendgrid_bulk_${Date.now()}_${index}`,
        provider: this.name,
        timestamp: new Date(),
      }));

      this.logger.log(`SendGrid bulk emails sent successfully. ${results.length} messages processed`);

      return results;
    } catch (error) {
      this.logger.error(`Failed to send SendGrid bulk emails: ${error instanceof Error ? error.message : 'Unknown error'}`);
      
      // Return failed results for all messages
      return messages.map(() => ({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        provider: this.name,
        timestamp: new Date(),
      }));
    }
  }

  validateEmailAddress(email: string): boolean {
    // SendGrid has specific email validation requirements
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    
    if (!emailRegex.test(email)) {
      return false;
    }

    const parts = email.split('@');
    if (parts.length !== 2) {
      return false;
    }

    const [localPart, domain] = parts;
    
    // SendGrid specific validations
    if (localPart.length === 0 || localPart.length > 64) {
      return false;
    }

    if (domain.length === 0 || domain.length > 253) {
      return false;
    }

    // Check for invalid characters
    if (localPart.includes('..') || domain.includes('..')) {
      return false;
    }

    // Check for leading/trailing dots
    if (localPart.startsWith('.') || localPart.endsWith('.') || 
        domain.startsWith('.') || domain.endsWith('.')) {
      return false;
    }

    // SendGrid doesn't allow certain characters
    const invalidChars = /[<>]/;
    if (invalidChars.test(email)) {
      return false;
    }

    return true;
  }

  async getDeliveryStatus(messageId: string): Promise<EmailDeliveryStatus> {
    try {
      // SendGrid provides delivery status through webhooks
      // In a real implementation, you would query your delivery status store
      // For now, we'll return a placeholder
      return {
        messageId,
        status: 'sent', // SendGrid doesn't provide real-time delivery status
        timestamp: new Date(),
      };
    } catch (error) {
      return {
        messageId,
        status: 'unknown',
        timestamp: new Date(),
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  private async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    const config = this.configService.getConfig();
    const sendgridConfig = config.sendgrid;

    if (!sendgridConfig) {
      throw new Error('SendGrid configuration is missing');
    }

    if (!sendgridConfig.apiKey) {
      throw new Error('SendGrid API key is required');
    }

    // Initialize SendGrid
    sgMail.setApiKey(sendgridConfig.apiKey);

    this.initialized = true;
    this.logger.log('SendGrid client initialized successfully');
  }

  // Health check method
  async healthCheck(): Promise<{ healthy: boolean; error?: string }> {
    try {
      await this.initialize();
      
      // Test SendGrid connection by sending a test email to a non-existent address
      // This will fail but will validate the API key
      const testMsg = {
        to: 'test@example.com',
        from: 'test@shooterista.com',
        subject: 'Test',
        text: 'Test',
      };

      try {
        await sgMail.send(testMsg);
      } catch (error) {
        // Expected to fail, but validates API key
        if (error && typeof error === 'object' && 'response' in error) {
          const sgError = error as any;
          if (sgError.response && sgError.response.status === 400) {
            // 400 means API key is valid but email is invalid (expected)
            return { healthy: true };
          }
        }
        throw error;
      }

      return { healthy: true };
    } catch (error) {
      return {
        healthy: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }
}
