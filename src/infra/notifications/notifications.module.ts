import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { NotificationsService } from './notifications.service';
import { SmtpEmailAdapter } from './adapters/smtp-email.adapter';
import { ConsoleEmailAdapter } from './adapters/console-email.adapter';
import { SesEmailAdapter } from './adapters/ses-email.adapter';
import { SendGridEmailAdapter } from './adapters/sendgrid-email.adapter';
import { TemplateRendererAdapter } from './adapters/template-renderer.adapter';
import { TenantContextModule } from '../tenant-context/tenant-context.module';
import { NotificationConfigService } from './notification-config.service';
import { SendEmailPort, SendEmailParams, SendEmailResult } from './ports/send-email.port';
import { EmailProvider, EmailMessage, NotificationContext } from './ports/notification.ports';

// Adapter to convert EmailProvider to SendEmailPort
class EmailProviderToSendEmailPortAdapter implements SendEmailPort {
  constructor(private readonly emailProvider: EmailProvider) {}

  async send(params: SendEmailParams): Promise<SendEmailResult> {
    console.log(`📧 [EMAIL ADAPTER] Converting SendEmailParams to EmailMessage`);
    console.log(`📧 [EMAIL ADAPTER] Provider: ${this.emailProvider.name}`);
    console.log(`📧 [EMAIL ADAPTER] To: ${params.to}`);
    console.log(`📧 [EMAIL ADAPTER] Subject: ${params.subject}`);
    
    const emailMessage: EmailMessage = {
      to: Array.isArray(params.to) ? params.to : [params.to],
      subject: params.subject,
      content: params.text,
      htmlContent: params.html,
      from: 'noreply@shooterista.com',
    };

    const context: NotificationContext = {
      tenantId: params.tenantMeta?.tenantId,
      requestId: `email_${Date.now()}`,
    };

    console.log(`📧 [EMAIL ADAPTER] Calling emailProvider.sendEmail()`);
    try {
      const result = await this.emailProvider.sendEmail(emailMessage, context);
      console.log(`📧 [EMAIL ADAPTER] emailProvider.sendEmail() result:`, result);
      
      return {
        success: result.success,
        messageId: result.messageId,
        error: result.error,
        provider: this.emailProvider.name,
        timestamp: result.timestamp,
      };
    } catch (error) {
      console.log(`❌ [EMAIL ADAPTER] Error in emailProvider.sendEmail():`, error.message);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        provider: this.emailProvider.name,
        timestamp: new Date(),
      };
    }
  }
}

@Module({
  imports: [
    ConfigModule,
    TenantContextModule,
  ],
  providers: [
    NotificationsService,
    TemplateRendererAdapter,
    NotificationConfigService,
    {
      provide: 'SEND_EMAIL_PORT',
      useFactory: (configService: ConfigService, notificationConfigService: NotificationConfigService) => {
        const emailProvider = notificationConfigService.getEmailProvider();
        console.log(`📧 [PROVIDER FACTORY] Selected email provider: ${emailProvider}`);
        
        switch (emailProvider) {
          case 'console':
            // ConsoleEmailAdapter implements EmailProvider
            console.log(`📧 [PROVIDER FACTORY] Creating ConsoleEmailAdapter`);
            const consoleProvider = new ConsoleEmailAdapter(notificationConfigService);
            return new EmailProviderToSendEmailPortAdapter(consoleProvider);
          case 'smtp':
            // SmtpEmailAdapter implements SendEmailPort directly
            console.log(`📧 [PROVIDER FACTORY] Creating SmtpEmailAdapter`);
            return new SmtpEmailAdapter(configService);
          case 'ses':
            // SesEmailAdapter implements SendEmailPort directly (no constructor params)
            console.log(`📧 [PROVIDER FACTORY] Creating SesEmailAdapter`);
            return new SesEmailAdapter();
          case 'sendgrid':
            // SendGridEmailAdapter implements EmailProvider
            console.log(`📧 [PROVIDER FACTORY] Creating SendGridEmailAdapter`);
            const sendgridProvider = new SendGridEmailAdapter(notificationConfigService);
            return new EmailProviderToSendEmailPortAdapter(sendgridProvider);
          default:
            console.warn(`📧 [PROVIDER FACTORY] Unknown email provider: ${emailProvider}. Falling back to console.`);
            const fallbackProvider = new ConsoleEmailAdapter(notificationConfigService);
            return new EmailProviderToSendEmailPortAdapter(fallbackProvider);
        }
      },
      inject: [ConfigService, NotificationConfigService],
    },
    {
      provide: 'RENDER_TEMPLATE_PORT',
      useClass: TemplateRendererAdapter,
    },
  ],
  exports: [
    NotificationsService,
  ],
})
export class NotificationsModule {}
