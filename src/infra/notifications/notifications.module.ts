import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { NotificationsService } from './notifications.service';
import { SmtpEmailAdapter } from './adapters/smtp-email.adapter';
import { SesEmailAdapter } from './adapters/ses-email.adapter';
import { TemplateRendererAdapter } from './adapters/template-renderer.adapter';
import { TenantContextModule } from '../tenant-context/tenant-context.module';

@Module({
  imports: [
    ConfigModule,
    TenantContextModule,
  ],
  providers: [
    NotificationsService,
    TemplateRendererAdapter,
    {
      provide: 'SEND_EMAIL_PORT',
      useFactory: (configService: any) => {
        // For now, always use SMTP
        return new SmtpEmailAdapter(configService);
      },
      inject: [ConfigService],
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
