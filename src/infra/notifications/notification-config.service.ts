import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NotificationConfig } from './ports/notification.ports';

@Injectable()
export class NotificationConfigService {
  constructor(private readonly configService: ConfigService) {}

  getConfig(): NotificationConfig {
    return {
      email: {
        provider: this.getEmailProvider(),
        enabled: this.configService.get<boolean>('app.EMAIL_ENABLED', false),
        defaultFrom: this.configService.get<string>('app.EMAIL_FROM', 'noreply@shooterista.com'),
        defaultReplyTo: this.configService.get<string>('app.EMAIL_REPLY_TO'),
        rateLimitPerMinute: this.configService.get<number>('app.EMAIL_RATE_LIMIT_PER_MINUTE', 60),
        rateLimitPerHour: this.configService.get<number>('app.EMAIL_RATE_LIMIT_PER_HOUR', 1000),
        rateLimitPerDay: this.configService.get<number>('app.EMAIL_RATE_LIMIT_PER_DAY', 10000),
      },
      
      smtp: this.getSmtpConfig(),
      ses: this.getSesConfig(),
      sendgrid: this.getSendGridConfig(),
      
      templates: {
        baseUrl: this.configService.get<string>('app.FRONTEND_URL', 'http://localhost:3000'),
        defaultLocale: this.configService.get<string>('app.DEFAULT_LOCALE', 'en'),
        supportedLocales: this.configService.get<string>('app.SUPPORTED_LOCALES', 'en').split(','),
      },
      
      tenant: {
        enabled: this.configService.get<boolean>('app.TENANT_BRANDING_ENABLED', false),
        defaultBranding: {
          logoUrl: this.configService.get<string>('app.DEFAULT_LOGO_URL'),
          primaryColor: this.configService.get<string>('app.DEFAULT_PRIMARY_COLOR', '#3B82F6'),
          secondaryColor: this.configService.get<string>('app.DEFAULT_SECONDARY_COLOR', '#1E40AF'),
          fontFamily: this.configService.get<string>('app.DEFAULT_FONT_FAMILY', 'Inter, sans-serif'),
        },
      },
    };
  }

  getEmailProvider(): 'console' | 'smtp' | 'ses' | 'sendgrid' {
    const provider = this.configService.get<string>('app.EMAIL_PROVIDER', 'console');
    
    if (typeof provider === 'string' && !['console', 'smtp', 'ses', 'sendgrid'].includes(provider)) {
      console.warn(`Invalid email provider: ${provider}. Falling back to console.`);
      return 'console';
    }
    
    return provider as 'console' | 'smtp' | 'ses' | 'sendgrid';
  }

  private getSmtpConfig() {
    const host = this.configService.get<string>('app.SMTP_HOST');
    if (!host) return undefined;

    return {
      host,
      port: this.configService.get<number>('app.SMTP_PORT', 587),
      secure: this.configService.get<boolean>('app.SMTP_SECURE', false),
      username: this.configService.get<string>('app.SMTP_USERNAME') || this.configService.get<string>('app.SMTP_USER'),
      password: this.configService.get<string>('app.SMTP_PASSWORD') || this.configService.get<string>('app.SMTP_PASS'),
      timeout: this.configService.get<number>('app.SMTP_TIMEOUT', 30000),
    };
  }

  private getSesConfig() {
    const region = this.configService.get<string>('app.SES_REGION');
    const accessKeyId = this.configService.get<string>('app.SES_ACCESS_KEY_ID');
    const secretAccessKey = this.configService.get<string>('app.SES_SECRET_ACCESS_KEY');
    
    if (!region || !accessKeyId || !secretAccessKey) return undefined;

    return {
      region,
      accessKeyId,
      secretAccessKey,
      configurationSet: this.configService.get<string>('app.SES_CONFIGURATION_SET'),
    };
  }

  private getSendGridConfig() {
    const apiKey = this.configService.get<string>('app.SENDGRID_API_KEY');
    if (!apiKey) return undefined;

    return {
      apiKey,
      fromEmail: this.configService.get<string>('app.SENDGRID_FROM_EMAIL', 'noreply@shooterista.com'),
      fromName: this.configService.get<string>('app.SENDGRID_FROM_NAME', 'Shooterista'),
    };
  }

  // Tenant-specific configuration methods
  getTenantConfig(tenantId?: string): Partial<NotificationConfig> {
    if (!tenantId) return {};

    // In a real implementation, you would fetch tenant-specific config from database
    // For now, return default config
    return {
      email: {
        provider: this.getEmailProvider(),
        enabled: true,
        defaultFrom: this.configService.get<string>('app.EMAIL_FROM', 'noreply@shooterista.com'),
      },
    };
  }

  getTenantBranding(tenantId?: string) {
    if (!tenantId) {
      return this.getConfig().tenant?.defaultBranding;
    }

    // In a real implementation, you would fetch tenant branding from database
    // For now, return default branding
    return this.getConfig().tenant?.defaultBranding;
  }

  // Validation methods
  validateConfig(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    const config = this.getConfig();

    if (!config.email.enabled) {
      return { valid: true, errors: [] }; // Email disabled, no validation needed
    }

    // Validate provider-specific config
    switch (config.email.provider) {
      case 'smtp':
        if (!config.smtp) {
          errors.push('SMTP configuration is missing');
        } else {
          if (!config.smtp.host) errors.push('SMTP host is required');
          if (!config.smtp.port) errors.push('SMTP port is required');
        }
        break;
        
      case 'ses':
        if (!config.ses) {
          errors.push('SES configuration is missing');
        } else {
          if (!config.ses.region) errors.push('SES region is required');
          if (!config.ses.accessKeyId) errors.push('SES access key ID is required');
          if (!config.ses.secretAccessKey) errors.push('SES secret access key is required');
        }
        break;
        
      case 'sendgrid':
        if (!config.sendgrid) {
          errors.push('SendGrid configuration is missing');
        } else {
          if (!config.sendgrid.apiKey) errors.push('SendGrid API key is required');
        }
        break;
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  // Health check methods
  async checkProviderHealth(): Promise<{ provider: string; healthy: boolean; error?: string }> {
    const provider = this.getEmailProvider();
    
    try {
      switch (provider) {
        case 'smtp':
          return await this.checkSmtpHealth();
        case 'ses':
          return await this.checkSesHealth();
        case 'sendgrid':
          return await this.checkSendGridHealth();
        case 'console':
        default:
          return { provider: 'console', healthy: true };
      }
    } catch (error) {
      return {
        provider,
        healthy: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  private async checkSmtpHealth(): Promise<{ provider: string; healthy: boolean; error?: string }> {
    // In a real implementation, you would test SMTP connection
    return { provider: 'smtp', healthy: true };
  }

  private async checkSesHealth(): Promise<{ provider: string; healthy: boolean; error?: string }> {
    // In a real implementation, you would test SES connection
    return { provider: 'ses', healthy: true };
  }

  private async checkSendGridHealth(): Promise<{ provider: string; healthy: boolean; error?: string }> {
    // In a real implementation, you would test SendGrid API
    return { provider: 'sendgrid', healthy: true };
  }
}
