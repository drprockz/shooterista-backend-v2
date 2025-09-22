# 📧 Notifications Infrastructure

This document describes the notifications infrastructure implemented using the ports/adapters pattern for clean separation of concerns and future microservice readiness.

## 🏗️ Architecture Overview

The notifications infrastructure follows the **ports/adapters pattern** (also known as hexagonal architecture) to ensure:

- **Domain isolation**: Business logic is separated from infrastructure concerns
- **Provider abstraction**: Easy switching between email providers (SMTP, SES, SendGrid, Console)
- **Multi-tenant support**: Tenant-specific branding and configuration
- **Microservice ready**: Can be extracted to a separate service without changing domain code
- **Testability**: Easy to mock and test with different providers

## 📁 File Structure

```
src/infra/notifications/
├── notifications.module.ts          # Main module with provider factory
├── notification.service.ts          # Main service implementing INotificationService
├── notification-config.service.ts   # Configuration management
├── ports/
│   └── notification.ports.ts        # Domain interfaces (ports)
└── adapters/
    ├── console-email.adapter.ts     # Console adapter (development)
    ├── smtp-email.adapter.ts        # SMTP adapter (nodemailer)
    ├── ses-email.adapter.ts         # AWS SES adapter
    └── sendgrid-email.adapter.ts    # SendGrid adapter
```

## 🔌 Ports (Interfaces)

### Core Interfaces

- **`INotificationService`**: Main service interface
- **`EmailProvider`**: Email provider interface
- **`NotificationMessage`**: Base message interface
- **`EmailMessage`**: Email-specific message interface
- **`NotificationContext`**: Context for multi-tenant support

### Provider Capabilities

Each provider exposes its capabilities:

```typescript
interface NotificationCapabilities {
  supportsHtml: boolean;
  supportsAttachments: boolean;
  supportsTemplates: boolean;
  supportsBulk: boolean;
  maxRecipients: number;
  maxAttachmentSize: number;
  supportedAttachmentTypes: string[];
}
```

## 🔧 Adapters (Implementations)

### 1. Console Adapter (`console-email.adapter.ts`)
- **Purpose**: Development and testing
- **Features**: Logs emails to console with full content
- **Capabilities**: HTML support, bulk sending, no attachments

### 2. SMTP Adapter (`smtp-email.adapter.ts`)
- **Purpose**: Traditional SMTP servers (Gmail, Outlook, etc.)
- **Features**: Full email support with attachments
- **Dependencies**: `nodemailer`
- **Capabilities**: HTML, attachments, individual sending only

### 3. SES Adapter (`ses-email.adapter.ts`)
- **Purpose**: AWS Simple Email Service
- **Features**: High deliverability, detailed analytics
- **Dependencies**: `@aws-sdk/client-ses`
- **Capabilities**: HTML, attachments, bulk sending

### 4. SendGrid Adapter (`sendgrid-email.adapter.ts`)
- **Purpose**: SendGrid email service
- **Features**: Advanced analytics, templates, deliverability
- **Dependencies**: `@sendgrid/mail`
- **Capabilities**: HTML, attachments, bulk sending, templates

## ⚙️ Configuration

### Environment Variables

```bash
# Email Provider Configuration
EMAIL_ENABLED="true"
EMAIL_PROVIDER="console"  # console, smtp, ses, sendgrid
EMAIL_FROM="noreply@shooterista.com"
EMAIL_REPLY_TO="support@shooterista.com"

# Rate Limiting
EMAIL_RATE_LIMIT_PER_MINUTE="60"
EMAIL_RATE_LIMIT_PER_HOUR="1000"
EMAIL_RATE_LIMIT_PER_DAY="10000"

# SMTP Configuration
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="465"
SMTP_SECURE="true"
SMTP_USERNAME="your-email@gmail.com"
SMTP_PASSWORD="your-app-password"
SMTP_TIMEOUT="30000"

# AWS SES Configuration
SES_REGION="us-east-1"
SES_ACCESS_KEY_ID="your-access-key"
SES_SECRET_ACCESS_KEY="your-secret-key"
SES_CONFIGURATION_SET="your-config-set"

# SendGrid Configuration
SENDGRID_API_KEY="your-sendgrid-api-key"
SENDGRID_FROM_EMAIL="noreply@shooterista.com"
SENDGRID_FROM_NAME="Shooterista"

# Frontend Configuration
FRONTEND_URL="http://localhost:3000"
DEFAULT_LOCALE="en"
SUPPORTED_LOCALES="en"

# Tenant Branding
TENANT_BRANDING_ENABLED="false"
DEFAULT_PRIMARY_COLOR="#3B82F6"
DEFAULT_SECONDARY_COLOR="#1E40AF"
DEFAULT_FONT_FAMILY="Inter, sans-serif"
```

### Provider Selection

The provider is selected at runtime based on the `EMAIL_PROVIDER` environment variable:

```typescript
// In notifications.module.ts
{
  provide: 'EMAIL_ADAPTER',
  useFactory: (configService: NotificationConfigService) => {
    const provider = configService.getEmailProvider();
    
    switch (provider) {
      case 'smtp': return new SmtpEmailAdapter(configService);
      case 'ses': return new SesEmailAdapter(configService);
      case 'sendgrid': return new SendGridEmailAdapter(configService);
      case 'console':
      default: return new ConsoleEmailAdapter(configService);
    }
  },
  inject: [NotificationConfigService],
}
```

## 🚀 Usage Examples

### Basic Email Sending

```typescript
import { NotificationService } from '@/infra/notifications/notification.service';
import { EmailMessage, NotificationContext } from '@/infra/notifications/ports/notification.ports';

@Injectable()
export class MyService {
  constructor(private readonly notificationService: NotificationService) {}

  async sendWelcomeEmail(email: string, firstName: string, tenantId?: string) {
    const message: EmailMessage = {
      to: email,
      subject: 'Welcome to Shooterista!',
      content: `Hello ${firstName}, welcome to Shooterista!`,
      htmlContent: `
        <html>
          <body>
            <h1>Welcome ${firstName}!</h1>
            <p>Welcome to Shooterista!</p>
          </body>
        </html>
      `,
    };

    const context: NotificationContext = {
      tenantId,
      requestId: `welcome_${Date.now()}`,
    };

    const result = await this.notificationService.sendEmail(message, context);
    
    if (result.success) {
      console.log(`Email sent: ${result.messageId}`);
    } else {
      console.error(`Email failed: ${result.error}`);
    }
  }
}
```

### Bulk Email Sending

```typescript
async sendBulkEmails(recipients: string[], tenantId?: string) {
  const messages: EmailMessage[] = recipients.map(email => ({
    to: email,
    subject: 'Important Update',
    content: 'This is an important update from Shooterista.',
    htmlContent: '<p>This is an important update from Shooterista.</p>',
  }));

  const context: NotificationContext = {
    tenantId,
    requestId: `bulk_${Date.now()}`,
  };

  const results = await this.notificationService.sendBulkEmails(messages, context);
  
  const successCount = results.filter(r => r.success).length;
  console.log(`Sent ${successCount}/${results.length} emails successfully`);
}
```

### Templated Emails

```typescript
async sendTemplatedEmail(email: string, variables: Record<string, any>) {
  const result = await this.notificationService.sendTemplatedEmail(
    'welcome', // template ID
    email,
    variables,
    { tenantId: 'tenant-123' }
  );
  
  return result;
}
```

## 🏢 Multi-Tenant Support

### Tenant-Specific Configuration

The system supports tenant-specific branding and configuration:

```typescript
// Tenant branding is automatically applied to HTML emails
const tenantBranding = {
  logoUrl: 'https://tenant.com/logo.png',
  primaryColor: '#FF6B6B',
  secondaryColor: '#4ECDC4',
  fontFamily: 'Roboto, sans-serif',
};
```

### Context Propagation

Tenant context is propagated through the notification chain:

```typescript
const context: NotificationContext = {
  tenantId: 'tenant-123',
  userId: 'user-456',
  requestId: 'req-789',
  ipAddress: '192.168.1.1',
  userAgent: 'Mozilla/5.0...',
  locale: 'en-US',
  timezone: 'America/New_York',
};
```

## 🧪 Testing

### Test Script

Run the notification test script:

```bash
npx ts-node scripts/test-notifications.ts
```

This will:
- Initialize the notification service
- Test email sending with the configured provider
- Validate email addresses
- Check service health
- Display provider capabilities

### Unit Testing

```typescript
describe('NotificationService', () => {
  let service: NotificationService;
  let mockProvider: jest.Mocked<EmailProvider>;

  beforeEach(async () => {
    mockProvider = {
      sendEmail: jest.fn(),
      sendBulkEmails: jest.fn(),
      validateEmailAddress: jest.fn(),
      getDeliveryStatus: jest.fn(),
      name: 'test',
      version: '1.0.0',
      capabilities: {
        supportsHtml: true,
        supportsAttachments: false,
        supportsTemplates: false,
        supportsBulk: false,
        maxRecipients: 1,
        maxAttachmentSize: 0,
        supportedAttachmentTypes: [],
      },
    };

    const module = await Test.createTestingModule({
      providers: [
        NotificationService,
        { provide: 'EMAIL_ADAPTER', useValue: mockProvider },
      ],
    }).compile();

    service = module.get<NotificationService>(NotificationService);
  });

  it('should send email successfully', async () => {
    mockProvider.sendEmail.mockResolvedValue({
      success: true,
      messageId: 'test-123',
      provider: 'test',
      timestamp: new Date(),
    });

    const result = await service.sendEmail({
      to: 'test@example.com',
      subject: 'Test',
      content: 'Test content',
    });

    expect(result.success).toBe(true);
    expect(mockProvider.sendEmail).toHaveBeenCalled();
  });
});
```

## 🔄 Migration to Microservice

The ports/adapters pattern makes it easy to extract the notifications infrastructure into a separate microservice:

### 1. Extract Domain Interfaces
Move `notification.ports.ts` to a shared package or copy to the new service.

### 2. Create New Service
```typescript
// notifications-service/src/app.module.ts
@Module({
  imports: [
    ConfigModule.forRoot(),
    NotificationsModule,
  ],
  controllers: [NotificationsController],
})
export class AppModule {}
```

### 3. Update Domain Services
Replace direct notification service calls with HTTP calls:

```typescript
// Before (direct injection)
constructor(private readonly notificationService: NotificationService) {}

// After (HTTP client)
constructor(private readonly httpService: HttpService) {}

async sendEmail(message: EmailMessage, context?: NotificationContext) {
  return this.httpService.post('/notifications/email', {
    message,
    context,
  }).toPromise();
}
```

### 4. Environment Configuration
Update environment variables to point to the new service:

```bash
NOTIFICATIONS_SERVICE_URL="http://notifications-service:3000"
NOTIFICATIONS_SERVICE_API_KEY="your-api-key"
```

## 🚨 Error Handling

### Provider Errors

Each adapter handles provider-specific errors:

```typescript
// SMTP errors
catch (error) {
  if (error.code === 'ECONNREFUSED') {
    return { success: false, error: 'SMTP server unavailable' };
  }
  if (error.code === 'EAUTH') {
    return { success: false, error: 'SMTP authentication failed' };
  }
  return { success: false, error: error.message };
}

// SendGrid errors
catch (error) {
  if (error.response?.body?.errors) {
    const errorMessages = error.response.body.errors.map(err => err.message);
    return { success: false, error: errorMessages.join(', ') };
  }
  return { success: false, error: error.message };
}
```

### Retry Logic

Implement retry logic for transient failures:

```typescript
async sendEmailWithRetry(message: EmailMessage, context?: NotificationContext, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const result = await this.notificationService.sendEmail(message, context);
      if (result.success) return result;
      
      if (attempt === maxRetries) return result;
      
      // Wait before retry (exponential backoff)
      await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
    } catch (error) {
      if (attempt === maxRetries) throw error;
      await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
    }
  }
}
```

## 📊 Monitoring and Health Checks

### Health Check Endpoint

```typescript
@Get('health')
async healthCheck() {
  const health = await this.notificationService.healthCheck();
  return {
    status: health.healthy ? 'healthy' : 'unhealthy',
    provider: health.provider,
    error: health.error,
    timestamp: new Date(),
  };
}
```

### Metrics Collection

```typescript
// Track email metrics
const metrics = {
  emailsSent: 0,
  emailsFailed: 0,
  averageLatency: 0,
  providerErrors: {},
};

// Update metrics after each email
if (result.success) {
  metrics.emailsSent++;
} else {
  metrics.emailsFailed++;
  metrics.providerErrors[result.provider] = 
    (metrics.providerErrors[result.provider] || 0) + 1;
}
```

## 🔒 Security Considerations

### Rate Limiting

Implement rate limiting to prevent abuse:

```typescript
// In notification-config.service.ts
getRateLimitConfig() {
  return {
    perMinute: this.configService.get<number>('app.EMAIL_RATE_LIMIT_PER_MINUTE', 60),
    perHour: this.configService.get<number>('app.EMAIL_RATE_LIMIT_PER_HOUR', 1000),
    perDay: this.configService.get<number>('app.EMAIL_RATE_LIMIT_PER_DAY', 10000),
  };
}
```

### Input Validation

Validate all inputs before sending:

```typescript
validateMessage(message: EmailMessage): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!message.to || (Array.isArray(message.to) && message.to.length === 0)) {
    errors.push('Recipients are required');
  }
  
  if (!message.subject || message.subject.trim().length === 0) {
    errors.push('Subject is required');
  }
  
  if (!message.content && !message.htmlContent) {
    errors.push('Email content is required');
  }
  
  return { valid: errors.length === 0, errors };
}
```

### Sensitive Data Protection

Never log sensitive information:

```typescript
// Safe logging
this.logger.log(`Email sent to ${email.replace(/(.{2}).*(@.*)/, '$1***$2')}`);

// Avoid logging
// this.logger.log(`Email content: ${message.content}`); // DON'T DO THIS
```

## 🎯 Best Practices

1. **Always use the notification service interface** - Don't inject adapters directly
2. **Include context information** - Pass tenant, user, and request context
3. **Handle errors gracefully** - Check result.success before proceeding
4. **Use appropriate providers** - Console for dev, SMTP/SES/SendGrid for production
5. **Monitor and log** - Track email metrics and failures
6. **Validate inputs** - Always validate email addresses and content
7. **Respect rate limits** - Implement proper rate limiting
8. **Test thoroughly** - Test with different providers and scenarios

## 🔧 Troubleshooting

### Common Issues

1. **SMTP Connection Failed**
   - Check SMTP credentials and server settings
   - Verify firewall and network connectivity
   - Test with telnet: `telnet smtp.gmail.com 587`

2. **SendGrid API Errors**
   - Verify API key is correct and has send permissions
   - Check sender verification status
   - Review SendGrid activity logs

3. **SES Authentication Failed**
   - Verify AWS credentials and permissions
   - Check SES region configuration
   - Ensure sender email is verified in SES

4. **Email Not Delivered**
   - Check spam folders
   - Verify email addresses are valid
   - Review provider delivery logs
   - Check DNS records (SPF, DKIM, DMARC)

### Debug Mode

Enable debug logging:

```bash
LOG_LEVEL="debug"
VERBOSE_LOGGING="true"
```

This will provide detailed logs of the notification process.

## 📚 Additional Resources

- [Nodemailer Documentation](https://nodemailer.com/)
- [AWS SES Documentation](https://docs.aws.amazon.com/ses/)
- [SendGrid Documentation](https://docs.sendgrid.com/)
- [Ports and Adapters Pattern](https://herbertograca.com/2017/09/14/ports-adapters-architecture/)
- [Hexagonal Architecture](https://alistair.cockburn.us/hexagonal-architecture/)
