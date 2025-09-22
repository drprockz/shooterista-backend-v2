# 📧 Notifications Infrastructure

This document explains the ports/adapters pattern implementation for notifications, tenancy support, and future microservice extraction steps.

## 🏗️ Architecture Overview

The notifications infrastructure follows the **ports/adapters pattern** (hexagonal architecture) to ensure clean separation between domain logic and infrastructure concerns.

### Key Components

1. **Ports (Interfaces)**: Define contracts for external dependencies
2. **Adapters (Implementations)**: Concrete implementations of ports
3. **Services**: Orchestrate business logic using ports
4. **Tenant Context**: Manages multi-tenant configuration and branding

## 📁 File Structure

```
src/infra/
├── notifications/
│   ├── ports/
│   │   ├── send-email.port.ts          # Email sending interface
│   │   └── render-template.port.ts     # Template rendering interface
│   ├── adapters/
│   │   ├── smtp-email.adapter.ts       # SMTP implementation
│   │   ├── ses-email.adapter.ts         # AWS SES implementation (scaffold)
│   │   └── template-renderer.adapter.ts # Template rendering implementation
│   ├── notifications.service.ts         # Main orchestration service
│   └── notifications.module.ts          # NestJS module
├── tenant-context/
│   ├── tenant-context.service.ts        # Tenant metadata management
│   └── tenant-context.module.ts         # NestJS module
└── templates/
    ├── base.layout.html                 # Base email template
    ├── welcome-email.html               # Welcome email template
    └── otp-email.html                   # OTP email template
```

## 🔌 Ports (Interfaces)

### SendEmailPort

```typescript
interface SendEmailParams {
  to: string[];
  subject: string;
  html?: string;
  text?: string;
  templateKey?: string;
  data?: Record<string, any>;
  tenantMeta?: any;
}

interface SendEmailPort {
  send(params: SendEmailParams): Promise<SendEmailResult>;
}
```

### RenderTemplatePort

```typescript
interface RenderTemplateResult {
  html: string;
  text?: string;
}

interface RenderTemplatePort {
  render(templateKey: string, data: any, tenantMeta: any): Promise<RenderTemplateResult>;
}
```

## 🔧 Adapters (Implementations)

### SMTP Email Adapter

- **Purpose**: Send emails via SMTP servers (Gmail, Outlook, etc.)
- **Configuration**: Reads from `.env.development` in dev mode
- **Features**: 
  - Supports HTML and text emails
  - Tenant-specific from/reply-to addresses
  - Connection verification
  - Fail-fast validation for required environment variables

### SES Email Adapter

- **Purpose**: AWS Simple Email Service integration
- **Status**: Scaffold implementation (no-op)
- **Future**: Ready for AWS SES implementation

### Template Renderer Adapter

- **Purpose**: Render email templates with tenant branding
- **Features**:
  - Template file loading from `src/templates/`
  - Tenant branding application (colors, logo, fonts)
  - Variable substitution
  - Fallback templates for development
  - HTML to text conversion

## 🏢 Tenant Context

### TenantContextService

Manages tenant-specific configuration and metadata:

```typescript
interface TenantMeta {
  tenantId?: string;
  brandColors?: {
    primary: string;
    secondary: string;
  };
  logoUrl?: string;
  fromEmail?: string;
  replyToEmail?: string;
  provider: string;
}
```

### Tenant Resolution

The service extracts tenant information from:
- `X-Tenant-ID` header
- User context (`req.user.tenantId`)
- Cookies (`tenant-id`)
- Domain-based resolution (subdomain)

## 🚀 Usage Examples

### Domain Module Integration

```typescript
// In AuthService
constructor(
  private readonly notificationsService: NotificationsService,
  private readonly tenantContextService: TenantContextService,
) {}

async register(input: CreateUserInput): Promise<AuthPayload> {
  // ... user creation logic ...
  
  // Send welcome email
  const tenantMeta = this.tenantContextService.getTenantMeta({ tenantId: input.tenantId });
  await this.notificationsService.sendWelcomeEmail(user.email, user.firstName, tenantMeta);
  
  // Send OTP email
  await this.notificationsService.sendOTPEmail(user.email, otpCode, user.firstName, tenantMeta);
}
```

### Module Imports

```typescript
// In AuthModule
@Module({
  imports: [
    NotificationsModule,
    TenantContextModule,
  ],
  // ...
})
export class AuthModule {}
```

## ⚙️ Configuration

### Environment Variables

```bash
# SMTP Configuration (required in dev)
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="465"
SMTP_SECURE="true"
SMTP_USERNAME="your-email@gmail.com"
SMTP_PASSWORD="your-app-password"

# Email Configuration
EMAIL_FROM="noreply@shooterista.com"
EMAIL_REPLY_TO="support@shooterista.com"

# Tenant Branding
DEFAULT_PRIMARY_COLOR="#3B82F6"
DEFAULT_SECONDARY_COLOR="#1E40AF"
DEFAULT_LOGO_URL="https://example.com/logo.png"
DEFAULT_FONT_FAMILY="Inter, sans-serif"
```

### Development Environment

- Only loads `.env.development` in dev mode
- Logs `[ENV] Loaded from .env.development` on startup
- Fails fast if required SMTP variables are missing

## 📧 Email Templates

### Template Structure

Templates support:
- Tenant branding variables (`{{primaryColor}}`, `{{logoUrl}}`, etc.)
- Data variables (`{{firstName}}`, `{{code}}`, etc.)
- Conditional rendering (`{{#if logoUrl}}`)
- Fallback templates for development

### Available Templates

1. **welcome-email.html**: User registration welcome
2. **otp-email.html**: Email verification codes
3. **base.layout.html**: Base template with branding

## 🧪 Testing & Diagnostics

### Commands

```bash
# Build check
npm run build:check

# Prisma connection check
npm run prisma:check

# Notifications diagnostics
npm run diag:notifications
```

### Development Test Email

GraphQL mutation for testing (dev only):

```graphql
mutation SendTestEmail($to: String!) {
  sendTestEmail(to: $to)
}
```

### Unit Testing

```typescript
describe('NotificationsService', () => {
  let service: NotificationsService;
  let mockSendEmailPort: jest.Mocked<SendEmailPort>;
  let mockRenderTemplatePort: jest.Mocked<RenderTemplatePort>;

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      providers: [
        NotificationsService,
        { provide: 'SEND_EMAIL_PORT', useValue: mockSendEmailPort },
        { provide: 'RENDER_TEMPLATE_PORT', useValue: mockRenderTemplatePort },
      ],
    }).compile();

    service = module.get<NotificationsService>(NotificationsService);
  });

  it('should send welcome email', async () => {
    mockRenderTemplatePort.render.mockResolvedValue({
      html: '<h1>Welcome!</h1>',
      text: 'Welcome!',
    });
    
    mockSendEmailPort.send.mockResolvedValue({
      success: true,
      messageId: 'test-123',
      provider: 'smtp',
      timestamp: new Date(),
    });

    const result = await service.sendWelcomeEmail('test@example.com', 'John');
    
    expect(result.success).toBe(true);
    expect(mockSendEmailPort.send).toHaveBeenCalled();
  });
});
```

## 🔄 Microservice Extraction

### Step 1: Extract Domain Interfaces

Move ports to a shared package:

```typescript
// @shooterista/notifications-contracts
export interface SendEmailPort { ... }
export interface RenderTemplatePort { ... }
export interface TenantMeta { ... }
```

### Step 2: Create Notifications Service

```typescript
// notifications-service/src/app.module.ts
@Module({
  imports: [
    ConfigModule.forRoot(),
    NotificationsModule,
    TenantContextModule,
  ],
  controllers: [NotificationsController],
})
export class AppModule {}
```

### Step 3: Update Domain Services

Replace direct service calls with HTTP calls:

```typescript
// Before (direct injection)
constructor(private readonly notificationsService: NotificationsService) {}

// After (HTTP client)
constructor(private readonly httpService: HttpService) {}

async sendWelcomeEmail(email: string, firstName: string) {
  return this.httpService.post('/notifications/send', {
    templateKey: 'welcome-email',
    data: { firstName },
    to: [email],
  }).toPromise();
}
```

### Step 4: Environment Configuration

```bash
# Domain services
NOTIFICATIONS_SERVICE_URL="http://notifications-service:3000"
NOTIFICATIONS_SERVICE_API_KEY="your-api-key"

# Notifications service
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="465"
# ... other SMTP config
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
```

### Template Errors

Fallback to default templates if custom templates fail:

```typescript
if (!fs.existsSync(templatePath)) {
  this.logger.warn(`Template ${templateKey} not found, using fallback`);
  return this.getFallbackTemplate(templateKey, data, tenantMeta);
}
```

## 🔒 Security Considerations

### Rate Limiting

```typescript
// Optional rate limiting hooks
async checkRateLimit(email: string, templateKey: string): Promise<boolean> {
  // TODO: Implement rate limiting logic
  return true;
}
```

### Input Validation

```typescript
// Validate email addresses
validateEmailAddress(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}
```

### Sensitive Data Protection

- Never log email content
- Mask email addresses in logs
- Secure SMTP credentials in environment variables

## 📊 Monitoring & Health Checks

### Health Check Endpoint

```typescript
@Get('health')
async healthCheck() {
  return {
    status: 'healthy',
    provider: 'smtp',
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
```

## 🎯 Best Practices

1. **Always use ports**: Depend on interfaces, not concrete implementations
2. **Include tenant context**: Pass tenant metadata for branding
3. **Handle errors gracefully**: Check result.success before proceeding
4. **Use appropriate providers**: SMTP for development, SES/SendGrid for production
5. **Monitor and log**: Track email metrics and failures
6. **Validate inputs**: Always validate email addresses and content
7. **Respect rate limits**: Implement proper rate limiting
8. **Test thoroughly**: Test with different providers and scenarios

## 🔧 Troubleshooting

### Common Issues

1. **SMTP Connection Failed**
   - Check SMTP credentials and server settings
   - Verify firewall and network connectivity
   - Test with telnet: `telnet smtp.gmail.com 587`

2. **Template Not Found**
   - Check template file exists in `src/templates/`
   - Verify template name matches exactly
   - Fallback templates will be used automatically

3. **Tenant Context Missing**
   - Check tenant ID extraction logic
   - Verify headers/cookies are set correctly
   - Default tenant meta will be used

### Debug Mode

Enable debug logging:

```bash
LOG_LEVEL="debug"
VERBOSE_LOGGING="true"
```

## 📚 Additional Resources

- [Ports and Adapters Pattern](https://herbertograca.com/2017/09/14/ports-adapters-architecture/)
- [Hexagonal Architecture](https://alistair.cockburn.us/hexagonal-architecture/)
- [Nodemailer Documentation](https://nodemailer.com/)
- [AWS SES Documentation](https://docs.aws.amazon.com/ses/)

## 🚀 Future Enhancements

1. **SES Adapter Implementation**: Complete AWS SES integration
2. **SendGrid Adapter**: Add SendGrid email service support
3. **Template Management**: Dynamic template loading from database
4. **Advanced Branding**: More sophisticated tenant branding options
5. **Analytics Integration**: Email delivery tracking and analytics
6. **Queue System**: Async email processing with retry logic
7. **Multi-language Support**: Internationalization for email templates
