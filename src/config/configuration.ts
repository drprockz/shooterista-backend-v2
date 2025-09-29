import { registerAs } from '@nestjs/config';
import { z } from 'zod';

const schema = z.object({
  // Application
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(4000),
  API_VERSION: z.string().default('v1'),
  HOST: z.string().default('0.0.0.0'),

  // Database URLs
  REDIS_URL: z.string(),
  AUTH_DB_URL: z.string(),
  ATHLETES_DB_URL: z.string(),
  COMPETITIONS_DB_URL: z.string(),

  // JWT Configuration
  JWT_SECRET: z.string().min(32, 'JWT secret must be at least 32 characters'),
  JWT_PUBLIC_KEY_BASE64: z.string().optional(),
  JWT_PRIVATE_KEY_BASE64: z.string().optional(),
  JWT_ISS: z.string().default('shooterista-api'),
  JWT_AUD: z.string().default('shooterista-app'),
  JWT_EXPIRES_IN: z.string().default('15m'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),

  // S3/Object Storage
  S3_REGION: z.string().default('us-east-1'),
  S3_ENDPOINT: z.string().optional(),
  S3_BUCKET_NAME: z.string().default('shooterista-uploads'),
  S3_ACCESS_KEY_ID: z.string(),
  S3_SECRET_ACCESS_KEY: z.string(),
  S3_FORCE_PATH_STYLE: z.string().default('false').transform(val => val === 'true'),

  // GraphQL Configuration
  GRAPHQL_PLAYGROUND: z.string().default('false').transform(val => val === 'true'),
  GRAPHQL_INTROSPECTION: z.string().default('false').transform(val => val === 'true'),
  GRAPHQL_DEBUG: z.string().default('false').transform(val => val === 'true'),

  // Security Configuration
  CORS_ORIGINS: z.string().default('http://localhost:3000'),
  CORS_CREDENTIALS: z.string().default('true').transform(val => val === 'true'),
  RATE_LIMIT_TTL: z.coerce.number().default(60),
  RATE_LIMIT_LIMIT: z.coerce.number().default(100),
  HELMET_ENABLED: z.string().default('true').transform(val => val === 'true'),
  TRUST_PROXY: z.string().default('false').transform(val => val === 'true'),

  // Monitoring Configuration
  HEALTH_CHECK_DATABASE: z.string().default('true').transform(val => val === 'true'),
  HEALTH_CHECK_REDIS: z.string().default('true').transform(val => val === 'true'),
  HEALTH_CHECK_S3: z.string().default('true').transform(val => val === 'true'),
  METRICS_ENABLED: z.string().default('true').transform(val => val === 'true'),

  // Logging Configuration
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  LOG_FORMAT: z.enum(['json', 'pretty']).default('json'),

  // File Upload Configuration
  MAX_FILE_SIZE: z.coerce.number().default(10485760), // 10MB
  ALLOWED_FILE_TYPES: z.string().default('image/jpeg,image/png,image/gif,image/webp'),

  // Email/Notification Configuration
  EMAIL_ENABLED: z.string().default('false').transform(val => val === 'true'),
  EMAIL_PROVIDER: z.enum(['console', 'smtp', 'ses', 'sendgrid']).default('console'),
  EMAIL_FROM: z.string().default('noreply@shooterista.com'),
  EMAIL_REPLY_TO: z.string().optional(),
  EMAIL_RATE_LIMIT_PER_MINUTE: z.coerce.number().default(60),
  EMAIL_RATE_LIMIT_PER_HOUR: z.coerce.number().default(1000),
  EMAIL_RATE_LIMIT_PER_DAY: z.coerce.number().default(10000),
  EMAIL_VERIFICATION_ENABLED: z.string().default('false').transform(val => val === 'true'),
  EMAIL_RESET_PASSWORD_ENABLED: z.string().default('false').transform(val => val === 'true'),

  // SMTP Configuration
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().default(587),
  SMTP_SECURE: z.string().default('false').transform(val => val === 'true'),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_USERNAME: z.string().optional(),
  SMTP_PASSWORD: z.string().optional(),
  SMTP_TIMEOUT: z.coerce.number().default(30000),

  // AWS SES Configuration
  SES_REGION: z.string().optional(),
  SES_ACCESS_KEY_ID: z.string().optional(),
  SES_SECRET_ACCESS_KEY: z.string().optional(),
  SES_CONFIGURATION_SET: z.string().optional(),

  // SendGrid Configuration
  SENDGRID_API_KEY: z.string().optional(),
  SENDGRID_FROM_EMAIL: z.string().default('noreply@shooterista.com'),
  SENDGRID_FROM_NAME: z.string().default('Shooterista'),

  // Frontend Configuration
  FRONTEND_URL: z.string().default('http://localhost:3000'),
  DEFAULT_LOCALE: z.string().default('en'),
  SUPPORTED_LOCALES: z.string().default('en'),

  // Tenant Branding Configuration
  TENANT_BRANDING_ENABLED: z.string().default('false').transform(val => val === 'true'),
  DEFAULT_LOGO_URL: z.string().optional().transform(val => val === '' ? undefined : val),
  DEFAULT_PRIMARY_COLOR: z.string().default('#3B82F6'),
  DEFAULT_SECONDARY_COLOR: z.string().default('#1E40AF'),
  DEFAULT_FONT_FAMILY: z.string().default('Inter, sans-serif'),

  // OTP Configuration
  OTP_LENGTH: z.coerce.number().default(6),
  OTP_EXPIRY_MINUTES: z.coerce.number().default(5),
  OTP_MAX_ATTEMPTS: z.coerce.number().default(3),
  OTP_COOLDOWN_MINUTES: z.coerce.number().default(1),

  // Profile Completion Configuration
  FEATURE_REQUIRE_PROFILE_COMPLETION: z.string().default('true').transform(val => val === 'true'),
  PROFILE_APPROVAL_REQUIRED: z.string().default('true').transform(val => val === 'true'),
  PROFILE_MIN_COMPLETION_PERCENTAGE: z.coerce.number().default(80),
  PROFILE_SECTION_COMPLETION_THRESHOLD: z.coerce.number().default(20), // 20% per section
  
  // OTP Requirements
  OTP_EMAIL_REQUIRED_FOR_REGISTER: z.string().default('true').transform(val => val === 'true'),
  OTP_PHONE_REQUIRED_FOR_CONTACT: z.string().default('false').transform(val => val === 'true'),
  
  // OTP Cooldowns and Limits
  OTP_REQUEST_COOLDOWN_SEC: z.coerce.number().default(60),
  OTP_MAX_ATTEMPTS_PER_EMAIL: z.coerce.number().default(5),
  OTP_TTL_SEC: z.coerce.number().default(300), // 5 minutes

  // Security Configuration
  SECURITY_MAX_FAILED_LOGINS: z.coerce.number().default(5),
  SECURITY_LOCKOUT_DURATION: z.coerce.number().default(30),
  SECURITY_SESSION_TIMEOUT: z.coerce.number().default(30),
  SECURITY_PASSWORD_MIN_AGE: z.coerce.number().default(1),
  SECURITY_REQUIRE_STRONG_PASSWORDS: z.string().default('true').transform(val => val === 'true'),
  SECURITY_ENABLE_MFA: z.string().default('true').transform(val => val === 'true'),
  SECURITY_AUDIT_RETENTION: z.coerce.number().default(90),

  // Rate Limiting Configuration
  RATE_LIMIT_LOGIN_MAX: z.coerce.number().default(5),
  RATE_LIMIT_LOGIN_WINDOW: z.coerce.number().default(900000), // 15 minutes
  RATE_LIMIT_LOGIN_BLOCK: z.coerce.number().default(3600000), // 1 hour
  RATE_LIMIT_PASSWORD_RESET_MAX: z.coerce.number().default(3),
  RATE_LIMIT_PASSWORD_RESET_WINDOW: z.coerce.number().default(3600000), // 1 hour
  RATE_LIMIT_PASSWORD_RESET_BLOCK: z.coerce.number().default(3600000), // 1 hour
  RATE_LIMIT_EMAIL_VERIFICATION_MAX: z.coerce.number().default(5),
  RATE_LIMIT_EMAIL_VERIFICATION_WINDOW: z.coerce.number().default(3600000), // 1 hour
  RATE_LIMIT_EMAIL_VERIFICATION_BLOCK: z.coerce.number().default(3600000), // 1 hour
  RATE_LIMIT_MFA_MAX: z.coerce.number().default(3),
  RATE_LIMIT_MFA_WINDOW: z.coerce.number().default(300000), // 5 minutes
  RATE_LIMIT_MFA_BLOCK: z.coerce.number().default(900000), // 15 minutes

  // Development Configuration
  DEBUG: z.string().optional(),
  VERBOSE_LOGGING: z.string().default('false').transform(val => val === 'true'),

  // Tenant Resolution Configuration
  TENANT_RESOLUTION_MODE: z.enum(['subdomain', 'env', 'header']).default('subdomain'),
  TENANT_OVERRIDE_SLUG: z.string().optional(),
  TENANT_OVERRIDE_ID: z.string().optional(),
});

export type AppConfig = z.infer<typeof schema>;

export default registerAs('app', () => {
  const parsed = schema.safeParse(process.env);
  if (!parsed.success) {
    console.error('❌ Invalid environment configuration:', parsed.error.flatten().fieldErrors);
    throw new Error(`Configuration validation failed: ${parsed.error.message}`);
  }
  
  const config = parsed.data;
  
  // Additional validation for development environment
  if (config.NODE_ENV === 'development') {
    const dbUrls = [config.AUTH_DB_URL, config.ATHLETES_DB_URL, config.COMPETITIONS_DB_URL];
    
    // Check if any database URL still points to localhost (should point to server)
    const localhostUrls = dbUrls.filter(url => typeof url === 'string' && url.includes('localhost'));
    if (localhostUrls.length > 0) {
      console.warn('⚠️  Warning: Database URLs are pointing to localhost in development mode.');
      console.warn('   Consider updating .env.development to use server URLs instead.');
      console.warn('   Current URLs:', localhostUrls);
    }
    
    // Check if any database URL contains placeholder values
    const placeholderUrls = dbUrls.filter(url => typeof url === 'string' && url.includes('your-server.com'));
    if (placeholderUrls.length > 0) {
      console.warn('⚠️  Warning: Database URLs contain placeholder values (your-server.com).');
      console.warn('   Please update .env.development with actual server URLs.');
    }
  }

  // Email configuration validation
  if (config.EMAIL_ENABLED && config.EMAIL_PROVIDER === 'smtp') {
    const requiredSmtpVars = ['SMTP_HOST', 'SMTP_PORT'];
    const missingSmtpVars = requiredSmtpVars.filter(varName => !process.env[varName]);
    
    if (missingSmtpVars.length > 0) {
      console.error('❌ Critical SMTP configuration missing:', missingSmtpVars.join(', '));
      throw new Error(`SMTP configuration validation failed: Missing required variables ${missingSmtpVars.join(', ')}`);
    }

    // Validate SMTP credentials if provided
    const smtpUser = process.env.SMTP_USERNAME || process.env.SMTP_USER;
    const smtpPass = process.env.SMTP_PASSWORD || process.env.SMTP_PASS;
    
    if (smtpUser && !smtpPass) {
      console.warn('⚠️  Warning: SMTP_USERNAME provided but SMTP_PASSWORD is missing');
    }
    if (smtpPass && !smtpUser) {
      console.warn('⚠️  Warning: SMTP_PASSWORD provided but SMTP_USERNAME is missing');
    }
  }

  // Logo URL validation and fallback
  if (config.DEFAULT_LOGO_URL === undefined) {
    console.warn('⚠️  Warning: DEFAULT_LOGO_URL not set. Email templates will use text fallback instead of logo.');
  } else if (config.DEFAULT_LOGO_URL && !config.DEFAULT_LOGO_URL.startsWith('http')) {
    console.warn('⚠️  Warning: DEFAULT_LOGO_URL should be a full URL (starting with http/https)');
  }
  
  return config;
});
