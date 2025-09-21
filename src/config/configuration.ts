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

  // Email Configuration (Optional)
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().optional(),
  SMTP_SECURE: z.string().default('false').transform(val => val === 'true'),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_USERNAME: z.string().optional(),
  SMTP_PASSWORD: z.string().optional(),
  SMTP_FROM: z.string().optional(),
  EMAIL_ENABLED: z.string().default('false').transform(val => val === 'true'),
  EMAIL_VERIFICATION_ENABLED: z.string().default('false').transform(val => val === 'true'),
  EMAIL_RESET_PASSWORD_ENABLED: z.string().default('false').transform(val => val === 'true'),

  // Development Configuration
  DEBUG: z.string().optional(),
  VERBOSE_LOGGING: z.string().default('false').transform(val => val === 'true'),
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
    const localhostUrls = dbUrls.filter(url => url.includes('localhost'));
    if (localhostUrls.length > 0) {
      console.warn('⚠️  Warning: Database URLs are pointing to localhost in development mode.');
      console.warn('   Consider updating .env.development to use server URLs instead.');
      console.warn('   Current URLs:', localhostUrls);
    }
    
    // Check if any database URL contains placeholder values
    const placeholderUrls = dbUrls.filter(url => url.includes('your-server.com'));
    if (placeholderUrls.length > 0) {
      console.warn('⚠️  Warning: Database URLs contain placeholder values (your-server.com).');
      console.warn('   Please update .env.development with actual server URLs.');
    }
  }
  
  return config;
});
