#!/usr/bin/env ts-node

import { config } from 'dotenv';
import { z } from 'zod';

// Load environment variables
config({ path: '.env.development' });

interface ValidationResult {
  variable: string;
  status: 'valid' | 'invalid' | 'missing' | 'warning';
  message: string;
  value?: string;
}

// Define validation schema
const envSchema = z.object({
  // Required variables
  NODE_ENV: z.enum(['development', 'production', 'test']),
  PORT: z.coerce.number().min(1000).max(65535),
  AUTH_DB_URL: z.string().url('Must be a valid database URL'),
  ATHLETES_DB_URL: z.string().url('Must be a valid database URL'),
  COMPETITIONS_DB_URL: z.string().url('Must be a valid database URL'),
  REDIS_URL: z.string().url('Must be a valid Redis URL'),
  JWT_SECRET: z.string().min(32, 'JWT secret must be at least 32 characters'),
  S3_ACCESS_KEY_ID: z.string().min(1, 'S3 access key is required'),
  S3_SECRET_ACCESS_KEY: z.string().min(1, 'S3 secret key is required'),
  S3_BUCKET_NAME: z.string().min(1, 'S3 bucket name is required'),
  
  // Optional but recommended
  JWT_ISS: z.string().optional(),
  JWT_AUD: z.string().optional(),
  CORS_ORIGINS: z.string().optional(),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).optional(),
});

function validateEnvironment(): ValidationResult[] {
  const results: ValidationResult[] = [];
  
  // Check required variables
  const requiredVars = [
    'NODE_ENV',
    'PORT',
    'AUTH_DB_URL',
    'ATHLETES_DB_URL', 
    'COMPETITIONS_DB_URL',
    'REDIS_URL',
    'JWT_SECRET',
    'S3_ACCESS_KEY_ID',
    'S3_SECRET_ACCESS_KEY',
    'S3_BUCKET_NAME',
  ];
  
  requiredVars.forEach(varName => {
    const value = process.env[varName];
    if (!value) {
      results.push({
        variable: varName,
        status: 'missing',
        message: 'Required environment variable is missing',
      });
    } else {
      results.push({
        variable: varName,
        status: 'valid',
        message: 'Present',
        value: varName.includes('SECRET') || varName.includes('PASSWORD') 
          ? '***hidden***' 
          : value,
      });
    }
  });
  
  // Validate JWT secret strength
  const jwtSecret = process.env.JWT_SECRET;
  if (jwtSecret) {
    if (jwtSecret.length < 32) {
      results.push({
        variable: 'JWT_SECRET',
        status: 'invalid',
        message: 'JWT secret must be at least 32 characters long',
        value: '***hidden***',
      });
    } else if (jwtSecret === 'your-jwt-secret-key-here' || jwtSecret.includes('change-in-production')) {
      results.push({
        variable: 'JWT_SECRET',
        status: 'warning',
        message: 'Using default/development JWT secret - change for production',
        value: '***hidden***',
      });
    }
  }
  
  // Check database URLs format
  const dbUrls = ['AUTH_DB_URL', 'ATHLETES_DB_URL', 'COMPETITIONS_DB_URL'];
  dbUrls.forEach(urlVar => {
    const url = process.env[urlVar];
    if (url) {
      if (!url.startsWith('mysql://') && !url.startsWith('postgresql://')) {
        results.push({
          variable: urlVar,
          status: 'warning',
          message: 'Database URL should start with mysql:// or postgresql://',
          value: url.replace(/:[^:@]+@/, ':***@'),
        });
      }
      
      if (url.includes('password') && url.includes('localhost')) {
        results.push({
          variable: urlVar,
          status: 'warning',
          message: 'Using default password - consider changing for security',
          value: url.replace(/:[^:@]+@/, ':***@'),
        });
      }
    }
  });
  
  // Check Redis URL
  const redisUrl = process.env.REDIS_URL;
  if (redisUrl && !redisUrl.startsWith('redis://')) {
    results.push({
      variable: 'REDIS_URL',
      status: 'warning',
      message: 'Redis URL should start with redis://',
      value: redisUrl,
    });
  }
  
  // Check S3 configuration
  const s3Endpoint = process.env.S3_ENDPOINT;
  if (s3Endpoint && !s3Endpoint.startsWith('http')) {
    results.push({
      variable: 'S3_ENDPOINT',
      status: 'warning',
      message: 'S3 endpoint should be a valid HTTP/HTTPS URL',
      value: s3Endpoint,
    });
  }
  
  // Check CORS origins
  const corsOrigins = process.env.CORS_ORIGINS;
  if (corsOrigins && corsOrigins.includes('*')) {
    results.push({
      variable: 'CORS_ORIGINS',
      status: 'warning',
      message: 'Avoid using wildcard (*) in CORS origins for security',
      value: corsOrigins,
    });
  }
  
  // Check for development-specific warnings
  if (process.env.NODE_ENV === 'development') {
    const devWarnings = [
      { var: 'GRAPHQL_PLAYGROUND', expected: 'true' },
      { var: 'GRAPHQL_INTROSPECTION', expected: 'true' },
      { var: 'LOG_LEVEL', expected: 'debug' },
    ];
    
    devWarnings.forEach(({ var: varName, expected }) => {
      const value = process.env[varName];
      if (value && value !== expected) {
        results.push({
          variable: varName,
          status: 'warning',
          message: `Consider setting to '${expected}' for development`,
          value,
        });
      }
    });
  }
  
  return results;
}

function printResults(results: ValidationResult[]) {
  console.log('🔍 Environment Variables Validation Report');
  console.log('=' .repeat(60));
  
  const valid = results.filter(r => r.status === 'valid');
  const warnings = results.filter(r => r.status === 'warning');
  const invalid = results.filter(r => r.status === 'invalid');
  const missing = results.filter(r => r.status === 'missing');
  
  // Print missing variables
  if (missing.length > 0) {
    console.log('\n❌ Missing Required Variables:');
    missing.forEach(result => {
      console.log(`   • ${result.variable}: ${result.message}`);
    });
  }
  
  // Print invalid variables
  if (invalid.length > 0) {
    console.log('\n❌ Invalid Variables:');
    invalid.forEach(result => {
      console.log(`   • ${result.variable}: ${result.message}`);
      if (result.value) {
        console.log(`     Value: ${result.value}`);
      }
    });
  }
  
  // Print warnings
  if (warnings.length > 0) {
    console.log('\n⚠️  Warnings:');
    warnings.forEach(result => {
      console.log(`   • ${result.variable}: ${result.message}`);
      if (result.value) {
        console.log(`     Value: ${result.value}`);
      }
    });
  }
  
  // Print valid variables
  if (valid.length > 0) {
    console.log('\n✅ Valid Variables:');
    valid.forEach(result => {
      console.log(`   • ${result.variable}: ${result.message}`);
    });
  }
  
  // Summary
  console.log('\n📊 Summary:');
  console.log(`   Total: ${results.length}`);
  console.log(`   Valid: ${valid.length}`);
  console.log(`   Warnings: ${warnings.length}`);
  console.log(`   Invalid: ${invalid.length}`);
  console.log(`   Missing: ${missing.length}`);
  
  // Recommendations
  console.log('\n💡 Recommendations:');
  console.log('   1. Copy .env.development to .env for local development');
  console.log('   2. Update database credentials if using different setup');
  console.log('   3. Generate strong JWT secrets for production');
  console.log('   4. Configure proper CORS origins for your frontend');
  console.log('   5. Set up proper S3 credentials for file uploads');
  
  // Next steps
  if (missing.length === 0 && invalid.length === 0) {
    console.log('\n🚀 Next Steps:');
    console.log('   1. Start infrastructure: npm run infra:up');
    console.log('   2. Run migrations: npm run prisma:migrate');
    console.log('   3. Test database: npm run db:test');
    console.log('   4. Start development: npm run dev');
  } else {
    console.log('\n🔧 Fix the issues above before proceeding');
  }
}

function main() {
  console.log('🔍 Validating environment configuration...\n');
  
  try {
    // Validate using Zod schema
    const parsed = envSchema.safeParse(process.env);
    
    if (!parsed.success) {
      console.log('❌ Schema validation failed:');
      console.log(parsed.error.flatten().fieldErrors);
    }
    
    // Run custom validation
    const results = validateEnvironment();
    printResults(results);
    
    // Exit with appropriate code
    const hasErrors = results.some(r => r.status === 'invalid' || r.status === 'missing');
    process.exit(hasErrors ? 1 : 0);
    
  } catch (error) {
    console.error('❌ Validation script failed:', error);
    process.exit(1);
  }
}

main();
