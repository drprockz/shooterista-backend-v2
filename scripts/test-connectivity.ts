#!/usr/bin/env ts-node

import { PrismaClient as AuthPrismaClient } from '../node_modules/.prisma/auth';
import Redis from 'ioredis';
import { config } from 'dotenv';

// Load environment variables
config({ path: '.env.development' });

interface TestResult {
  service: string;
  status: 'success' | 'error';
  message: string;
  details?: any;
}

async function testRedis(): Promise<TestResult> {
  try {
    const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
    
    // Test basic operations
    await redis.ping();
    await redis.set('test-key', 'test-value', 'EX', 10);
    const value = await redis.get('test-key');
    await redis.del('test-key');
    
    await redis.disconnect();
    
    return {
      service: 'Redis',
      status: 'success',
      message: 'Redis connection successful',
      details: { value: value === 'test-value' ? 'Data operations working' : 'Data operations failed' }
    };
  } catch (error) {
    return {
      service: 'Redis',
      status: 'error',
      message: `Redis connection failed: ${error.message}`,
      details: { error: error.message }
    };
  }
}

async function testPostgreSQL(): Promise<TestResult> {
  try {
    const prisma = new AuthPrismaClient({
      datasources: {
        db: {
          url: process.env.AUTH_DB_URL
        }
      }
    });
    
    // Test connection
    await prisma.$connect();
    
    // Test basic query
    const result = await prisma.$queryRaw`SELECT 1 as test`;
    
    await prisma.$disconnect();
    
    return {
      service: 'PostgreSQL (Auth DB)',
      status: 'success',
      message: 'PostgreSQL connection successful',
      details: { queryResult: result }
    };
  } catch (error) {
    return {
      service: 'PostgreSQL (Auth DB)',
      status: 'error',
      message: `PostgreSQL connection failed: ${error.message}`,
      details: { error: error.message }
    };
  }
}

async function testGraphQLSetup(): Promise<TestResult> {
  try {
    // Check if GraphQL module files exist
    const fs = require('fs');
    const path = require('path');
    
    const graphqlModulePath = path.join(__dirname, '../src/graphql/graphql.module.ts');
    const authResolverPath = path.join(__dirname, '../src/modules/auth/auth.resolver.ts');
    
    if (!fs.existsSync(graphqlModulePath)) {
      return {
        service: 'GraphQL Setup',
        status: 'error',
        message: 'GraphQL module not found',
        details: { missingFile: graphqlModulePath }
      };
    }
    
    if (!fs.existsSync(authResolverPath)) {
      return {
        service: 'GraphQL Setup',
        status: 'error',
        message: 'Auth resolver not found',
        details: { missingFile: authResolverPath }
      };
    }
    
    // Check if Prisma clients are generated
    const authClientPath = path.join(__dirname, '../node_modules/.prisma/auth/index.d.ts');
    if (!fs.existsSync(authClientPath)) {
      return {
        service: 'GraphQL Setup',
        status: 'error',
        message: 'Prisma clients not generated',
        details: { missingFile: authClientPath, suggestion: 'Run: npm run prisma:gen' }
      };
    }
    
    return {
      service: 'GraphQL Setup',
      status: 'success',
      message: 'GraphQL setup files present',
      details: { 
        graphqlModule: 'Found',
        authResolver: 'Found',
        prismaClients: 'Generated'
      }
    };
  } catch (error) {
    return {
      service: 'GraphQL Setup',
      status: 'error',
      message: `GraphQL setup check failed: ${error.message}`,
      details: { error: error.message }
    };
  }
}

async function runAllTests() {
  console.log('🔍 Running connectivity tests for core services...\n');
  
  const results: TestResult[] = [];
  
  // Test Redis
  console.log('Testing Redis connectivity...');
  results.push(await testRedis());
  
  // Test PostgreSQL
  console.log('Testing PostgreSQL connectivity...');
  results.push(await testPostgreSQL());
  
  // Test GraphQL Setup
  console.log('Testing GraphQL setup...');
  results.push(await testGraphQLSetup());
  
  // Print results
  console.log('\n📊 Test Results:');
  console.log('=====================================');
  
  results.forEach(result => {
    const icon = result.status === 'success' ? '✅' : '❌';
    console.log(`${icon} ${result.service}: ${result.message}`);
    if (result.details) {
      console.log(`   Details: ${JSON.stringify(result.details, null, 2)}`);
    }
    console.log('');
  });
  
  const successCount = results.filter(r => r.status === 'success').length;
  const totalCount = results.length;
  
  console.log(`📈 Summary: ${successCount}/${totalCount} services working`);
  
  if (successCount === totalCount) {
    console.log('🎉 All services are working correctly!');
  } else {
    console.log('⚠️  Some services need attention. See details above.');
  }
}

// Run tests
runAllTests().catch(console.error);
