#!/usr/bin/env ts-node

import { PrismaClient as AuthPrismaClient } from '.prisma/auth';
import { PrismaClient as AthletesPrismaClient } from '.prisma/athletes';
import { PrismaClient as CompetitionsPrismaClient } from '.prisma/competitions';
import { config } from 'dotenv';

// Load environment variables
config({ path: '.env.development' });

interface DatabaseTestResult {
  name: string;
  url: string;
  status: 'success' | 'error';
  message: string;
  responseTime?: number;
}

async function testDatabaseConnection(
  name: string,
  url: string,
  client: any
): Promise<DatabaseTestResult> {
  const startTime = Date.now();
  
  try {
    console.log(`🔍 Testing ${name} connection...`);
    
    // Test basic connection
    await client.$connect();
    
    // Test query execution
    await client.$queryRaw`SELECT 1 as test`;
    
    const responseTime = Date.now() - startTime;
    
    console.log(`✅ ${name} connection successful (${responseTime}ms)`);
    
    return {
      name,
      url: url.replace(/:[^:@]+@/, ':***@'), // Hide password in output
      status: 'success',
      message: 'Connection successful',
      responseTime,
    };
  } catch (error: any) {
    const responseTime = Date.now() - startTime;
    
    console.log(`❌ ${name} connection failed (${responseTime}ms): ${error.message}`);
    
    return {
      name,
      url: url.replace(/:[^:@]+@/, ':***@'), // Hide password in output
      status: 'error',
      message: error.message,
      responseTime,
    };
  } finally {
    try {
      await client.$disconnect();
    } catch {
      // Ignore disconnect errors
    }
  }
}

async function main() {
  console.log('🚀 Starting database connection tests...\n');
  
  const results: DatabaseTestResult[] = [];
  
  // Test Auth Database
  if (process.env.AUTH_DB_URL) {
    const authClient = new AuthPrismaClient({
      datasources: {
        db: { url: process.env.AUTH_DB_URL },
      },
    });
    
    const authResult = await testDatabaseConnection(
      'Auth Database',
      process.env.AUTH_DB_URL,
      authClient
    );
    results.push(authResult);
  }
  
  // Test Athletes Database
  if (process.env.ATHLETES_DB_URL) {
    const athletesClient = new AthletesPrismaClient({
      datasources: {
        db: { url: process.env.ATHLETES_DB_URL },
      },
    });
    
    const athletesResult = await testDatabaseConnection(
      'Athletes Database',
      process.env.ATHLETES_DB_URL,
      athletesClient
    );
    results.push(athletesResult);
  }
  
  // Test Competitions Database
  if (process.env.COMPETITIONS_DB_URL) {
    const competitionsClient = new CompetitionsPrismaClient({
      datasources: {
        db: { url: process.env.COMPETITIONS_DB_URL },
      },
    });
    
    const competitionsResult = await testDatabaseConnection(
      'Competitions Database',
      process.env.COMPETITIONS_DB_URL,
      competitionsClient
    );
    results.push(competitionsResult);
  }
  
  // Print summary
  console.log('\n📊 Connection Test Summary:');
  console.log('=' .repeat(50));
  
  const successful = results.filter(r => r.status === 'success');
  const failed = results.filter(r => r.status === 'error');
  
  results.forEach(result => {
    const status = result.status === 'success' ? '✅' : '❌';
    const time = result.responseTime ? ` (${result.responseTime}ms)` : '';
    console.log(`${status} ${result.name}: ${result.message}${time}`);
    if (result.status === 'error') {
      console.log(`   URL: ${result.url}`);
    }
  });
  
  console.log('\n📈 Statistics:');
  console.log(`   Total: ${results.length}`);
  console.log(`   Successful: ${successful.length}`);
  console.log(`   Failed: ${failed.length}`);
  
  if (failed.length > 0) {
    console.log('\n🔧 Troubleshooting Tips:');
    console.log('   1. Ensure MySQL is running: docker-compose up -d mysql');
    console.log('   2. Check database URLs in .env.development');
    console.log('   3. Verify database credentials');
    console.log('   4. Run migrations: npm run prisma:migrate');
    process.exit(1);
  } else {
    console.log('\n🎉 All database connections successful!');
    process.exit(0);
  }
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Run the tests
main().catch(error => {
  console.error('❌ Test script failed:', error);
  process.exit(1);
});
