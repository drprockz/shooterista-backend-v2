#!/usr/bin/env ts-node

/**
 * Complete Setup Script
 * 
 * This script runs the complete setup process:
 * 1. Validates environment configuration
 * 2. Generates Prisma clients
 * 3. Runs database migrations
 * 4. Seeds all databases
 * 5. Tests auth flows
 * 
 * Run this after setting up your environment variables.
 */

import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { join } from 'path';

const SETUP_STEPS = [
  {
    name: 'Environment Validation',
    command: 'npm run env:validate',
    description: 'Validates all required environment variables are present',
  },
  {
    name: 'Prisma Client Generation',
    command: 'npm run prisma:gen',
    description: 'Generates Prisma clients for all databases',
  },
  {
    name: 'Database Migrations',
    command: 'npm run prisma:migrate',
    description: 'Runs pending database migrations',
  },
  {
    name: 'Database Seeding',
    command: 'npm run db:seed',
    description: 'Seeds all databases with minimal viable data',
  },
  {
    name: 'Auth Flow Testing',
    command: 'npm run test:auth',
    description: 'Tests complete authentication and profile flows',
  },
];

class SetupRunner {
  private results: Array<{ name: string; success: boolean; error?: string; duration: number }> = [];

  async runCompleteSetup(): Promise<void> {
    console.log('🚀 Starting Complete Backend Setup');
    console.log('=' .repeat(60));
    console.log('This will set up your backend with:');
    console.log('• Tenant resolution with local override');
    console.log('• Seeded databases (auth, tenant, athletes, competitions)');
    console.log('• Test users and admin accounts');
    console.log('• Verified auth flows');
    console.log('=' .repeat(60));

    // Check if .env.development exists
    const envFile = join(process.cwd(), '.env.development');
    if (!existsSync(envFile)) {
      console.error('❌ .env.development file not found!');
      console.error('   Please copy .env.development.example to .env.development and configure it.');
      process.exit(1);
    }

    try {
      for (const step of SETUP_STEPS) {
        await this.runStep(step);
      }
      
      this.printResults();
      this.printNextSteps();
    } catch (error) {
      console.error('❌ Setup failed:', error);
      this.printResults();
      process.exit(1);
    }
  }

  private async runStep(step: { name: string; command: string; description: string }): Promise<void> {
    console.log(`\n🔄 ${step.name}`);
    console.log(`   ${step.description}`);
    
    const startTime = Date.now();
    
    try {
      execSync(step.command, { 
        stdio: 'inherit',
        cwd: process.cwd(),
        env: { ...process.env, NODE_ENV: 'development' }
      });
      
      const duration = Date.now() - startTime;
      this.results.push({ name: step.name, success: true, duration });
      
      console.log(`   ✅ ${step.name} completed in ${duration}ms`);
    } catch (error) {
      const duration = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      this.results.push({ name: step.name, success: false, error: errorMessage, duration });
      
      console.error(`   ❌ ${step.name} failed: ${errorMessage}`);
      throw new Error(`Step '${step.name}' failed: ${errorMessage}`);
    }
  }

  private printResults(): void {
    console.log('\n' + '=' .repeat(60));
    console.log('📊 Setup Results Summary');
    console.log('=' .repeat(60));

    const passed = this.results.filter(r => r.success).length;
    const failed = this.results.filter(r => !r.success).length;
    const totalDuration = this.results.reduce((sum, r) => sum + r.duration, 0);

    this.results.forEach(result => {
      const status = result.success ? '✅' : '❌';
      const duration = `${result.duration}ms`;
      console.log(`${status} ${result.name} (${duration})`);
      
      if (!result.success && result.error) {
        console.log(`   Error: ${result.error}`);
      }
    });

    console.log('=' .repeat(60));
    console.log(`📈 Results: ${passed} passed, ${failed} failed`);
    console.log(`⏱️  Total time: ${totalDuration}ms`);
    
    if (failed === 0) {
      console.log('🎉 Setup completed successfully!');
    } else {
      console.log('⚠️  Setup failed. Please check the errors above.');
    }
  }

  private printNextSteps(): void {
    if (this.results.every(r => r.success)) {
      console.log('\n🎯 Next Steps:');
      console.log('1. Start the development server:');
      console.log('   npm run start:dev');
      console.log('');
      console.log('2. Test GraphQL endpoints:');
      console.log('   http://localhost:5001/graphql');
      console.log('');
      console.log('3. Test credentials:');
      console.log('   Admin: admin@club-x.com / Admin123!');
      console.log('   Test: test@club-x.com / Test123!');
      console.log('');
      console.log('4. Tenant resolution:');
      console.log('   • Local override: TENANT_RESOLUTION_MODE=env');
      console.log('   • Tenant slug: club-x');
      console.log('   • Subdomain: club-x.localhost:5001');
      console.log('');
      console.log('5. Test auth flows:');
      console.log('   • OTP email verification');
      console.log('   • User registration');
      console.log('   • Profile completion');
      console.log('   • Admin approval workflow');
    }
  }
}

// Run the setup
async function main() {
  const runner = new SetupRunner();
  await runner.runCompleteSetup();
}

if (require.main === module) {
  main().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

export { SetupRunner };
