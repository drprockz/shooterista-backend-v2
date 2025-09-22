#!/usr/bin/env node

/**
 * Diagnostic script for notifications infrastructure
 * Tests the NotificationsService with mock tenant meta and dry-run render
 */

const { NestFactory } = require('@nestjs/core');
const { ConfigModule } = require('@nestjs/config');
const { NotificationsModule } = require('../dist/infra/notifications/notifications.module');
const { NotificationsService } = require('../dist/infra/notifications/notifications.service');

async function runDiagnostics() {
  console.log('🔍 Running Notifications Diagnostics...\n');

  try {
    // Create a minimal app
    const app = await NestFactory.createApplicationContext(
      ConfigModule.forRoot({
        envFilePath: '.env.development',
        isGlobal: true,
      })
    );

    // Import the notifications module
    const notificationsModule = app.select(NotificationsModule);
    const notificationsService = notificationsModule.get(NotificationsService);

    console.log('✅ NotificationsService initialized successfully');

    // Mock tenant meta
    const mockTenantMeta = {
      tenantId: 'test-tenant',
      brandColors: {
        primary: '#FF6B6B',
        secondary: '#4ECDC4',
      },
      logoUrl: 'https://example.com/logo.png',
      fromEmail: 'test@shooterista.com',
      replyToEmail: 'support@shooterista.com',
      provider: 'smtp',
    };

    console.log('📧 Testing template rendering...');

    // Test welcome email template
    try {
      const welcomeResult = await notificationsService.sendWelcomeEmail(
        'test@example.com',
        'John Doe',
        mockTenantMeta
      );
      
      console.log('✅ Welcome email test completed');
      console.log(`   Success: ${welcomeResult.success}`);
      console.log(`   Provider: ${welcomeResult.provider}`);
      if (welcomeResult.error) {
        console.log(`   Error: ${welcomeResult.error}`);
      }
    } catch (error) {
      console.log('❌ Welcome email test failed:', error.message);
    }

    // Test OTP email template
    try {
      const otpResult = await notificationsService.sendOTPEmail(
        'test@example.com',
        '123456',
        'Jane Doe',
        mockTenantMeta
      );
      
      console.log('✅ OTP email test completed');
      console.log(`   Success: ${otpResult.success}`);
      console.log(`   Provider: ${otpResult.provider}`);
      if (otpResult.error) {
        console.log(`   Error: ${otpResult.error}`);
      }
    } catch (error) {
      console.log('❌ OTP email test failed:', error.message);
    }

    await app.close();
    console.log('\n🎉 Notifications diagnostics completed successfully!');

  } catch (error) {
    console.error('❌ Diagnostics failed:', error.message);
    process.exit(1);
  }
}

// Run diagnostics
runDiagnostics().catch(console.error);
