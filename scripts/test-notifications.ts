#!/usr/bin/env ts-node

/**
 * Test script to verify notification infrastructure
 * This script tests the notification service without requiring a full application startup
 */

import { NestFactory } from '@nestjs/core';
import { ConfigModule } from '@nestjs/config';
import { NotificationsModule } from '../src/infra/notifications/notifications.module';
import { NotificationService } from '../src/infra/notifications/notification.service';
import { EmailMessage, NotificationContext } from '../src/infra/notifications/ports/notification.ports';
import { Module } from '@nestjs/common';

@Module({
  imports: [
    ConfigModule.forRoot({
      envFilePath: '.env.development',
      isGlobal: true,
    }),
    NotificationsModule,
  ],
})
class TestModule {}

async function testNotifications() {
  console.log('🧪 Testing Notification Infrastructure...\n');

  try {
    // Create a minimal app with the notifications module
    const app = await NestFactory.createApplicationContext(TestModule);

    const notificationService = app.get(NotificationService);

    console.log('✅ Notification service initialized successfully');
    console.log(`📧 Provider: ${notificationService.getProviderInfo().name}`);
    console.log(`🔧 Version: ${notificationService.getProviderInfo().version}`);
    console.log(`⚡ Capabilities:`, notificationService.getProviderInfo().capabilities);

    // Test email sending
    console.log('\n📧 Testing email sending...');
    
    const testMessage: EmailMessage = {
      to: 'test@example.com',
      subject: 'Test Email from Shooterista',
      content: 'This is a test email from the Shooterista notification system.',
      htmlContent: `
        <html>
          <body style="font-family: Arial, sans-serif;">
            <h1 style="color: #3B82F6;">Test Email</h1>
            <p>This is a test email from the Shooterista notification system.</p>
            <p>If you can see this, the notification infrastructure is working correctly!</p>
          </body>
        </html>
      `,
    };

    const testContext: NotificationContext = {
      tenantId: 'test-tenant',
      requestId: 'test-request-123',
      ipAddress: '127.0.0.1',
      userAgent: 'Test Script',
    };

    const result = await notificationService.sendEmail(testMessage, testContext);
    
    if (result.success) {
      console.log('✅ Email sent successfully!');
      console.log(`📨 Message ID: ${result.messageId}`);
      console.log(`🔧 Provider: ${result.provider}`);
      console.log(`⏰ Timestamp: ${result.timestamp}`);
    } else {
      console.log('❌ Email sending failed:');
      console.log(`   Error: ${result.error}`);
    }

    // Test health check
    console.log('\n🏥 Testing health check...');
    const health = await notificationService.healthCheck();
    console.log(`Status: ${health.healthy ? '✅ Healthy' : '❌ Unhealthy'}`);
    if (health.error) {
      console.log(`Error: ${health.error}`);
    }

    // Test email validation
    console.log('\n🔍 Testing email validation...');
    const validEmails = ['test@example.com', 'user@domain.co.uk', 'admin+test@company.org'];
    const invalidEmails = ['invalid-email', '@domain.com', 'user@', 'user@domain'];

    console.log('Valid emails:');
    validEmails.forEach(email => {
      const isValid = notificationService.validateEmailAddress(email);
      console.log(`  ${email}: ${isValid ? '✅ Valid' : '❌ Invalid'}`);
    });

    console.log('Invalid emails:');
    invalidEmails.forEach(email => {
      const isValid = notificationService.validateEmailAddress(email);
      console.log(`  ${email}: ${isValid ? '❌ Should be invalid' : '✅ Correctly invalid'}`);
    });

    await app.close();
    console.log('\n🎉 Notification infrastructure test completed successfully!');

  } catch (error) {
    console.error('❌ Test failed:', error);
    process.exit(1);
  }
}

// Run the test
testNotifications().catch(console.error);
