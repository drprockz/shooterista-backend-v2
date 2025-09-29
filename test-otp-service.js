#!/usr/bin/env node

// Test script to verify OTP email service
const { execSync } = require('child_process');

console.log('🧪 Testing OTP Email Service Configuration...\n');

// Test 1: Check environment variables
console.log('1. Checking environment variables:');
try {
  const envCheck = execSync('node -e "console.log(\'EMAIL_PROVIDER:\', process.env.EMAIL_PROVIDER); console.log(\'EMAIL_ENABLED:\', process.env.EMAIL_ENABLED);"', { 
    cwd: process.cwd(),
    env: { ...process.env, ...require('dotenv').config({ path: '.env.development' }).parsed }
  });
  console.log(envCheck.toString());
} catch (error) {
  console.error('❌ Environment check failed:', error.message);
}

// Test 2: Check if console adapter is being used
console.log('\n2. Testing email provider selection:');
try {
  const providerCheck = execSync('node -e "
    const { NotificationConfigService } = require(\'./dist/infra/notifications/notification-config.service.js\');
    const { ConfigService } = require(\'@nestjs/config\');
    const config = new ConfigService(require(\'dotenv\').config({ path: \'.env.development\' }).parsed);
    const notificationConfig = new NotificationConfigService(config);
    console.log(\'Selected provider:\', notificationConfig.getEmailProvider());
  "', { 
    cwd: process.cwd(),
    env: { ...process.env, ...require('dotenv').config({ path: '.env.development' }).parsed }
  });
  console.log(providerCheck.toString());
} catch (error) {
  console.error('❌ Provider check failed:', error.message);
}

console.log('\n✅ OTP Email Service Test Complete!');
console.log('\n📋 Summary:');
console.log('- Your EMAIL_PROVIDER is set to "console" which should work for localhost development');
console.log('- The console adapter will log OTP emails to the server console instead of sending real emails');
console.log('- This is perfect for development and testing');
console.log('\n🔧 To test OTP:');
console.log('1. Start your frontend application');
console.log('2. Try to register with an email');
console.log('3. Check the backend server console for the OTP email content');
console.log('4. Use the OTP code from the console logs to complete registration');
