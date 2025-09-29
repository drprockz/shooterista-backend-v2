#!/usr/bin/env node

console.log('🧪 OTP Email Service Test Script');
console.log('=====================================\n');

console.log('📋 What to do:');
console.log('1. Start your backend server: npm run dev');
console.log('2. Start your frontend application');
console.log('3. Try to register with any email address');
console.log('4. Watch the backend console for detailed logs\n');

console.log('🔍 What you should see in the backend console:');
console.log('📧 [PROVIDER FACTORY] Selected email provider: console');
console.log('📧 [PROVIDER FACTORY] Creating ConsoleEmailAdapter');
console.log('🔐 [OTP REQUEST] Starting OTP request for email: your-email@example.com');
console.log('✅ [OTP REQUEST] Rate limit check passed for email: your-email@example.com');
console.log('🔑 [OTP REQUEST] Generated OTP code: 123456 for email: your-email@example.com');
console.log('📧 [OTP REQUEST] Attempting to send OTP email to: your-email@example.com');
console.log('📧 [NOTIFICATIONS] sendOTPEmail called for: your-email@example.com');
console.log('📧 [NOTIFICATIONS] OTP Code: 123456');
console.log('📧 [NOTIFICATIONS] send() called with template: otp-email');
console.log('📧 [NOTIFICATIONS] Recipients: your-email@example.com');
console.log('📧 [NOTIFICATIONS] Data: { code: "123456", firstName: "User" }');
console.log('📧 [NOTIFICATIONS] Using tenant meta: { brandColors: {...}, fromEmail: "noreply@shooterista.com", provider: "smtp" }');
console.log('📧 [NOTIFICATIONS] Rendering template: otp-email');
console.log('📧 [NOTIFICATIONS] Template rendered successfully');
console.log('📧 [NOTIFICATIONS] Email params prepared: { to: ["your-email@example.com"], subject: "Your Verification Code", hasHtml: true, hasText: true }');
console.log('📧 [NOTIFICATIONS] Calling sendEmailPort.send()');
console.log('📧 [EMAIL ADAPTER] Converting SendEmailParams to EmailMessage');
console.log('📧 [EMAIL ADAPTER] Provider: console');
console.log('📧 [EMAIL ADAPTER] To: your-email@example.com');
console.log('📧 [EMAIL ADAPTER] Subject: Your Verification Code');
console.log('📧 [EMAIL ADAPTER] Calling emailProvider.sendEmail()');
console.log('📧 EMAIL SENT (Console Adapter)');
console.log('Message ID: console_1234567890_abc123');
console.log('To: your-email@example.com');
console.log('From: noreply@shooterista.com');
console.log('Subject: Your Verification Code');
console.log('========================================');
console.log('EMAIL CONTENT');
console.log('========================================');
console.log('Your verification code is: 123456');
console.log('========================================');
console.log('📧 [EMAIL ADAPTER] emailProvider.sendEmail() result: { success: true, messageId: "console_1234567890_abc123", provider: "console", timestamp: "2025-01-22T..." }');
console.log('📧 [NOTIFICATIONS] sendEmailPort.send() result: { success: true, messageId: "console_1234567890_abc123", provider: "console", timestamp: "2025-01-22T..." }');
console.log('📧 [NOTIFICATIONS] sendOTPEmail result: { success: true, messageId: "console_1234567890_abc123", provider: "console", timestamp: "2025-01-22T..." }');
console.log('✅ [OTP REQUEST] Email sent successfully! MessageId: console_1234567890_abc123');
console.log('📧 [OTP REQUEST] OTP Code for your-email@example.com: 123456');
console.log('🎉 [OTP REQUEST] OTP request completed successfully for email: your-email@example.com\n');

console.log('❌ If you see errors, look for these patterns:');
console.log('❌ [OTP REQUEST] Error sending OTP email to your-email@example.com: [error message]');
console.log('❌ [NOTIFICATIONS] Error in send(): [error message]');
console.log('❌ [EMAIL ADAPTER] Error in emailProvider.sendEmail(): [error message]\n');

console.log('✅ Success indicators:');
console.log('✅ [OTP REQUEST] Email sent successfully!');
console.log('✅ [OTP REQUEST] OTP request completed successfully');
console.log('📧 EMAIL SENT (Console Adapter)');
console.log('📧 [EMAIL ADAPTER] emailProvider.sendEmail() result: { success: true, ... }\n');

console.log('🔧 If you still get "Failed to send OTP":');
console.log('1. Check that EMAIL_PROVIDER="console" in your .env.development');
console.log('2. Make sure the backend server is running');
console.log('3. Check the console logs for any error messages');
console.log('4. Verify the GraphQL mutation is calling requestEmailOtp correctly\n');

console.log('🎯 The OTP code will be displayed in the console logs - use that to complete registration!');
