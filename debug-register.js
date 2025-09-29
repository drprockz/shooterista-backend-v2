#!/usr/bin/env node

const fetch = require('node-fetch');

async function testRegisterWithDetailedLogging() {
  const requestId = `debug-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  
  console.log(`🧪 Testing register with detailed logging`);
  console.log(`📋 Request ID: ${requestId}`);
  console.log(`⏰ Timestamp: ${new Date().toISOString()}`);
  console.log('=' * 60);
  
  const mutation = `
    mutation Register($input: CreateUserInput!) {
      register(input: $input) {
        user {
          id
          email
          firstName
          lastName
        }
        accessToken
        refreshToken
        profileComplete
        requiresConsent
        sessionId
      }
    }
  `;

  const variables = {
    input: {
      email: `debug-${Date.now()}@example.com`,
      password: 'TestPassword123!',
      firstName: 'Debug',
      lastName: 'User',
      acceptTerms: true,
      acceptPrivacy: true,
      tenantId: 'debug-tenant'
    }
  };

  console.log('📤 Sending request to GraphQL endpoint...');
  console.log('📤 Headers:', {
    'Content-Type': 'application/json',
    'x-request-id': requestId,
    'x-tenant-id': 'debug-tenant'
  });
  console.log('📤 Variables:', JSON.stringify(variables, null, 2));

  try {
    const response = await fetch('http://localhost:5001/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'x-request-id': requestId,
        'x-tenant-id': 'debug-tenant'
      },
      body: JSON.stringify({
        query: mutation,
        variables: variables
      })
    });

    console.log('📥 Response received');
    console.log('📥 Status:', response.status);
    console.log('📥 Headers:', Object.fromEntries(response.headers.entries()));
    
    const result = await response.json();
    console.log('📥 Response body:', JSON.stringify(result, null, 2));
    
    if (result.errors) {
      console.log('\n❌ GRAPHQL ERRORS DETECTED:');
      result.errors.forEach((error, index) => {
        console.log(`❌ Error ${index + 1}:`, {
          message: error.message,
          code: error.extensions?.code,
          requestId: error.extensions?.requestId,
          path: error.path,
          extensions: error.extensions
        });
      });
      
      console.log('\n🔍 NEXT STEPS:');
      console.log('1. Check the server console output for detailed logs');
      console.log('2. Look for logs containing this requestId:', requestId);
      console.log('3. Search for these log events:');
      console.log('   - register.start');
      console.log('   - register.core_validations.ok');
      console.log('   - register.config_snapshot');
      console.log('   - guard.check.url');
      console.log('   - guard.block.url_access');
      console.log('   - register.mail.start');
      console.log('   - register.mail.err');
      console.log('   - register.error');
      console.log('   - url_access_error');
    }
    
    if (result.data?.register) {
      console.log('\n✅ Registration successful!');
      console.log('✅ User ID:', result.data.register.user.id);
      console.log('✅ Session ID:', result.data.register.sessionId);
    }
    
  } catch (error) {
    console.error('💥 Request failed:', error.message);
    console.error('💥 Stack:', error.stack);
  }
  
  console.log('\n🏁 Test completed');
  console.log('💡 Check the server console output for detailed logs with requestId:', requestId);
}

// Run the test
testRegisterWithDetailedLogging().catch(error => {
  console.error('💥 Test failed:', error);
});
