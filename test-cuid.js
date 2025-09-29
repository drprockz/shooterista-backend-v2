#!/usr/bin/env node

const fetch = require('node-fetch');

async function testRegisterWithValidCUID() {
  const requestId = `cuid-test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  
  console.log(`🧪 Testing register with valid CUID tenantId`);
  console.log(`📋 Request ID: ${requestId}`);
  
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

  // Test with valid CUID format tenantId
  const variables = {
    input: {
      email: `test-${Date.now()}@example.com`,
      password: 'TestPassword123!',
      firstName: 'Test',
      lastName: 'User',
      acceptTerms: true,
      acceptPrivacy: true,
      tenantId: 'c123456789012345678901234' // Valid CUID format
    }
  };

  console.log('📤 Sending request with valid CUID tenantId...');
  console.log('📤 Variables:', JSON.stringify(variables, null, 2));

  try {
    const response = await fetch('http://localhost:5001/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'x-request-id': requestId,
        'x-tenant-id': 'c123456789012345678901234'
      },
      body: JSON.stringify({
        query: mutation,
        variables: variables
      })
    });

    const result = await response.json();
    
    if (result.errors) {
      console.log('\n❌ ERRORS DETECTED:');
      result.errors.forEach((error, index) => {
        console.log(`❌ Error ${index + 1}:`, {
          message: error.message,
          code: error.extensions?.code,
          requestId: error.extensions?.requestId,
          path: error.path,
          extensions: error.extensions
        });
      });
    }
    
    if (result.data?.register) {
      console.log('\n🎉 SUCCESS! Registration worked!');
      console.log('✅ User ID:', result.data.register.user.id);
      console.log('✅ Session ID:', result.data.register.sessionId);
      console.log('✅ Profile Complete:', result.data.register.profileComplete);
      console.log('✅ Requires Consent:', result.data.register.requiresConsent);
    }
    
  } catch (error) {
    console.error('💥 Request failed:', error.message);
  }
  
  console.log('\n🏁 Test completed');
}

// Run the test
testRegisterWithValidCUID().catch(error => {
  console.error('💥 Test failed:', error);
});
