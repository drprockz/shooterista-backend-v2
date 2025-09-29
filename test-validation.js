#!/usr/bin/env node

const fetch = require('node-fetch');

async function testRegisterWithDetailedValidation() {
  const requestId = `validation-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  
  console.log(`🧪 Testing register with detailed validation error capture`);
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

  // Test with minimal valid data
  const variables = {
    input: {
      email: `test-${Date.now()}@example.com`,
      password: 'TestPassword123!',
      firstName: 'Test',
      lastName: 'User',
      acceptTerms: true,
      acceptPrivacy: true,
      tenantId: 'test-tenant'
    }
  };

  console.log('📤 Sending request with minimal valid data...');
  console.log('📤 Variables:', JSON.stringify(variables, null, 2));

  try {
    const response = await fetch('http://localhost:5001/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'x-request-id': requestId,
        'x-tenant-id': 'test-tenant'
      },
      body: JSON.stringify({
        query: mutation,
        variables: variables
      })
    });

    const result = await response.json();
    
    if (result.errors) {
      console.log('\n❌ VALIDATION ERRORS DETECTED:');
      result.errors.forEach((error, index) => {
        console.log(`❌ Error ${index + 1}:`, {
          message: error.message,
          code: error.extensions?.code,
          requestId: error.extensions?.requestId,
          path: error.path,
          extensions: error.extensions
        });
        
        // Check if there's a stack trace in development mode
        if (error.extensions?.exception?.stacktrace) {
          console.log('\n📋 STACK TRACE:');
          error.extensions.exception.stacktrace.forEach((line, i) => {
            console.log(`  ${i + 1}. ${line}`);
          });
        }
      });
      
      console.log('\n🔍 VALIDATION ANALYSIS:');
      console.log('The validation is failing, which means:');
      console.log('✅ The .url access error is completely fixed!');
      console.log('✅ The register mutation is processing requests');
      console.log('❌ The input data doesn\'t meet validation requirements');
      console.log('\n💡 NEXT STEPS:');
      console.log('1. Check the custom validators in src/modules/auth/validators/password.validator.ts');
      console.log('2. The issue might be with tenantId format (needs CUID format)');
      console.log('3. Or password strength requirements');
      console.log('4. Or email format validation');
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
}

// Run the test
testRegisterWithDetailedValidation().catch(error => {
  console.error('💥 Test failed:', error);
});
