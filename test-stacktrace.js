#!/usr/bin/env node

const fetch = require('node-fetch');

async function testRegisterWithStackTrace() {
  const requestId = `stacktrace-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  
  console.log(`🧪 Testing register with stack trace capture`);
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

  const variables = {
    input: {
      email: `stacktrace-${Date.now()}@example.com`,
      password: 'TestPassword123!',
      firstName: 'Stack',
      lastName: 'Trace',
      acceptTerms: true,
      acceptPrivacy: true,
      tenantId: 'stacktrace-tenant'
    }
  };

  try {
    const response = await fetch('http://localhost:5001/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-request-id': requestId,
        'x-tenant-id': 'stacktrace-tenant'
      },
      body: JSON.stringify({
        query: mutation,
        variables: variables
      })
    });

    const result = await response.json();
    
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
        
        // Check if there's a stack trace in development mode
        if (error.extensions?.exception?.stacktrace) {
          console.log('\n📋 STACK TRACE:');
          error.extensions.exception.stacktrace.forEach((line, i) => {
            console.log(`  ${i + 1}. ${line}`);
          });
        }
      });
    }
    
  } catch (error) {
    console.error('💥 Request failed:', error.message);
    console.error('💥 Stack:', error.stack);
  }
  
  console.log('\n🏁 Test completed');
}

// Run the test
testRegisterWithStackTrace().catch(error => {
  console.error('💥 Test failed:', error);
});
