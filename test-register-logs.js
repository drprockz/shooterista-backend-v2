#!/usr/bin/env node

const fetch = require('node-fetch');

async function testRegister() {
  const requestId = `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  
  console.log(`🧪 Testing register with requestId: ${requestId}`);
  
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
      email: `test-${Date.now()}@example.com`,
      password: 'TestPassword123!',
      firstName: 'Test',
      lastName: 'User',
      acceptTerms: true,
      acceptPrivacy: true,
      tenantId: 'test-tenant'
    }
  };

  try {
    const response = await fetch('http://localhost:5001/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-request-id': requestId,
        'x-tenant-id': 'test-tenant'
      },
      body: JSON.stringify({
        query: mutation,
        variables: variables
      })
    });

    const result = await response.json();
    
    console.log('📊 Response Status:', response.status);
    console.log('📊 Response Headers:', Object.fromEntries(response.headers.entries()));
    console.log('📊 GraphQL Response:', JSON.stringify(result, null, 2));
    
    if (result.errors) {
      console.log('❌ GraphQL Errors:', result.errors);
      result.errors.forEach(error => {
        console.log('❌ Error Details:', {
          message: error.message,
          code: error.extensions?.code,
          requestId: error.extensions?.requestId,
          path: error.path
        });
      });
    }
    
    if (result.data?.register) {
      console.log('✅ Registration successful!');
      console.log('✅ User ID:', result.data.register.user.id);
      console.log('✅ Session ID:', result.data.register.sessionId);
    }
    
  } catch (error) {
    console.error('💥 Request failed:', error.message);
  }
}

// Run the test
testRegister().then(() => {
  console.log('🏁 Test completed');
}).catch(error => {
  console.error('💥 Test failed:', error);
});
