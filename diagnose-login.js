const axios = require('axios');

async function diagnoseLogin() {
  console.log('🔍 Diagnosing login functionality...');
  
  try {
    // First, check if server is running
    console.log('1. Checking server health...');
    const healthResponse = await axios.get('http://localhost:5001/health', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
      }
    });
    console.log('✅ Server is healthy:', healthResponse.data.data.status);
    
    // Test GraphQL introspection
    console.log('\n2. Testing GraphQL introspection...');
    const introspectionQuery = {
      query: `
        query IntrospectionQuery {
          __schema {
            queryType {
              name
            }
            mutationType {
              name
            }
          }
        }
      `
    };
    
    const introspectionResponse = await axios.post('http://localhost:5001/graphql', introspectionQuery, {
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
      }
    });
    
    console.log('✅ GraphQL introspection successful');
    console.log('   Query type:', introspectionResponse.data.data.__schema.queryType.name);
    console.log('   Mutation type:', introspectionResponse.data.data.__schema.mutationType.name);
    
    // Test a simple query
    console.log('\n3. Testing simple GraphQL query...');
    const testQuery = {
      query: `
        query {
          test
        }
      `
    };
    
    const testResponse = await axios.post('http://localhost:5001/graphql', testQuery, {
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
      }
    });
    
    console.log('✅ Simple query successful:', testResponse.data.data.test);
    
    // Test login mutation
    console.log('\n4. Testing login mutation...');
    const loginQuery = {
      query: `
        mutation {
          login(input: {
            email: "test@example.com",
            password: "Test123!",
            tenantId: "default"
          }) {
            user {
              id
              email
              firstName
              lastName
            }
            accessToken
            refreshToken
            expiresIn
            sessionId
          }
        }
      `
    };
    
    const loginResponse = await axios.post('http://localhost:5001/graphql', loginQuery, {
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
      }
    });
    
    console.log('✅ Login mutation response:', JSON.stringify(loginResponse.data, null, 2));
    
    // Check cookies
    const cookies = loginResponse.headers['set-cookie'];
    if (cookies) {
      console.log('🍪 Cookies set:', cookies);
    } else {
      console.log('❌ No cookies set');
    }
    
  } catch (error) {
    console.error('❌ Diagnosis failed:', error.response?.data || error.message);
    
    if (error.response?.data?.errors) {
      console.log('\n🔍 Error details:');
      error.response.data.errors.forEach((err, index) => {
        console.log(`   Error ${index + 1}:`, err.message);
        if (err.path) console.log(`   Path:`, err.path);
        if (err.extensions) console.log(`   Extensions:`, err.extensions);
      });
    }
  }
}

diagnoseLogin();
