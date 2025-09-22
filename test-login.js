const axios = require('axios');

async function testLogin() {
  try {
    console.log('🧪 Testing login functionality...');
    
    // Test GraphQL login
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

    const response = await axios.post('http://localhost:5001/graphql', loginQuery, {
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
      }
    });

    console.log('✅ Login response:', JSON.stringify(response.data, null, 2));
    
    // Check if cookies are set
    const cookies = response.headers['set-cookie'];
    if (cookies) {
      console.log('🍪 Cookies set:', cookies);
    } else {
      console.log('❌ No cookies set');
    }

  } catch (error) {
    console.error('❌ Login test failed:', error.response?.data || error.message);
  }
}

// Test REST login
async function testRestLogin() {
  try {
    console.log('\n🧪 Testing REST login functionality...');
    
    const loginData = {
      email: "test@example.com",
      password: "Test123!",
      tenantId: "default"
    };

    const response = await axios.post('http://localhost:5001/auth/login', loginData, {
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
      }
    });

    console.log('✅ REST Login response:', JSON.stringify(response.data, null, 2));
    
    // Check if cookies are set
    const cookies = response.headers['set-cookie'];
    if (cookies) {
      console.log('🍪 Cookies set:', cookies);
    } else {
      console.log('❌ No cookies set');
    }

  } catch (error) {
    console.error('❌ REST Login test failed:', error.response?.data || error.message);
  }
}

// Run tests
async function runTests() {
  await testLogin();
  await testRestLogin();
}

runTests();
