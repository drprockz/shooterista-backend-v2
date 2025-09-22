const express = require('express');
const cors = require('cors');
const app = express();

// Enable CORS
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:4000'],
  credentials: true
}));

app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    data: {
      status: 'ok',
      info: {
        'auth-database': { status: 'up', message: 'Database connection is healthy' },
        'redis': { status: 'up', message: 'Redis connection is healthy' },
        's3': { status: 'up', message: 'S3 connection is healthy', bucket: 'dev-shooterista' }
      },
      error: {},
      details: {
        'auth-database': { status: 'up', message: 'Database connection is healthy' },
        'redis': { status: 'up', message: 'Redis connection is healthy' },
        's3': { status: 'up', message: 'S3 connection is healthy', bucket: 'dev-shooterista' }
      }
    },
    meta: {
      timestamp: new Date().toISOString(),
      requestId: Math.random().toString(36).substr(2, 9),
      version: 'v1'
    }
  });
});

// Simple login endpoint
app.post('/auth/login', (req, res) => {
  console.log('🔍 REST Login endpoint called:', {
    email: req.body.email,
    tenantId: req.body.tenantId,
    ip: req.ip,
    userAgent: req.headers['user-agent']?.substring(0, 50) + '...',
    headers: {
      'content-type': req.headers['content-type'],
      'origin': req.headers['origin'],
      'x-tenant-id': req.headers['x-tenant-id']
    }
  });

  // Mock successful login response
  const mockResponse = {
    user: {
      id: '1',
      email: req.body.email,
      firstName: 'Test',
      lastName: 'User',
      userType: 'ATHLETE',
      isEmailVerified: true,
      isMfaEnabled: false,
      lastLoginAt: new Date().toISOString(),
      passwordChangedAt: null,
      status: 'ACTIVE',
      tenantId: req.body.tenantId || 'default',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      roles: [],
      permissions: []
    },
    accessToken: 'mock-access-token-' + Date.now(),
    refreshToken: 'mock-refresh-token-' + Date.now(),
    expiresIn: 900, // 15 minutes
    profileComplete: true,
    sessionId: 'mock-session-' + Date.now()
  };

  // Set cookies
  res.cookie('access_token', mockResponse.accessToken, {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    maxAge: 15 * 60 * 1000, // 15 minutes
    path: '/'
  });

  res.cookie('refresh_token', mockResponse.refreshToken, {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/'
  });

  res.cookie('tenant_id', req.body.tenantId || 'default', {
    httpOnly: false,
    secure: false,
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    path: '/'
  });

  console.log('🎉 Mock login successful:', {
    userId: mockResponse.user.id,
    email: mockResponse.user.email,
    sessionId: mockResponse.sessionId,
    hasAccessToken: !!mockResponse.accessToken,
    hasRefreshToken: !!mockResponse.refreshToken
  });

  res.json(mockResponse);
});

// GraphQL endpoint
app.post('/graphql', (req, res) => {
  console.log('🔍 GraphQL endpoint called:', {
    query: req.body.query?.substring(0, 100) + '...',
    variables: req.body.variables,
    ip: req.ip,
    userAgent: req.headers['user-agent']?.substring(0, 50) + '...'
  });

  // Simple GraphQL response
  if (req.body.query?.includes('login')) {
    const mockResponse = {
      data: {
        login: {
          user: {
            id: '1',
            email: 'test@example.com',
            firstName: 'Test',
            lastName: 'User',
            userType: 'ATHLETE',
            isEmailVerified: true,
            isMfaEnabled: false,
            lastLoginAt: new Date().toISOString(),
            passwordChangedAt: null,
            status: 'ACTIVE',
            tenantId: 'default',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            roles: [],
            permissions: []
          },
          accessToken: 'mock-access-token-' + Date.now(),
          refreshToken: 'mock-refresh-token-' + Date.now(),
          expiresIn: 900,
          profileComplete: true,
          sessionId: 'mock-session-' + Date.now()
        }
      }
    };

    // Set cookies
    res.cookie('access_token', mockResponse.data.login.accessToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000,
      path: '/'
    });

    res.cookie('refresh_token', mockResponse.data.login.refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/'
    });

    res.cookie('tenant_id', 'default', {
      httpOnly: false,
      secure: false,
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000,
      path: '/'
    });

    console.log('🎉 Mock GraphQL login successful');
    res.json(mockResponse);
  } else {
    res.json({ data: { test: 'GraphQL endpoint is working' } });
  }
});

const PORT = 5001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Simple test server running on http://localhost:${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔐 Login endpoint: http://localhost:${PORT}/auth/login`);
  console.log(`🔍 GraphQL endpoint: http://localhost:${PORT}/graphql`);
});
