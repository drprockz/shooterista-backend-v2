import 'reflect-metadata';

// Global test setup
beforeAll(async () => {
  // Set test environment variables if not already set
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = 'test-secret';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.AUTH_DB_URL = 'mysql://root:password@localhost:3306/test_auth';
  process.env.ATHLETES_DB_URL = 'mysql://root:password@localhost:3306/test_athletes';
  process.env.COMPETITIONS_DB_URL = 'mysql://root:password@localhost:3306/test_competitions';
});

afterAll(async () => {
  // Cleanup after all tests
});
