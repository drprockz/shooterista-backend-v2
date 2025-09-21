# Shooterista Backend API v2

A production-ready GraphQL API built with NestJS, Prisma, and TypeScript for managing shooting competitions, athletes, and scoring data.

## 🚀 Features

### Core Features
- **GraphQL API** with Apollo Server integration
- **Multi-database architecture** (Auth, Athletes, Competitions)
- **JWT Authentication** with token rotation
- **Role-based access control**
- **Real-time updates** with subscriptions
- **File upload** with S3-compatible storage
- **Background job processing** with BullMQ

### Security Features
- **JWT token rotation** and refresh mechanism
- **Rate limiting** and DDoS protection
- **Input validation** and sanitization
- **Security headers** (CSRF, XSS, HSTS)
- **CORS configuration**
- **Request/response logging**

### Operational Features
- **Health checks** for all services
- **Metrics and monitoring**
- **Graceful shutdown**
- **Docker support**
- **Comprehensive testing**
- **TypeScript throughout**

## 🏗️ Architecture

```
src/
├── common/               # Shared utilities
│   ├── filters/         # Exception filters
│   ├── guards/          # Authentication guards
│   ├── interceptors/    # Request/response interceptors
│   └── pipes/           # Validation pipes
├── config/              # Configuration management
├── graphql/             # GraphQL module setup
├── infra/               # Infrastructure modules
│   ├── bullmq/          # Queue management
│   └── s3/              # Object storage
├── modules/             # Business logic modules
│   ├── auth/            # Authentication & authorization
│   └── health/          # Health check endpoints
└── prisma/              # Database schemas
    ├── auth/            # User authentication
    ├── athletes/        # Athletes & tenants
    └── competitions/    # Competitions & scoring
```

## 🛠️ Setup Instructions

### Prerequisites
- Node.js 18+ 
- Docker & Docker Compose
- MySQL 8.0+
- Redis 6+

### 1. Environment Setup

Copy the environment template:
```bash
cp .env.development .env
```

Update the `.env` file with your configuration:
```env
# Application
NODE_ENV=development
PORT=4000

# Database URLs
AUTH_DB_URL="mysql://root:password@localhost:3306/shooterista_auth"
ATHLETES_DB_URL="mysql://root:password@localhost:3306/shooterista_athletes"
COMPETITIONS_DB_URL="mysql://root:password@localhost:3306/shooterista_competitions"

# Redis
REDIS_URL="redis://localhost:6379"

# JWT Configuration
JWT_SECRET="your-super-secret-jwt-key"
JWT_EXPIRES_IN="15m"
JWT_REFRESH_EXPIRES_IN="7d"

# S3/Object Storage
S3_ACCESS_KEY_ID="minioadmin"
S3_SECRET_ACCESS_KEY="minioadmin"
S3_ENDPOINT="http://localhost:9000"
S3_BUCKET_NAME="shooterista-uploads"
```

### 2. Infrastructure Setup

Start all required services:
```bash
# Start databases, Redis, and MinIO
npm run infra:up

# Wait for services to be ready, then install dependencies
npm install
```

### 3. Database Setup

```bash
# Run database migrations
npm run prisma:migrate

# Generate Prisma clients
npm run prisma:gen
```

### 4. Development

```bash
# Start in development mode
npm run dev

# Or use NestJS CLI
npm run start:dev
```

The API will be available at:
- **GraphQL Playground**: http://localhost:4000/graphql
- **Health Checks**: http://localhost:4000/health
- **Database Admin**: http://localhost:8080 (Adminer)
- **Redis Admin**: http://localhost:8081 (Redis Commander)
- **MinIO Console**: http://localhost:9001

## 🧪 Testing

```bash
# Run unit tests
npm test

# Run tests with coverage
npm run test:cov

# Run e2e tests
npm run test:e2e

# Watch mode
npm run test:watch
```

## 📊 API Documentation

### Authentication

```graphql
# Register a new user
mutation Register {
  register(input: {
    email: "user@example.com"
    password: "securePassword123"
  }) {
    user {
      id
      email
    }
    accessToken
    refreshToken
    expiresIn
  }
}

# Login
mutation Login {
  login(input: {
    email: "user@example.com"
    password: "securePassword123"
  }) {
    user {
      id
      email
    }
    accessToken
    refreshToken
  }
}

# Refresh tokens
mutation RefreshToken {
  refreshToken(input: {
    refreshToken: "your-refresh-token"
  }) {
    accessToken
    refreshToken
    expiresIn
  }
}
```

### Health Checks

```bash
# Overall health
curl http://localhost:4000/health

# Readiness check
curl http://localhost:4000/health/ready

# Liveness check  
curl http://localhost:4000/health/live
```

## 🔒 Security Features

### JWT Authentication
- **Access tokens**: Short-lived (15 minutes)
- **Refresh tokens**: Long-lived (7 days) with rotation
- **Token validation**: Issuer, audience, and expiration checks
- **Secure storage**: Refresh tokens stored securely in database

### Security Headers
- **HSTS**: HTTP Strict Transport Security
- **CSP**: Content Security Policy
- **X-Frame-Options**: Clickjacking protection
- **X-Content-Type-Options**: MIME sniffing protection

### Rate Limiting
- **Configurable limits**: Per IP and per user
- **Redis-backed**: Distributed rate limiting
- **Graceful handling**: Informative error responses

## 🐳 Docker Deployment

### Development
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Production
```bash
# Build production image
docker build -t shooterista-api .

# Run with production compose
docker-compose -f docker-compose.prod.yml up -d
```

## 📈 Monitoring

### Health Endpoints
- `/health` - Complete health check
- `/health/ready` - Readiness probe
- `/health/live` - Liveness probe

### Metrics
- Database connection status
- Redis connectivity
- S3 bucket accessibility
- Memory and CPU usage
- Request/response times

### Logging
- **Structured logging** with Pino
- **Request tracing** with correlation IDs
- **Error tracking** with stack traces
- **Performance monitoring**

## 🔧 Configuration

All configuration is managed through environment variables and validated with Zod schemas:

```typescript
// Configuration is type-safe and validated
const config = {
  port: z.coerce.number().default(4000),
  jwtSecret: z.string().min(32),
  corsOrigins: z.string().transform(val => val.split(',')),
  // ... more config
}
```

## 🤝 Development Guidelines

### Code Style
- **ESLint**: Code linting
- **Prettier**: Code formatting
- **TypeScript**: Type safety
- **Conventional Commits**: Commit message format

### Testing Strategy
- **Unit tests**: Individual components
- **Integration tests**: Module interactions  
- **E2E tests**: Full API workflows
- **Minimum 80% coverage**

### Database Management
- **Prisma migrations**: Version controlled schema changes
- **Multi-database**: Separate schemas for different domains
- **Type generation**: Automatic TypeScript types from schema

## 📚 Additional Resources

- [NestJS Documentation](https://docs.nestjs.com/)
- [Prisma Documentation](https://www.prisma.io/docs/)
- [GraphQL Documentation](https://graphql.org/learn/)
- [Fastify Documentation](https://www.fastify.io/docs/)

## 🐛 Troubleshooting

### Common Issues

**Database connection errors:**
```bash
# Check if databases are running
docker-compose ps

# View database logs
docker-compose logs mysql
```

**Prisma client not found:**
```bash
# Regenerate Prisma clients
npm run prisma:gen
```

**Permission errors:**
```bash
# Reset Docker volumes
docker-compose down -v
docker-compose up -d
```

## 📝 License

This project is licensed under the ISC License.

---

**Happy coding! 🚀**
