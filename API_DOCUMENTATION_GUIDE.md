# 🚀 Shooterista API Documentation & Testing Guide

## 📋 Overview

Your NestJS backend with Fastify is now fully equipped with comprehensive API documentation and testing tools. This guide covers all available tools and how to use them effectively.

## 🛠️ Available Tools

### 1. **Swagger UI** - REST API Documentation
- **URL**: `http://localhost:5001/api/docs`
- **Purpose**: Interactive REST API documentation
- **Features**:
  - Complete API endpoint documentation
  - Interactive testing interface
  - JWT authentication support
  - Request/response examples
  - Schema validation

### 2. **GraphQL Endpoint** - GraphQL API
- **URL**: `http://localhost:5001/graphql`
- **Purpose**: GraphQL API endpoint
- **Features**:
  - Apollo Server with Fastify
  - Schema introspection (when enabled)
  - CSRF protection
  - Optimized for Fastify

### 3. **Apollo Studio Sandbox** - Modern GraphQL IDE
- **URL**: `https://studio.apollographql.com/sandbox/explorer`
- **Purpose**: Modern GraphQL development environment
- **Features**:
  - Advanced query editor
  - Schema exploration
  - Query history
  - Real-time collaboration
  - Better performance than GraphQL Playground

### 4. **Health Check Endpoints** - System Monitoring
- **Live Check**: `http://localhost:5001/health/live`
- **Readiness Check**: `http://localhost:5001/health/ready`
- **Full Health Check**: `http://localhost:5001/health`

## 🔧 Configuration

### Environment Variables
```bash
# GraphQL Configuration
GRAPHQL_PLAYGROUND="true"        # Enable GraphQL Playground (deprecated)
GRAPHQL_INTROSPECTION="true"     # Enable schema introspection
GRAPHQL_DEBUG="true"             # Enable debug mode

# Application Configuration
NODE_ENV="development"           # Swagger only available in development
PORT=5001                        # Application port
```

### GraphQL Configuration
- **Introspection**: Enabled in development
- **Playground**: Disabled (using Apollo Studio instead)
- **CSRF Protection**: Enabled
- **Caching**: Bounded cache enabled

## 🧪 Testing Your APIs

### 1. Testing REST Endpoints

#### Using Swagger UI
1. Open `http://localhost:5001/api/docs`
2. Click on any endpoint to expand
3. Click "Try it out" button
4. Fill in parameters and click "Execute"
5. View response in the interface

#### Using curl
```bash
# Health check
curl http://localhost:5001/health/live

# With headers
curl -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:5001/api/endpoint
```

### 2. Testing GraphQL

#### Using Apollo Studio Sandbox
1. Open `https://studio.apollographql.com/sandbox/explorer`
2. Enter your GraphQL endpoint: `http://localhost:5001/graphql`
3. Start exploring and testing queries

#### Using curl
```bash
# Simple query (CSRF protection disabled in development)
curl -X POST http://localhost:5001/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "query { __typename }"}'

# With variables
curl -X POST http://localhost:5001/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query GetUser($id: ID!) { user(id: $id) { name email } }",
    "variables": {"id": "1"}
  }'

# For production or when CSRF is enabled, use these headers:
curl -X POST http://localhost:5001/graphql \
  -H "Content-Type: application/json" \
  -H "apollo-require-preflight: true" \
  -d '{"query": "query { __typename }"}'
```

#### Using GraphQL Playground (Alternative)
If you prefer the traditional GraphQL Playground:
1. Set `GRAPHQL_PLAYGROUND="true"` in your environment
2. Restart the application
3. Visit `http://localhost:5001/graphql`

## 📊 API Documentation Features

### Swagger Documentation
- **Interactive Interface**: Test endpoints directly in the browser
- **Authentication**: JWT Bearer token support
- **Schema Validation**: Automatic request/response validation
- **Code Generation**: Export client SDKs
- **Versioning**: API version management

### GraphQL Features
- **Schema Introspection**: Explore available types and queries
- **Query Validation**: Real-time query validation
- **Performance Monitoring**: Built-in query performance tracking
- **Error Handling**: Detailed error messages and stack traces

## 🔒 Security Features

### REST API Security
- **CORS**: Configurable cross-origin resource sharing
- **Security Headers**: XSS protection, content type options, frame options
- **Rate Limiting**: Built-in rate limiting (configurable)
- **JWT Authentication**: Secure token-based authentication

### GraphQL Security
- **CSRF Protection**: Disabled in development, enabled in production
- **Query Depth Limiting**: Prevent deeply nested queries
- **Query Complexity Analysis**: Prevent expensive queries
- **Introspection Control**: Disabled by default for security
- **CORS Headers**: Properly configured for development tools

## 🚀 Performance Optimizations

### Fastify Optimizations
- **Compression**: Built-in gzip/deflate compression
- **Request Parsing**: Optimized JSON parsing
- **Response Serialization**: Fast JSON serialization
- **Connection Pooling**: Efficient database connections

### GraphQL Optimizations
- **Query Caching**: Bounded cache for repeated queries
- **Schema Caching**: Compiled schema caching
- **Response Compression**: Automatic response compression
- **Query Batching**: Support for query batching

## 📝 Development Workflow

### 1. API Development
1. Define your REST endpoints with Swagger decorators
2. Create GraphQL resolvers and types
3. Test using Swagger UI and Apollo Studio
4. Document your APIs with proper descriptions

### 2. Testing Workflow
1. Use Swagger UI for REST endpoint testing
2. Use Apollo Studio for GraphQL query testing
3. Monitor health endpoints for system status
4. Use curl/Postman for automated testing

### 3. Documentation Maintenance
1. Keep Swagger decorators up to date
2. Update GraphQL schema documentation
3. Maintain API versioning
4. Update health check indicators

## 🎯 Best Practices

### REST API
- Use descriptive endpoint names
- Include proper HTTP status codes
- Implement proper error handling
- Add comprehensive Swagger documentation

### GraphQL
- Use descriptive field names
- Implement proper error handling
- Add schema documentation
- Use data loaders for N+1 query problems

### General
- Keep documentation up to date
- Test all endpoints regularly
- Monitor performance metrics
- Use proper authentication

## 🔧 Troubleshooting

### Common Issues

1. **Swagger UI not loading**
   - Check if `NODE_ENV=development`
   - Verify Swagger dependencies are installed
   - Check application logs for errors

2. **GraphQL CSRF errors**
   - Add `apollo-require-preflight: true` header
   - Use proper Content-Type headers
   - Check CORS configuration

3. **Health checks failing**
   - Verify database connections
   - Check Redis connectivity
   - Review health indicator configurations

### Debug Commands
```bash
# Check application status
curl http://localhost:5001/health/live

# Test GraphQL
curl -X POST http://localhost:5001/graphql \
  -H "Content-Type: application/json" \
  -H "apollo-require-preflight: true" \
  -d '{"query": "query { __typename }"}'

# Check Swagger
curl -I http://localhost:5001/api/docs
```

## 📚 Additional Resources

- [NestJS Documentation](https://docs.nestjs.com/)
- [Fastify Documentation](https://www.fastify.io/docs/latest/)
- [Apollo Server Documentation](https://www.apollographql.com/docs/apollo-server/)
- [Swagger UI Documentation](https://swagger.io/tools/swagger-ui/)
- [GraphQL Best Practices](https://graphql.org/learn/best-practices/)

---

**Happy coding! 🎉** Your API is now fully documented and ready for development and testing.
