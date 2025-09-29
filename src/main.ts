import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import pino from 'pino';
import { v4 as uuid } from 'uuid';
import { ValidationPipe } from '@/common/pipes/validation.pipe';
import { GlobalExceptionFilter } from '@/common/filters/global-exception.filter';
import { FastifyExceptionFilter } from '@/common/filters/fastify-exception.filter';
import { ResponseInterceptor } from '@/common/interceptors/response.interceptor';
import { RateLimitInterceptor } from '@/common/interceptors/rate-limit.interceptor';
import { ProcessSafetyService } from '@/common/services/process-safety.service';
import { 
  createFastifyCorsOptions,
  fastifyRequestIdMiddleware,
  fastifySecurityHeadersMiddleware,
  fastifyIpValidationMiddleware,
  createFastifyRequestSizeMiddleware,
  fastifyUserAgentValidationMiddleware,
  createFastifyRateLimitMiddleware
} from '@/common/middleware/fastify-security.middleware';

async function bootstrap() {
  // Initialize process safety nets first
  const processSafetyService = new ProcessSafetyService();
  processSafetyService.initialize();

  // Log environment information at startup
  const nodeEnv = process.env.NODE_ENV || 'development';
  const envFile = nodeEnv === 'development' ? '.env.development' : 
                 nodeEnv === 'production' ? '.env.production' : 
                 nodeEnv === 'test' ? '.env.test' : '.env';
  
  console.log(`🚀 Starting Shooterista Backend`);
  console.log(`📁 Environment: ${nodeEnv}`);
  console.log(`📄 Config file: ${envFile}`);
  console.log(`⏰ Started at: ${new Date().toISOString()}`);

  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule, 
    new FastifyAdapter({
      logger: false, // We'll use our own logger
      trustProxy: true,
      // Fastify performance optimizations
      bodyLimit: 10485760, // 10MB
      maxParamLength: 200,
      ignoreTrailingSlash: true,
      caseSensitive: false,
    })
  );

  const configService = app.get(ConfigService);

  // Add security headers and optimizations using Fastify's built-in capabilities
  const fastifyInstance = app.getHttpAdapter().getInstance();
  
  // Security headers
  fastifyInstance.addHook('onSend', async (request, reply, payload) => {
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('X-Frame-Options', 'DENY');
    reply.header('X-XSS-Protection', '1; mode=block');
    reply.header('Referrer-Policy', 'strict-origin-when-cross-origin');
    reply.header('Server', 'Shooterista-API');
    return payload;
  });

  // Request logging and performance monitoring
  fastifyInstance.addHook('onRequest', async (request, reply) => {
    (request as any).startTime = Date.now();
  });

  fastifyInstance.addHook('onResponse', async (request, reply) => {
    const duration = Date.now() - ((request as any).startTime || Date.now());
    reply.header('X-Response-Time', `${duration}ms`);
  });

  // Logger configuration
  const logLevel = configService.get<string>('app.LOG_LEVEL') || 'info';
  const logFormat = configService.get<string>('app.LOG_FORMAT') || 'json';
  
  const logger = pino({
    level: logLevel,
    ...(logFormat === 'pretty' && {
      transport: {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:standard',
        },
      },
    }),
  });

  // Enhanced Security Middleware - Fastify compatible
  const corsOptions = createFastifyCorsOptions(configService);
  app.enableCors(corsOptions);

  // Apply Fastify-compatible security middleware using hooks
  fastifyInstance.addHook('onRequest', fastifySecurityHeadersMiddleware);
  fastifyInstance.addHook('onRequest', fastifyIpValidationMiddleware);
  fastifyInstance.addHook('onRequest', createFastifyRequestSizeMiddleware(configService.get<number>('app.MAX_FILE_SIZE') || 10485760));
  fastifyInstance.addHook('onRequest', fastifyUserAgentValidationMiddleware);
  fastifyInstance.addHook('onRequest', createFastifyRateLimitMiddleware(configService));

  // Swagger API Documentation
  if (configService.get<string>('app.NODE_ENV') === 'development') {
    try {
      const config = new DocumentBuilder()
        .setTitle('Shooterista API')
        .setDescription('The Shooterista backend API documentation')
        .setVersion(configService.get<string>('app.API_VERSION') || 'v1')
        .addBearerAuth(
          {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
            name: 'JWT',
            description: 'Enter JWT token',
            in: 'header',
          },
          'JWT-auth',
        )
        .addTag('Health', 'Health check endpoints')
        .addTag('Auth', 'Authentication and authorization')
        .addTag('Tenant', 'Tenant and organization management')
        .addTag('User', 'User profile management')
        .addTag('Athletes', 'Athlete management')
        .addTag('Competitions', 'Competition management')
        .addServer(`http://localhost:${configService.get<number>('app.PORT') || 5001}`, 'Development server')
        .build();

      const document = SwaggerModule.createDocument(app, config);
      SwaggerModule.setup('api/docs', app, document, {
        swaggerOptions: {
          persistAuthorization: true,
          displayRequestDuration: true,
          docExpansion: 'none',
          filter: true,
          showRequestHeaders: true,
          tryItOutEnabled: true,
        },
        customSiteTitle: 'Shooterista API Documentation',
        customfavIcon: '/favicon.ico',
      });
      
      logger.info('📚 Swagger documentation available at: http://localhost:5001/api/docs');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.warn(`⚠️  Swagger setup failed: ${errorMessage}`);
    }
  }

  // Request logging using Fastify hooks
  fastifyInstance.addHook('onRequest', async (request, reply) => {
    const requestId = request.headers['x-request-id'] as string || uuid();
    request.headers['x-request-id'] = requestId;
    reply.header('X-Request-ID', requestId);
    
    // Log request
    logger.info({
      method: request.method,
      url: request.url,
      headers: {
        host: request.headers.host,
        'user-agent': request.headers['user-agent'],
        'content-length': request.headers['content-length'],
      },
      tenant: request.headers['x-tenant-id'] || null,
      requestId,
    }, 'Incoming request');
  });

  fastifyInstance.addHook('onResponse', async (request, reply) => {
    // Log response
    const startTime = (request as any).startTime || Date.now();
    const responseTime = Date.now() - startTime;
    
    logger.info({
      method: request.method,
      url: request.url,
      statusCode: reply.statusCode,
      responseTime: `${responseTime}ms`,
      requestId: request.headers['x-request-id'],
    }, 'Request completed');
  });

  // Global pipes, filters, and interceptors
  app.useGlobalPipes(new ValidationPipe());
  // Note: FastifyExceptionFilter removed - using GlobalExceptionFilter for GraphQL
  app.useGlobalInterceptors(new ResponseInterceptor());

  // Add a simple root route
  app.getHttpAdapter().get('/', (request, reply) => {
    reply.send({
      message: 'Shooterista API is running!',
      version: configService.get<string>('app.API_VERSION') || 'v1',
      environment: configService.get<string>('app.NODE_ENV'),
      timestamp: new Date().toISOString(),
      endpoints: {
        health: '/health',
        graphql: '/graphql',
        docs: '/api/docs',
        apolloStudio: 'https://studio.apollographql.com/sandbox/explorer'
      }
    });
  });

  // Graceful shutdown
  process.on('SIGTERM', async () => {
    logger.info('SIGTERM received, shutting down gracefully');
    await app.close();
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    logger.info('SIGINT received, shutting down gracefully');
    await app.close();
    process.exit(0);
  });

  const port = configService.get<number>('app.PORT') || 5001;
  await app.listen({ port, host: '0.0.0.0' });
  
  logger.info(`🚀 Application is running on: http://localhost:${port}`);
  logger.info(`📊 Health checks available at: http://localhost:${port}/health`);
  logger.info(`🔍 GraphQL Sandbox: http://localhost:${port}/graphql`);
  if (configService.get<string>('app.NODE_ENV') === 'development') {
    logger.info(`📚 API Documentation: http://localhost:${port}/api/docs`);
    logger.info(`🔧 Apollo Studio Sandbox: https://studio.apollographql.com/sandbox/explorer`);
  }
}

bootstrap().catch((error) => {
  console.error('❌ Error starting server:', error);
  process.exit(1);
});
