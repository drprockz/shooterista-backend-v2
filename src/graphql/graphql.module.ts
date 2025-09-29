import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { ConfigService } from '@nestjs/config';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { CsrfInterceptor } from '../common/interceptors/csrf.interceptor';
import { GraphQLContextService } from '../common/context/graphql-context';
import { CorrelationService } from '../common/services/correlation.service';
import { AuthModule } from '../modules/auth/auth.module';
import { AuthResolver } from '../modules/auth/auth.resolver';
import { TestResolver } from '../test-resolver';

@Module({
  imports: [
    AuthModule,
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('app.JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('app.JWT_EXPIRES_IN'),
          issuer: configService.get<string>('app.JWT_ISS'),
          audience: configService.get<string>('app.JWT_AUD'),
        },
      }),
    }),
    GraphQLModule.forRootAsync<ApolloDriverConfig>({
      driver: ApolloDriver,
      useFactory: (configService: ConfigService) => ({
        autoSchemaFile: 'schema.gql',  // code-first
        sortSchema: true,
        // Use Apollo Studio Sandbox (modern replacement for GraphQL Playground)
        playground: configService.get<string>('app.NODE_ENV') === 'development',
        introspection: configService.get<boolean>('app.GRAPHQL_INTROSPECTION') || true, // Enable introspection
        debug: configService.get<boolean>('app.GRAPHQL_DEBUG') || false,
        // Enable Apollo Studio Sandbox
        plugins: configService.get<string>('app.NODE_ENV') === 'development' ? [
          {
            requestDidStart() {
              return {
                willSendResponse(requestContext) {
                  // Add CORS headers for Apollo Studio and development tools
                  if (requestContext.response.http) {
                    requestContext.response.http.headers.set('Access-Control-Allow-Origin', '*');
                    requestContext.response.http.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
                    requestContext.response.http.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-apollo-operation-name, apollo-require-preflight, x-csrf-token');
                    requestContext.response.http.headers.set('Access-Control-Allow-Credentials', 'true');
                    requestContext.response.http.headers.set('X-Content-Type-Options', 'nosniff');
                    requestContext.response.http.headers.set('X-Frame-Options', 'DENY');
                    requestContext.response.http.headers.set('X-XSS-Protection', '1; mode=block');
                    requestContext.response.http.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
                    requestContext.response.http.headers.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
                  }
                },
              };
            },
          } as any,
        ] : [],
        context: ({ request, reply }) => {
          // Generate request ID if not present
          const requestId = request?.headers?.['x-request-id'] || require('uuid').v4();
          if (request?.headers) {
            request.headers['x-request-id'] = requestId;
          }
          
          return { 
            req: request, 
            res: reply,
            requestContext: {
              requestId,
              startTime: Date.now(),
              operationName: 'unknown', // Will be set by resolver
              userEmail: null,
              tenantId: request?.headers?.['x-tenant-id'] || request?.headers?.['x-tenant-slug'],
              ipAddress: request?.ip || 'unknown',
              userAgent: request?.headers?.['user-agent'] || 'unknown'
            }
          };
        },
        csrfPrevention: configService.get<string>('app.NODE_ENV') === 'production',
        cache: 'bounded',
        // Fastify-specific optimizations
        subscriptions: {
          'graphql-ws': true,
          'subscriptions-transport-ws': false,
        },
        formatError: (error) => {
          // Log errors in development
          if (configService.get<string>('app.NODE_ENV') === 'development') {
            console.error('GraphQL Error:', error);
          }
          
          // Don't expose internal errors in production
          const isDevelopment = configService.get<string>('app.NODE_ENV') === 'development';
          
          return {
            message: isDevelopment ? error.message : 'An error occurred',
            code: error.extensions?.code,
            path: error.path,
            extensions: error.extensions,
            ...(isDevelopment && { 
              stack: (error as any).stack,
              originalError: (error as any).originalError?.message 
            }),
          };
        },
        // Security headers
        cors: {
          origin: (() => {
            const corsOrigin = configService.get<string>('app.CORS_ORIGINS');
            return corsOrigin ? corsOrigin.split(',').map(origin => origin.trim()) : ['http://localhost:3000'];
          })(),
          credentials: true,
          methods: ['GET', 'POST', 'OPTIONS'],
          allowedHeaders: [
            'Content-Type',
            'Authorization',
            'x-apollo-operation-name',
            'apollo-require-preflight',
            'x-csrf-token',
          ],
        },
        // Query complexity analysis - disabled for now due to type issues
        // validationRules: [],
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [
    GraphQLContextService,
    CorrelationService,
    CsrfInterceptor,
    AuthResolver,
    TestResolver,
  ],
  exports: [GraphQLContextService],
})
export class GqlModule {}
