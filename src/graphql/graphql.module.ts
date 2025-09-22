import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { ConfigService } from '@nestjs/config';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { CsrfInterceptor } from '../common/interceptors/csrf.interceptor';
import { GraphQLContextService } from '../common/context/graphql-context';
import { AuthModule } from '../modules/auth/auth.module';
import { AuthResolver } from '../modules/auth/auth.resolver';
import { RbacResolver } from '../modules/auth/rbac.resolver';
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
        context: ({ request }) => ({ req: request }),
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
            ...(isDevelopment && { 
              stack: (error as any).stack,
              originalError: (error as any).originalError?.message 
            }),
          };
        },
        // Security headers
        cors: {
          origin: configService.get<string>('app.CORS_ORIGIN')?.split(',') || ['http://localhost:3000'],
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
    CsrfInterceptor,
    AuthResolver,
    RbacResolver,
    TestResolver,
  ],
  exports: [GraphQLContextService],
})
export class GqlModule {}
