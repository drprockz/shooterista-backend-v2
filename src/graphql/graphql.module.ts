import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { ConfigService } from '@nestjs/config';

@Module({
  imports: [
    GraphQLModule.forRootAsync<ApolloDriverConfig>({
      driver: ApolloDriver,
      useFactory: (configService: ConfigService) => ({
        autoSchemaFile: true,          // code-first
        sortSchema: true,
        // Use Apollo Studio Sandbox (modern replacement for GraphQL Playground)
        playground: false, // Disable old playground
        introspection: configService.get<string>('app.GRAPHQL_INTROSPECTION') === 'true',
        debug: configService.get<string>('app.GRAPHQL_DEBUG') === 'true',
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
                    requestContext.response.http.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-apollo-operation-name, apollo-require-preflight');
                    requestContext.response.http.headers.set('Access-Control-Allow-Credentials', 'true');
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
          return {
            message: error.message,
            code: error.extensions?.code,
            path: error.path,
          };
        },
      }),
      inject: [ConfigService],
    }),
  ],
})
export class GqlModule {}
