import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';

@Module({
  imports: [
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: true,          // code-first
      sortSchema: true,
      playground: process.env.GRAPHQL_PLAYGROUND === 'true',
      context: ({ request }) => ({ req: request }),
      csrfPrevention: true,
      cache: 'bounded',
    }),
  ],
})
export class GqlModule {}
