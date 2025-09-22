import { Resolver, Query } from '@nestjs/graphql';

@Resolver()
export class TestResolver {
  @Query(() => String)
  async test(): Promise<string> {
    return 'Test query works!';
  }

  @Query(() => String)
  async hello(): Promise<string> {
    return 'Hello from GraphQL!';
  }
}
