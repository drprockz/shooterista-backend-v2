import { Resolver, Query, Mutation, Args, Context } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthGuard } from '@/common/guards/auth.guard';
import { CreateUserInput, LoginInput, RefreshTokenInput, LogoutInput } from './dto/auth.input';
import { AuthPayload, TokenRefreshPayload } from './dto/auth.types';

@Resolver()
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

  @Query(() => String)
  async health(): Promise<string> {
    return 'Auth service is healthy';
  }

  @Mutation(() => AuthPayload)
  async register(@Args('input') input: CreateUserInput): Promise<AuthPayload> {
    return this.authService.register(input);
  }

  @Mutation(() => AuthPayload)
  async login(@Args('input') input: LoginInput): Promise<AuthPayload> {
    return this.authService.login(input);
  }

  @Mutation(() => TokenRefreshPayload)
  async refreshToken(@Args('input') input: RefreshTokenInput): Promise<TokenRefreshPayload> {
    return this.authService.refreshTokens(input);
  }

  @Mutation(() => Boolean)
  @UseGuards(AuthGuard)
  async logout(@Args('input') input: LogoutInput, @Context('req') req: any): Promise<boolean> {
    await this.authService.logout(req.user.id, input.refreshToken);
    return true;
  }

  @Mutation(() => Boolean)
  @UseGuards(AuthGuard)
  async logoutAll(@Context('req') req: any): Promise<boolean> {
    await this.authService.logoutAll(req.user.id);
    return true;
  }
}
