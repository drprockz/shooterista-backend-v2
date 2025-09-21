import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthResolver } from './auth.resolver';
import { JwtStrategy } from './strategies/jwt.strategy';
import { RefreshTokenStrategy } from './strategies/refresh-token.strategy';
import { AuthGuard } from '@/common/guards/auth.guard';
import { PrismaAuthService } from './prisma-auth.service';

@Module({
  imports: [
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
  ],
  providers: [
    AuthService,
    AuthResolver,
    JwtStrategy,
    RefreshTokenStrategy,
    AuthGuard,
    PrismaAuthService,
  ],
  exports: [AuthService, AuthGuard, PrismaAuthService],
})
export class AuthModule {}
