import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthResolver } from './auth.resolver';
import { RbacResolver } from './rbac.resolver';
import { JwtStrategy } from './strategies/jwt.strategy';
import { RefreshTokenStrategy } from './strategies/refresh-token.strategy';
import { AuthGuard } from '@/common/guards/auth.guard';
import { PrismaAuthService } from './prisma-auth.service';
import { MfaService } from './services/mfa.service';
import { EmailService } from './services/email.service';
import { RateLimitService } from './services/rate-limit.service';
import { AuditService } from './services/audit.service';
import { RbacService } from './services/rbac.service';
import { InitializationService } from './services/initialization.service';
import { TestResolver } from '../../test-resolver';

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
    RbacResolver,
    TestResolver,
    JwtStrategy,
    RefreshTokenStrategy,
    AuthGuard,
    PrismaAuthService,
    MfaService,
    EmailService,
    RateLimitService,
    AuditService,
    RbacService,
    InitializationService,
  ],
  exports: [
    AuthService, 
    AuthGuard, 
    PrismaAuthService, 
    MfaService, 
    EmailService, 
    RateLimitService, 
    AuditService,
    RbacService,
  ],
})
export class AuthModule {}
