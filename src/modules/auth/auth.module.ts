import { Module } from '@nestjs/common';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthResolver } from './auth.resolver';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { RefreshTokenStrategy } from './strategies/refresh-token.strategy';
import { AuthGuard } from '@/common/guards/auth.guard';
import { PrismaAuthService } from './prisma-auth.service';
import { MfaService } from './services/mfa.service';
import { RateLimitService } from './services/rate-limit.service';
import { AuditService } from './services/audit.service';
// import { InitializationService } from './services/initialization.service'; // Temporarily disabled
import { OTPService } from './services/otp.service';
import { NotificationsModule } from '../../infra/notifications/notifications.module';
import { TenantContextModule } from '../../infra/tenant-context/tenant-context.module';
import { ProfileCompletionService } from './services/profile-completion.service';
import { ConsentService } from './services/consent.service';
import { SecurityService } from './services/security.service';

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
    NotificationsModule,
    TenantContextModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    AuthResolver,
    JwtStrategy,
    RefreshTokenStrategy,
    AuthGuard,
    PrismaAuthService,
    MfaService,
    RateLimitService,
    AuditService,
    OTPService,
    // ProfileCompletionService, // Temporarily disabled due to missing Prisma methods
    // ConsentService, // Temporarily disabled due to missing Prisma methods
    // SecurityService, // Temporarily disabled due to missing Prisma methods
    // InitializationService, // Temporarily disabled
  ],
  exports: [
    AuthService, 
    AuthGuard, 
    PrismaAuthService, 
    MfaService,
    RateLimitService,
    AuditService,
    OTPService,
    // ProfileCompletionService, // Temporarily disabled
    // ConsentService, // Temporarily disabled
    // SecurityService, // Temporarily disabled
  ],
})
export class AuthModule {}