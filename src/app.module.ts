import { Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { AppConfigModule } from './config/config.module';
import { GqlModule } from './graphql/graphql.module';
import { AuthModule } from './modules/auth/auth.module';
import { TenantModule } from './modules/tenant/tenant.module';
import { UserModule } from './modules/user/user.module';
import { HealthModule } from './modules/health/health.module';
import { BullInfraModule } from './infra/bullmq/bull.module';
import { S3Module } from './infra/s3/s3.module';
import { RateLimitInterceptor } from './common/interceptors/rate-limit.interceptor';

@Module({
  imports: [
    AppConfigModule,
    JwtModule.register({}), // Global JWT module
    GqlModule,
    AuthModule,
    TenantModule,
    UserModule,
    HealthModule,
    BullInfraModule,
    S3Module,
  ],
  providers: [
    // Temporarily disabled due to Redis connection issues
    // {
    //   provide: APP_INTERCEPTOR,
    //   useClass: RateLimitInterceptor,
    // },
  ],
})
export class AppModule {}
