import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { TenantService } from './tenant.service';
import { TenantResolver } from './tenant.resolver';
import { TenantController } from './tenant.controller';
import { PrismaTenantService } from './prisma-tenant.service';

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
  controllers: [TenantController],
  providers: [
    TenantService,
    TenantResolver,
    PrismaTenantService,
  ],
  exports: [
    TenantService,
    PrismaTenantService,
  ],
})
export class TenantModule {}
