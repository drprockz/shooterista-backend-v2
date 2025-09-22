import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TenantContextService } from './tenant-context.service';

@Module({
  imports: [ConfigModule],
  providers: [TenantContextService],
  exports: [TenantContextService],
})
export class TenantContextModule {}
