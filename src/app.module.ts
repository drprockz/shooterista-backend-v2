import { Module } from '@nestjs/common';
import { AppConfigModule } from './config/config.module';
import { GqlModule } from './graphql/graphql.module';
// import { AuthModule } from './modules/auth/auth.module';
import { BullInfraModule } from './infra/bullmq/bull.module';
import { S3Module } from './infra/s3/s3.module';
// import { HealthController } from './rest/health.controller';
// import { AthletesModule } from './modules/athletes/athletes.module';

@Module({
  imports: [
    AppConfigModule,
    GqlModule,
    BullInfraModule,
    S3Module,
//     AuthModule,
//     AthletesModule,
  ],
//   controllers: [HealthController],
})
export class AppModule {}
