import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UserService } from './user.service';
import { UserResolver } from './user.resolver';
import { UserController } from './user.controller';
import { PrismaUserService } from './prisma-user.service';

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
  controllers: [UserController],
  providers: [
    UserService,
    UserResolver,
    PrismaUserService,
  ],
  exports: [
    UserService,
    PrismaUserService,
  ],
})
export class UserModule {}
