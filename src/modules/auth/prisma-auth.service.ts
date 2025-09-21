import { Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient as AuthPrismaClient } from '.prisma/auth';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class PrismaAuthService extends AuthPrismaClient implements OnModuleInit {
  constructor(private readonly configService: ConfigService) {
    super({
      datasources: {
        db: {
          url: configService.get<string>('app.AUTH_DB_URL'),
        },
      },
    });
  }

  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }

  // User operations
  async findUserByEmail(email: string) {
    return this.user.findUnique({
      where: { email },
    });
  }

  async findUserById(id: number) {
    return this.user.findUnique({
      where: { id },
    });
  }

  async createUser(data: { email: string; password: string }) {
    return this.user.create({
      data,
    });
  }

  // Refresh token operations
  async createRefreshToken(data: { userId: number; token: string; expiresAt: Date }) {
    return this.refreshToken.create({
      data,
    });
  }

  async findRefreshToken(userId: string, token: string) {
    return this.refreshToken.findFirst({
      where: {
        userId: parseInt(userId),
        token,
        expiresAt: {
          gt: new Date(),
        },
        revokedAt: null,
      },
    });
  }

  async revokeRefreshToken(userId: string, token: string) {
    return this.refreshToken.updateMany({
      where: {
        userId: parseInt(userId),
        token,
      },
      data: {
        revokedAt: new Date(),
      },
    });
  }

  async revokeAllRefreshTokens(userId: string) {
    return this.refreshToken.updateMany({
      where: {
        userId: parseInt(userId),
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    });
  }

  async cleanupExpiredTokens() {
    return this.refreshToken.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });
  }
}
