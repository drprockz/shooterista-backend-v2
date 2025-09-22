import { Injectable } from '@nestjs/common';
import { PrismaClient as UserPrismaClient } from '../../../node_modules/.prisma/user';

@Injectable()
export class PrismaUserService {
  private prisma: UserPrismaClient;

  constructor() {
    this.prisma = new UserPrismaClient();
  }

  async getUserProfile(userId: number) {
    return this.prisma.userProfile.findUnique({
      where: { userId },
    });
  }

  async createUserProfile(userId: number, data: any) {
    return this.prisma.userProfile.create({
      data: {
        userId,
        ...data,
      },
    });
  }

  async updateUserProfile(userId: number, data: any) {
    return this.prisma.userProfile.update({
      where: { userId },
      data,
    });
  }

  async getUserActivities(userId: number, limit = 50, offset = 0) {
    return this.prisma.userActivity.findMany({
      where: { userId },
      orderBy: { occurredAt: 'desc' },
      take: limit,
      skip: offset,
    });
  }

  async getUserNotifications(userId: number, limit = 50, offset = 0) {
    return this.prisma.userNotification.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: limit,
      skip: offset,
    });
  }

  async getUserPreferences(userId: number, category?: string) {
    return this.prisma.userPreference.findMany({
      where: {
        userId,
        ...(category && { category }),
      },
    });
  }

  async onModuleDestroy() {
    await this.prisma.$disconnect();
  }
}
