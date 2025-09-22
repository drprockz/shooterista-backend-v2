import { Injectable } from '@nestjs/common';
import { PrismaUserService } from './prisma-user.service';

@Injectable()
export class UserService {
  constructor(private readonly prismaUser: PrismaUserService) {}

  async getUserProfile(userId: number) {
    return this.prismaUser.getUserProfile(userId);
  }

  async updateUserProfile(userId: number, data: any) {
    return this.prismaUser.updateUserProfile(userId, data);
  }

  async getUserActivities(userId: number, limit = 50, offset = 0) {
    return this.prismaUser.getUserActivities(userId, limit, offset);
  }

  async getUserNotifications(userId: number, limit = 50, offset = 0) {
    return this.prismaUser.getUserNotifications(userId, limit, offset);
  }

  async getUserPreferences(userId: number, category?: string) {
    return this.prismaUser.getUserPreferences(userId, category);
  }
}
