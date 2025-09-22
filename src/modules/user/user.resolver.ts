import { Resolver, Query, Mutation, Args, Context } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { AuthGuard } from '@/common/guards/auth.guard';

@Resolver()
export class UserResolver {
  constructor(private readonly userService: UserService) {}

  @Query(() => String)
  async userHealth(): Promise<string> {
    return 'User service is healthy';
  }

  @Query(() => String)
  @UseGuards(AuthGuard)
  async getUserProfile(@Context('req') req: any): Promise<string> {
    const profile = await this.userService.getUserProfile(req.user.id);
    return profile ? 'Profile exists' : 'No profile found';
  }

  @Mutation(() => String)
  @UseGuards(AuthGuard)
  async updateUserProfile(
    @Args('data') data: string,
    @Context('req') req: any,
  ): Promise<string> {
    await this.userService.updateUserProfile(req.user.id, data);
    return 'Profile updated successfully';
  }

  @Query(() => [String])
  @UseGuards(AuthGuard)
  async getUserActivities(@Context('req') req: any): Promise<string[]> {
    const activities = await this.userService.getUserActivities(req.user.id);
    return activities.map(activity => activity.action);
  }

  @Query(() => [String])
  @UseGuards(AuthGuard)
  async getUserNotifications(@Context('req') req: any): Promise<string[]> {
    const notifications = await this.userService.getUserNotifications(req.user.id);
    return notifications.map(notification => notification.title);
  }

  @Query(() => [String])
  @UseGuards(AuthGuard)
  async getUserPreferences(@Context('req') req: any): Promise<string[]> {
    const preferences = await this.userService.getUserPreferences(req.user.id);
    return preferences.map(pref => `${pref.category}:${pref.key}`);
  }
}
