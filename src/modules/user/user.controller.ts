import { Controller, Get, Put, Body, Request, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { UserService } from './user.service';
import { AuthGuard } from '@/common/guards/auth.guard';

@ApiTags('User')
@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get('profile')
  @UseGuards(AuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Get user profile',
    description: 'Get current user profile information'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'User profile retrieved' 
  })
  async getUserProfile(@Request() req: any) {
    return this.userService.getUserProfile(req.user.id);
  }

  @Put('profile')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Update user profile',
    description: 'Update current user profile information'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'User profile updated successfully' 
  })
  async updateUserProfile(
    @Body() data: any,
    @Request() req: any,
  ) {
    return this.userService.updateUserProfile(req.user.id, data);
  }

  @Get('activities')
  @UseGuards(AuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Get user activities',
    description: 'Get user activity history'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'User activities retrieved' 
  })
  async getUserActivities(@Request() req: any) {
    return this.userService.getUserActivities(req.user.id);
  }

  @Get('notifications')
  @UseGuards(AuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Get user notifications',
    description: 'Get user notifications'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'User notifications retrieved' 
  })
  async getUserNotifications(@Request() req: any) {
    return this.userService.getUserNotifications(req.user.id);
  }

  @Get('preferences')
  @UseGuards(AuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Get user preferences',
    description: 'Get user preferences and settings'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'User preferences retrieved' 
  })
  async getUserPreferences(@Request() req: any) {
    return this.userService.getUserPreferences(req.user.id);
  }
}
