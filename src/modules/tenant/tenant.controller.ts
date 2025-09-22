import { Controller, Post, Get, Put, Body, Request, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiBody } from '@nestjs/swagger';
import { TenantService } from './tenant.service';
import { AuthGuard } from '@/common/guards/auth.guard';
import { 
  CreateTenantInput, 
  UpdateTenantInput, 
  TenantInviteInput,
  TenantSwitchInput 
} from './dto/tenant.input';
import { 
  Tenant, 
  TenantUser, 
  TenantInvitation,
  TenantSwitchResponse 
} from './dto/tenant.types';

@ApiTags('Tenant')
@Controller('tenant')
export class TenantController {
  constructor(private readonly tenantService: TenantService) {}

  @Post()
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.CREATED)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Create new tenant',
    description: 'Create a new tenant/organization'
  })
  @ApiResponse({ 
    status: 201, 
    description: 'Tenant created successfully',
    type: Tenant 
  })
  @ApiBody({ type: CreateTenantInput })
  async createTenant(
    @Body() input: CreateTenantInput,
    @Request() req: any,
  ): Promise<Tenant> {
    return this.tenantService.createTenant(input, req.user.id);
  }

  @Get(':id')
  @UseGuards(AuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Get tenant by ID',
    description: 'Get tenant information by ID'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Tenant information retrieved',
    type: Tenant 
  })
  async getTenant(
    @Request() req: any,
  ): Promise<Tenant> {
    const tenantId = req.params.id;
    return this.tenantService.getTenant(tenantId);
  }

  @Get('slug/:slug')
  @UseGuards(AuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Get tenant by slug',
    description: 'Get tenant information by slug'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Tenant information retrieved',
    type: Tenant 
  })
  async getTenantBySlug(
    @Request() req: any,
  ): Promise<Tenant> {
    return this.tenantService.getTenantBySlug(req.params.slug);
  }

  @Put(':id')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Update tenant',
    description: 'Update tenant information'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Tenant updated successfully',
    type: Tenant 
  })
  @ApiBody({ type: UpdateTenantInput })
  async updateTenant(
    @Request() req: any,
    @Body() input: UpdateTenantInput,
  ): Promise<Tenant> {
    const tenantId = req.params.id;
    return this.tenantService.updateTenant(tenantId, input, req.user.id);
  }

  @Post('invite')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.CREATED)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Invite user to tenant',
    description: 'Send invitation to user to join tenant'
  })
  @ApiResponse({ 
    status: 201, 
    description: 'Invitation sent successfully',
    type: TenantInvitation 
  })
  @ApiBody({ type: TenantInviteInput })
  async inviteUser(
    @Body() input: TenantInviteInput,
    @Request() req: any,
  ): Promise<TenantInvitation> {
    return this.tenantService.inviteUser(input, req.user.id);
  }

  @Get('my/tenants')
  @UseGuards(AuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Get user tenants',
    description: 'Get all tenants user belongs to'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'User tenants retrieved',
    type: [TenantUser] 
  })
  async getUserTenants(@Request() req: any): Promise<TenantUser[]> {
    return this.tenantService.getUserTenants(req.user.id);
  }

  @Get(':id/users')
  @UseGuards(AuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Get tenant users',
    description: 'Get all users in tenant'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Tenant users retrieved',
    type: [TenantUser] 
  })
  async getTenantUsers(@Request() req: any): Promise<TenantUser[]> {
    const tenantId = req.params.id;
    return this.tenantService.getTenantUsers(tenantId);
  }

  @Post('switch')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Switch tenant context',
    description: 'Switch user active tenant context'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Tenant switched successfully',
    type: TenantSwitchResponse 
  })
  @ApiBody({ type: TenantSwitchInput })
  async switchTenant(
    @Body() input: TenantSwitchInput,
    @Request() req: any,
  ): Promise<TenantSwitchResponse> {
    const membership = await this.tenantService.switchTenant(req.user.id, input.tenantId);
    return {
      success: true,
      membership,
      message: 'Successfully switched tenant context',
    };
  }
}
