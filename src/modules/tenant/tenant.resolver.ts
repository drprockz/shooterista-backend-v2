import { Resolver, Query, Mutation, Args, Context } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
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

@Resolver()
export class TenantResolver {
  constructor(private readonly tenantService: TenantService) {}

  @Query(() => String)
  async tenantHealth(): Promise<string> {
    return 'Tenant service is healthy';
  }

  @Mutation(() => Tenant)
  @UseGuards(AuthGuard)
  async createTenant(
    @Args('input') input: CreateTenantInput,
    @Context('req') req: any,
  ): Promise<Tenant> {
    return this.tenantService.createTenant(input, req.user.id);
  }

  @Query(() => Tenant)
  @UseGuards(AuthGuard)
  async getTenant(
    @Args('id') id: string,
    @Context('req') req: any,
  ): Promise<Tenant> {
    return this.tenantService.getTenant(id);
  }

  @Query(() => Tenant)
  @UseGuards(AuthGuard)
  async getTenantBySlug(
    @Args('slug') slug: string,
    @Context('req') req: any,
  ): Promise<Tenant> {
    return this.tenantService.getTenantBySlug(slug);
  }

  @Mutation(() => Tenant)
  @UseGuards(AuthGuard)
  async updateTenant(
    @Args('id') id: string,
    @Args('input') input: UpdateTenantInput,
    @Context('req') req: any,
  ): Promise<Tenant> {
    return this.tenantService.updateTenant(id, input, req.user.id);
  }

  @Mutation(() => TenantInvitation)
  @UseGuards(AuthGuard)
  async inviteUser(
    @Args('input') input: TenantInviteInput,
    @Context('req') req: any,
  ): Promise<TenantInvitation> {
    return this.tenantService.inviteUser(input, req.user.id);
  }

  @Query(() => [TenantUser])
  @UseGuards(AuthGuard)
  async getUserTenants(@Context('req') req: any): Promise<TenantUser[]> {
    return this.tenantService.getUserTenants(req.user.id);
  }

  @Query(() => [TenantUser])
  @UseGuards(AuthGuard)
  async getTenantUsers(
    @Args('tenantId') tenantId: string,
    @Context('req') req: any,
  ): Promise<TenantUser[]> {
    return this.tenantService.getTenantUsers(tenantId);
  }

  @Mutation(() => TenantSwitchResponse)
  @UseGuards(AuthGuard)
  async switchTenant(
    @Args('input') input: TenantSwitchInput,
    @Context('req') req: any,
  ): Promise<TenantSwitchResponse> {
    const membership = await this.tenantService.switchTenant(req.user.id, input.tenantId);
    return {
      success: true,
      membership,
      message: 'Successfully switched tenant context',
    };
  }
}
