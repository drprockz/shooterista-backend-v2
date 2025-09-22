import { Resolver, Query, Mutation, Args, Context } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { RbacService } from './services/rbac.service';
import { AuthGuard } from '@/common/guards/auth.guard';
import { PermissionsGuard } from '@/common/guards/permissions.guard';
import { RequirePermissions } from '@/common/decorators/permissions.decorator';
import { Role, Permission } from './dto/auth.types';

@Resolver()
export class RbacResolver {
  constructor(
    private readonly rbacService: RbacService,
  ) {}

  @Query(() => [Role])
  @UseGuards(AuthGuard, PermissionsGuard)
  @RequirePermissions({ resource: 'admin', action: 'manage_roles' })
  async getRoles(@Context() context: any): Promise<Role[]> {
    const tenantId = context.req?.headers['x-tenant-id'] || null;
    return this.rbacService.getRoles(tenantId);
  }

  @Query(() => [Permission])
  @UseGuards(AuthGuard, PermissionsGuard)
  @RequirePermissions({ resource: 'admin', action: 'manage_roles' })
  async getPermissions(): Promise<Permission[]> {
    return this.rbacService.getPermissions();
  }

  @Query(() => [Permission])
  @UseGuards(AuthGuard)
  async getMyPermissions(@Context() context: any): Promise<Permission[]> {
    const user = context.req?.user;
    if (!user) {
      throw new Error('User not found in context');
    }

    const tenantId = context.req?.headers['x-tenant-id'] || null;
    return this.rbacService.getUserEffectivePermissions(parseInt(user.id), tenantId);
  }

  @Query(() => Boolean)
  @UseGuards(AuthGuard)
  async hasPermission(
    @Args('resource') resource: string,
    @Args('action') action: string,
    @Context() context: any,
  ): Promise<boolean> {
    const user = context.req?.user;
    if (!user) {
      return false;
    }

    const tenantId = context.req?.headers['x-tenant-id'] || null;
    return this.rbacService.hasPermission(parseInt(user.id), resource, action, tenantId);
  }

  @Mutation(() => Role)
  @UseGuards(AuthGuard, PermissionsGuard)
  @RequirePermissions({ resource: 'admin', action: 'manage_roles' })
  async createRoleBundle(
    @Args('name') name: string,
    @Args('description') description: string,
    @Args('permissions', { type: () => [String] }) permissions: string[],
    @Context() context: any,
    @Args('tenantId', { nullable: true }) tenantId?: string,
  ): Promise<Role> {
    return this.rbacService.createRoleBundle({
      name,
      description,
      permissions,
      tenantId: tenantId || context.req?.headers['x-tenant-id'] || null,
    });
  }

  @Mutation(() => Role)
  @UseGuards(AuthGuard, PermissionsGuard)
  @RequirePermissions({ resource: 'admin', action: 'manage_roles' })
  async updateRoleBundle(
    @Args('roleId') roleId: string,
    @Args('name', { nullable: true }) name?: string,
    @Args('description', { nullable: true }) description?: string,
    @Args('permissions', { type: () => [String], nullable: true }) permissions?: string[],
  ): Promise<Role> {
    return this.rbacService.updateRoleBundle(parseInt(roleId), {
      name,
      description,
      permissions,
    });
  }

  @Query(() => String)
  @UseGuards(AuthGuard)
  async initializeDefaultRoles(): Promise<string> {
    await this.rbacService.initializeDefaultRoles();
    return 'Default roles and permissions initialized successfully';
  }
}
