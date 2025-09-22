import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { PrismaTenantService } from './prisma-tenant.service';
import { CreateTenantInput, UpdateTenantInput, TenantInviteInput } from './dto/tenant.input';
import { Tenant, TenantUser, TenantInvitation } from './dto/tenant.types';

@Injectable()
export class TenantService {
  constructor(private readonly prismaTenant: PrismaTenantService) {}

  async createTenant(input: CreateTenantInput, ownerId: number): Promise<Tenant> {
    // Check if slug is available
    const existingTenant = await this.prismaTenant.findTenantBySlug(input.slug);
    if (existingTenant) {
      throw new ConflictException('Tenant slug already exists');
    }

    return this.prismaTenant.createTenant({
      ...input,
      ownerId,
    });
  }

  async getTenant(tenantId: string): Promise<Tenant> {
    const tenant = await this.prismaTenant.findTenantById(tenantId);
    if (!tenant) {
      throw new NotFoundException('Tenant not found');
    }
    return tenant;
  }

  async getTenantBySlug(slug: string): Promise<Tenant> {
    const tenant = await this.prismaTenant.findTenantBySlug(slug);
    if (!tenant) {
      throw new NotFoundException('Tenant not found');
    }
    return tenant;
  }

  async updateTenant(tenantId: string, input: UpdateTenantInput, userId: number): Promise<Tenant> {
    // Verify user has permission to update tenant
    await this.verifyTenantAccess(tenantId, userId, ['OWNER', 'ADMIN']);
    
    return this.prismaTenant.updateTenant(tenantId, input);
  }

  async inviteUser(input: TenantInviteInput, inviterId: number): Promise<TenantInvitation> {
    // Verify inviter has permission
    await this.verifyTenantAccess(input.tenantId, inviterId, ['OWNER', 'ADMIN']);
    
    return this.prismaTenant.createInvitation({
      ...input,
      invitedBy: inviterId,
    });
  }

  async getUserTenants(userId: number): Promise<TenantUser[]> {
    return this.prismaTenant.getUserTenants(userId);
  }

  async getTenantUsers(tenantId: string): Promise<TenantUser[]> {
    return this.prismaTenant.getTenantUsers(tenantId);
  }

  async checkUserAccess(tenantId: string, userId: number): Promise<TenantUser | null> {
    return this.prismaTenant.getUserTenantMembership(tenantId, userId);
  }

  async verifyTenantAccess(
    tenantId: string, 
    userId: number, 
    requiredRoles: string[] = []
  ): Promise<TenantUser> {
    const membership = await this.checkUserAccess(tenantId, userId);
    
    if (!membership) {
      throw new NotFoundException('User is not a member of this tenant');
    }

    if (requiredRoles.length > 0 && typeof membership.role === 'string' && !requiredRoles.includes(membership.role)) {
      throw new ConflictException('Insufficient permissions');
    }

    return membership;
  }

  async switchTenant(userId: number, tenantId: string): Promise<TenantUser> {
    const membership = await this.verifyTenantAccess(tenantId, userId);
    
    // Update user's active tenant context
    // This could be stored in user sessions or preferences
    
    return membership;
  }
}
