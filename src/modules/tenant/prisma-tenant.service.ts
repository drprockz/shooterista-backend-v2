import { Injectable } from '@nestjs/common';
import { PrismaClient as TenantPrismaClient } from '../../../node_modules/.prisma/tenant';
import { CreateTenantInput, UpdateTenantInput, TenantInviteInput } from './dto/tenant.input';
import { Tenant, TenantUser, TenantInvitation } from './dto/tenant.types';

@Injectable()
export class PrismaTenantService {
  private prisma: TenantPrismaClient;

  constructor() {
    this.prisma = new TenantPrismaClient();
  }

  async createTenant(data: CreateTenantInput & { ownerId: number }): Promise<Tenant> {
    return this.prisma.tenant.create({
      data: {
        name: data.name,
        slug: data.slug,
        description: data.description,
        logo: data.logo,
        website: data.website,
        email: data.email,
        phone: data.phone,
        address: data.address,
        timezone: data.timezone || 'UTC',
        currency: data.currency || 'USD',
        userMemberships: {
          create: {
            userId: data.ownerId,
            role: 'OWNER',
            status: 'ACTIVE',
          },
        },
      },
      include: {
        userMemberships: true,
        roles: true,
        subscriptions: true,
        invitations: true,
      },
    }) as any;
  }

  async findTenantById(id: string): Promise<Tenant | null> {
    return this.prisma.tenant.findUnique({
      where: { id },
      include: {
        userMemberships: true,
        roles: true,
        subscriptions: true,
        invitations: true,
      },
    }) as any;
  }

  async findTenantBySlug(slug: string): Promise<Tenant | null> {
    return this.prisma.tenant.findUnique({
      where: { slug },
      include: {
        userMemberships: true,
        roles: true,
        subscriptions: true,
        invitations: true,
      },
    }) as any;
  }

  async updateTenant(id: string, data: UpdateTenantInput): Promise<Tenant> {
    return this.prisma.tenant.update({
      where: { id },
      data: {
        name: data.name,
        description: data.description,
        logo: data.logo,
        website: data.website,
        email: data.email,
        phone: data.phone,
        address: data.address,
        timezone: data.timezone,
        currency: data.currency,
        isActive: data.isActive,
      },
      include: {
        userMemberships: true,
        roles: true,
        subscriptions: true,
        invitations: true,
      },
    }) as any;
  }

  async createInvitation(data: TenantInviteInput & { invitedBy: number }): Promise<TenantInvitation> {
    return this.prisma.tenantInvitation.create({
      data: {
        tenantId: data.tenantId,
        email: data.email,
        role: (data.role as any) || 'MEMBER',
        invitedBy: data.invitedBy,
        token: this.generateToken(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      },
      include: {
        tenant: true,
      },
    }) as any;
  }

  async getUserTenants(userId: number): Promise<TenantUser[]> {
    const result = await this.prisma.tenantUser.findMany({
      where: { userId },
      include: {
        tenant: true,
      },
    });
    return result.map(item => ({
      ...item,
      userId: item.userId.toString(),
    })) as any;
  }

  async getTenantUsers(tenantId: string): Promise<TenantUser[]> {
    const result = await this.prisma.tenantUser.findMany({
      where: { tenantId },
      include: {
        tenant: true,
      },
    });
    return result.map(item => ({
      ...item,
      userId: item.userId.toString(),
    })) as any;
  }

  async getUserTenantMembership(tenantId: string, userId: number): Promise<TenantUser | null> {
    const result = await this.prisma.tenantUser.findUnique({
      where: {
        tenantId_userId: {
          tenantId,
          userId,
        },
      },
      include: {
        tenant: true,
      },
    });
    if (!result) return null;
    return {
      ...result,
      userId: result.userId.toString(),
    } as any;
  }

  private generateToken(): string {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
  }

  async onModuleDestroy() {
    await this.prisma.$disconnect();
  }
}
