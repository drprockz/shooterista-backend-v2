import { ObjectType, Field, ID, registerEnumType } from '@nestjs/graphql';
import { ApiProperty } from '@nestjs/swagger';

export enum PlanType {
  FREE = 'FREE',
  BASIC = 'BASIC',
  PREMIUM = 'PREMIUM',
  ENTERPRISE = 'ENTERPRISE',
  CUSTOM = 'CUSTOM'
}

export enum TenantUserRole {
  OWNER = 'OWNER',
  ADMIN = 'ADMIN',
  MANAGER = 'MANAGER',
  MEMBER = 'MEMBER',
  VIEWER = 'VIEWER'
}

export enum MembershipStatus {
  ACTIVE = 'ACTIVE',
  INACTIVE = 'INACTIVE',
  SUSPENDED = 'SUSPENDED',
  PENDING = 'PENDING'
}

export enum InvitationStatus {
  PENDING = 'PENDING',
  ACCEPTED = 'ACCEPTED',
  EXPIRED = 'EXPIRED',
  CANCELLED = 'CANCELLED'
}

registerEnumType(PlanType, { name: 'PlanType' });
registerEnumType(TenantUserRole, { name: 'TenantUserRole' });
registerEnumType(MembershipStatus, { name: 'MembershipStatus' });
registerEnumType(InvitationStatus, { name: 'InvitationStatus' });

@ObjectType()
export class Tenant {
  @Field(() => ID)
  @ApiProperty({ description: 'Tenant ID' })
  id: string;

  @Field()
  @ApiProperty({ description: 'Tenant name' })
  name: string;

  @Field()
  @ApiProperty({ description: 'Unique tenant slug' })
  slug: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Tenant description', required: false })
  description?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Logo URL', required: false })
  logo?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Website URL', required: false })
  website?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Contact email', required: false })
  email?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Contact phone', required: false })
  phone?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Address', required: false })
  address?: string;

  @Field()
  @ApiProperty({ description: 'Timezone' })
  timezone: string;

  @Field()
  @ApiProperty({ description: 'Currency code' })
  currency: string;

  @Field(() => PlanType)
  @ApiProperty({ description: 'Subscription plan type', enum: PlanType })
  planType: PlanType;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Plan expiry date', required: false })
  planExpiry?: Date;

  @Field()
  @ApiProperty({ description: 'Tenant active status' })
  isActive: boolean;

  @Field()
  @ApiProperty({ description: 'Creation date' })
  createdAt: Date;

  @Field()
  @ApiProperty({ description: 'Last update date' })
  updatedAt: Date;

  @Field(() => [String], { nullable: true })
  @ApiProperty({ description: 'Tenant users', type: [String], required: false })
  users?: string[];
}

@ObjectType()
export class TenantUser {
  @Field(() => ID)
  @ApiProperty({ description: 'Membership ID' })
  id: string;

  @Field(() => ID)
  @ApiProperty({ description: 'Tenant ID' })
  tenantId: string;

  @Field(() => ID)
  @ApiProperty({ description: 'User ID' })
  userId: string;

  @Field(() => TenantUserRole)
  @ApiProperty({ description: 'User role in tenant', enum: TenantUserRole })
  role: TenantUserRole;

  @Field(() => MembershipStatus)
  @ApiProperty({ description: 'Membership status', enum: MembershipStatus })
  status: MembershipStatus;

  @Field()
  @ApiProperty({ description: 'Join date' })
  joinedAt: Date;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Leave date', required: false })
  leftAt?: Date;

  @Field()
  @ApiProperty({ description: 'Creation date' })
  createdAt: Date;

  @Field()
  @ApiProperty({ description: 'Last update date' })
  updatedAt: Date;

  @Field(() => Tenant, { nullable: true })
  @ApiProperty({ description: 'Tenant information', type: Tenant, required: false })
  tenant?: Tenant;
}

@ObjectType()
export class TenantInvitation {
  @Field(() => ID)
  @ApiProperty({ description: 'Invitation ID' })
  id: string;

  @Field(() => ID)
  @ApiProperty({ description: 'Tenant ID' })
  tenantId: string;

  @Field()
  @ApiProperty({ description: 'Invited email address' })
  email: string;

  @Field(() => TenantUserRole)
  @ApiProperty({ description: 'Invited role', enum: TenantUserRole })
  role: TenantUserRole;

  @Field(() => ID)
  @ApiProperty({ description: 'Inviter user ID' })
  invitedBy: string;

  @Field()
  @ApiProperty({ description: 'Invitation token' })
  token: string;

  @Field(() => InvitationStatus)
  @ApiProperty({ description: 'Invitation status', enum: InvitationStatus })
  status: InvitationStatus;

  @Field()
  @ApiProperty({ description: 'Expiry date' })
  expiresAt: Date;

  @Field()
  @ApiProperty({ description: 'Creation date' })
  createdAt: Date;

  @Field(() => Tenant, { nullable: true })
  @ApiProperty({ description: 'Tenant information', type: Tenant, required: false })
  tenant?: Tenant;
}

@ObjectType()
export class TenantSwitchResponse {
  @Field()
  @ApiProperty({ description: 'Switch success status' })
  success: boolean;

  @Field(() => TenantUser)
  @ApiProperty({ description: 'New tenant membership', type: TenantUser })
  membership: TenantUser;

  @Field()
  @ApiProperty({ description: 'Message' })
  message: string;
}
