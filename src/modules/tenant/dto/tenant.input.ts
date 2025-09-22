import { InputType, Field } from '@nestjs/graphql';
import { IsString, IsOptional, IsEmail, IsEnum, IsBoolean, MaxLength, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

@InputType()
export class CreateTenantInput {
  @Field()
  @ApiProperty({ description: 'Tenant name', example: 'Acme Shooting Club' })
  @IsString()
  @MaxLength(200)
  name: string;

  @Field()
  @ApiProperty({ description: 'Unique tenant slug', example: 'acme-shooting-club' })
  @IsString()
  @MinLength(3)
  @MaxLength(100)
  slug: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Tenant description', required: false })
  @IsOptional()
  @IsString()
  description?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Logo URL', required: false })
  @IsOptional()
  @IsString()
  logo?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Website URL', required: false })
  @IsOptional()
  @IsString()
  website?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Contact email', required: false })
  @IsOptional()
  @IsEmail()
  email?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Contact phone', required: false })
  @IsOptional()
  @IsString()
  phone?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Address', required: false })
  @IsOptional()
  @IsString()
  address?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Timezone', required: false, default: 'UTC' })
  @IsOptional()
  @IsString()
  timezone?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Currency code', required: false, default: 'USD' })
  @IsOptional()
  @IsString()
  currency?: string;
}

@InputType()
export class UpdateTenantInput {
  @Field({ nullable: true })
  @ApiProperty({ description: 'Tenant name', required: false })
  @IsOptional()
  @IsString()
  @MaxLength(200)
  name?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Tenant description', required: false })
  @IsOptional()
  @IsString()
  description?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Logo URL', required: false })
  @IsOptional()
  @IsString()
  logo?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Website URL', required: false })
  @IsOptional()
  @IsString()
  website?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Contact email', required: false })
  @IsOptional()
  @IsEmail()
  email?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Contact phone', required: false })
  @IsOptional()
  @IsString()
  phone?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Address', required: false })
  @IsOptional()
  @IsString()
  address?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Timezone', required: false })
  @IsOptional()
  @IsString()
  timezone?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Currency code', required: false })
  @IsOptional()
  @IsString()
  currency?: string;

  @Field({ nullable: true })
  @ApiProperty({ description: 'Tenant active status', required: false })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}

@InputType()
export class TenantInviteInput {
  @Field()
  @ApiProperty({ description: 'Tenant ID' })
  @IsString()
  tenantId: string;

  @Field()
  @ApiProperty({ description: 'Email address to invite' })
  @IsEmail()
  email: string;

  @Field({ nullable: true })
  @ApiProperty({ 
    description: 'Role to assign', 
    enum: ['OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER'],
    default: 'MEMBER'
  })
  @IsOptional()
  @IsEnum(['OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER'])
  role?: string;
}

@InputType()
export class TenantSwitchInput {
  @Field()
  @ApiProperty({ description: 'Tenant ID to switch to' })
  @IsString()
  tenantId: string;
}
