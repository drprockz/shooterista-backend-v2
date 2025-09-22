import { Field, InputType, Int } from '@nestjs/graphql';
import { IsEmail, IsString, MinLength, MaxLength, IsOptional, IsBoolean, IsEnum, IsUUID, IsInt, Min, Max } from 'class-validator';
import { MfaType, UserStatus } from './auth.types';

@InputType()
export class CreateUserInput {
  @Field()
  @IsEmail({}, { message: 'Please provide a valid email address' })
  email: string;

  @Field()
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(128, { message: 'Password must not exceed 128 characters' })
  password: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(50, { message: 'First name must not exceed 50 characters' })
  firstName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(50, { message: 'Last name must not exceed 50 characters' })
  lastName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  tenantId?: string;
}

@InputType()
export class LoginInput {
  @Field()
  @IsEmail({}, { message: 'Please provide a valid email address' })
  email: string;

  @Field()
  @IsString()
  password: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  tenantId?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  deviceInfo?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  ipAddress?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  userAgent?: string;
}

@InputType()
export class AdminLoginInput {
  @Field()
  @IsEmail({}, { message: 'Please provide a valid email address' })
  email: string;

  @Field()
  @IsString()
  password: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  tenantId?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  deviceInfo?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  ipAddress?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  userAgent?: string;
}

@InputType()
export class RefreshTokenInput {
  @Field()
  @IsString()
  refreshToken: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  deviceInfo?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  ipAddress?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  userAgent?: string;
}

@InputType()
export class LogoutInput {
  @Field()
  @IsString()
  refreshToken: string;
}

@InputType()
export class MfaVerificationInput {
  @Field()
  @IsString()
  token: string;

  @Field(() => MfaType)
  @IsEnum(MfaType)
  type: MfaType;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  backupCode?: string;
}

@InputType()
export class PasswordResetRequestInput {
  @Field()
  @IsEmail({}, { message: 'Please provide a valid email address' })
  email: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  tenantId?: string;
}

@InputType()
export class PasswordResetInput {
  @Field()
  @IsString()
  token: string;

  @Field()
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(128, { message: 'Password must not exceed 128 characters' })
  newPassword: string;
}

@InputType()
export class ChangePasswordInput {
  @Field()
  @IsString()
  currentPassword: string;

  @Field()
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(128, { message: 'Password must not exceed 128 characters' })
  newPassword: string;
}

@InputType()
export class EmailVerificationInput {
  @Field()
  @IsString()
  token: string;
}

@InputType()
export class ResendEmailVerificationInput {
  @Field()
  @IsEmail({}, { message: 'Please provide a valid email address' })
  email: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  tenantId?: string;
}

@InputType()
export class MfaSetupInput {
  @Field(() => MfaType)
  @IsEnum(MfaType)
  type: MfaType;
}

@InputType()
export class MfaDisableInput {
  @Field()
  @IsString()
  password: string;

  @Field()
  @IsString()
  token: string;

  @Field(() => MfaType)
  @IsEnum(MfaType)
  type: MfaType;
}

@InputType()
export class SessionRevokeInput {
  @Field()
  @IsString()
  sessionId: string;
}

@InputType()
export class AuditLogsInput {
  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  userId?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  action?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  tenantId?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsInt()
  @Min(1)
  limit?: number = 50;

  @Field({ nullable: true })
  @IsOptional()
  @IsInt()
  @Min(0)
  offset?: number = 0;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  startDate?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  endDate?: string;
}

@InputType()
export class PermissionCheckInput {
  @Field()
  @IsString()
  resource: string;

  @Field()
  @IsString()
  action: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  tenantId?: string;
}

@InputType()
export class RoleAssignmentInput {
  @Field()
  @IsString()
  userId: string;

  @Field()
  @IsString()
  roleId: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  tenantId?: string;
}

@InputType()
export class RoleRemovalInput {
  @Field()
  @IsString()
  userId: string;

  @Field()
  @IsString()
  roleId: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  tenantId?: string;
}

@InputType()
export class UserUpdateInput {
  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(50, { message: 'First name must not exceed 50 characters' })
  firstName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(50, { message: 'Last name must not exceed 50 characters' })
  lastName?: string;

  @Field(() => UserStatus, { nullable: true })
  @IsOptional()
  @IsEnum(UserStatus)
  status?: UserStatus;
}

@InputType()
export class SessionListInput {
  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  activeOnly?: boolean = false;

  @Field({ nullable: true })
  @IsOptional()
  @IsInt()
  @Min(1)
  limit?: number = 20;

  @Field({ nullable: true })
  @IsOptional()
  @IsInt()
  @Min(0)
  offset?: number = 0;
}
