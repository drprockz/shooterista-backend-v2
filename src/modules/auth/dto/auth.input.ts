import { Field, InputType, Int } from '@nestjs/graphql';
import { IsEmail, IsString, MinLength, MaxLength, IsOptional, IsBoolean, IsEnum, IsUUID, IsInt, Min, Max, IsIn } from 'class-validator';
import { MfaType, UserStatus } from './auth.types';
import { 
  IsStrongPassword, 
  IsEmailFormat, 
  IsUniqueEmailPerTenant, 
  IsValidTenantId, 
  IsValidUserType, 
  IsValidOTP, 
  IsValidToken, 
  IsValidDeviceInfo 
} from '../validators/password.validator';

@InputType()
export class CreateUserInput {
  @Field()
  @IsEmailFormat({ message: 'Please provide a valid email address format' })
  @IsUniqueEmailPerTenant({ message: 'Email address is already registered for this tenant' })
  email: string;

  @Field()
  @IsStrongPassword({ message: 'Password does not meet security requirements' })
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
  @IsValidTenantId({ message: 'Tenant ID must be a valid CUID format' })
  tenantId?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsValidUserType({ message: 'User type must be one of: superadmin, admin, athlete' })
  userType?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  acceptTerms?: boolean;

  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  acceptPrivacy?: boolean;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(10)
  termsVersion?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(10)
  privacyVersion?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsValidDeviceInfo({ message: 'Device information contains invalid content' })
  deviceInfo?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(45)
  ipAddress?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  userAgent?: string;
}

@InputType()
export class LoginInput {
  @Field()
  @IsEmailFormat({ message: 'Please provide a valid email address format' })
  email: string;

  @Field()
  @IsString()
  @MinLength(1, { message: 'Password is required' })
  password: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsValidTenantId({ message: 'Tenant ID must be a valid CUID format' })
  tenantId?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsValidDeviceInfo({ message: 'Device information contains invalid content' })
  deviceInfo?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(45)
  ipAddress?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  userAgent?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  rememberMe?: boolean;
}

@InputType()
export class AdminLoginInput {
  @Field()
  @IsEmailFormat({ message: 'Please provide a valid email address format' })
  email: string;

  @Field()
  @IsString()
  @MinLength(1, { message: 'Password is required' })
  password: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsValidTenantId({ message: 'Tenant ID must be a valid CUID format' })
  tenantId?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsValidDeviceInfo({ message: 'Device information contains invalid content' })
  deviceInfo?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(45)
  ipAddress?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(500)
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
  @IsValidOTP({ message: 'OTP must be a 6-digit numeric code' })
  token: string;

  @Field(() => MfaType)
  @IsEnum(MfaType)
  type: MfaType;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(20)
  backupCode?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  sessionId?: string;
}

@InputType()
export class PasswordResetRequestInput {
  @Field()
  @IsEmailFormat({ message: 'Please provide a valid email address format' })
  email: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsValidTenantId({ message: 'Tenant ID must be a valid CUID format' })
  tenantId?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(45)
  ipAddress?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  userAgent?: string;
}

@InputType()
export class PasswordResetInput {
  @Field()
  @IsValidToken({ message: 'Token must be a valid 64-character hex string' })
  token: string;

  @Field()
  @IsStrongPassword({ message: 'Password does not meet security requirements' })
  newPassword: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(45)
  ipAddress?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  userAgent?: string;
}

@InputType()
export class ChangePasswordInput {
  @Field()
  @IsString()
  @MinLength(1, { message: 'Current password is required' })
  currentPassword: string;

  @Field()
  @IsStrongPassword({ message: 'New password does not meet security requirements' })
  newPassword: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(45)
  ipAddress?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  userAgent?: string;
}

@InputType()
export class EmailVerificationInput {
  @Field()
  @IsValidToken({ message: 'Token must be a valid 64-character hex string' })
  token: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(45)
  ipAddress?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  userAgent?: string;
}

@InputType()
export class ResendEmailVerificationInput {
  @Field()
  @IsEmailFormat({ message: 'Please provide a valid email address format' })
  email: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsValidTenantId({ message: 'Tenant ID must be a valid CUID format' })
  tenantId?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(45)
  ipAddress?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  userAgent?: string;
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

// New DTOs for enhanced authentication features
@InputType()
export class OTPVerificationInput {
  @Field()
  @IsValidOTP({ message: 'OTP must be a 6-digit numeric code' })
  otp: string;

  @Field()
  @IsString()
  @MaxLength(100)
  sessionId: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(45)
  ipAddress?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  userAgent?: string;
}

@InputType()
export class ProfileCompletionInput {
  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(50)
  firstName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(50)
  lastName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(20)
  phone?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(3)
  country?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  state?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  city?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(50)
  timezone?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  title?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(200)
  company?: string;
}

@InputType()
export class ConsentInput {
  @Field()
  @IsBoolean()
  acceptTerms: boolean;

  @Field()
  @IsBoolean()
  acceptPrivacy: boolean;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(10)
  termsVersion?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(10)
  privacyVersion?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(45)
  ipAddress?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  userAgent?: string;
}

@InputType()
export class InviteUserInput {
  @Field()
  @IsEmailFormat({ message: 'Please provide a valid email address format' })
  email: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(50)
  firstName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(50)
  lastName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  role?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  message?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(45)
  ipAddress?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  userAgent?: string;
}

@InputType()
export class AcceptInviteInput {
  @Field()
  @IsValidToken({ message: 'Invite token must be a valid token' })
  token: string;

  @Field()
  @IsStrongPassword({ message: 'Password does not meet security requirements' })
  password: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(50)
  firstName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(50)
  lastName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsValidDeviceInfo({ message: 'Device information contains invalid content' })
  deviceInfo?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(45)
  ipAddress?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  userAgent?: string;
}
