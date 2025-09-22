import { Field, ObjectType, Int, registerEnumType } from '@nestjs/graphql';

// Enums
export enum UserStatus {
  ACTIVE = 'ACTIVE',
  INACTIVE = 'INACTIVE',
  SUSPENDED = 'SUSPENDED',
  PENDING_VERIFICATION = 'PENDING_VERIFICATION',
}

export enum MfaType {
  EMAIL = 'EMAIL',
  TOTP = 'TOTP',
}

export enum SessionStatus {
  ACTIVE = 'ACTIVE',
  EXPIRED = 'EXPIRED',
  REVOKED = 'REVOKED',
}

export enum AuditAction {
  LOGIN = 'LOGIN',
  LOGOUT = 'LOGOUT',
  LOGIN_FAILED = 'LOGIN_FAILED',
  PASSWORD_CHANGE = 'PASSWORD_CHANGE',
  PASSWORD_RESET_REQUEST = 'PASSWORD_RESET_REQUEST',
  PASSWORD_RESET_COMPLETE = 'PASSWORD_RESET_COMPLETE',
  EMAIL_VERIFICATION_REQUEST = 'EMAIL_VERIFICATION_REQUEST',
  EMAIL_VERIFICATION_COMPLETE = 'EMAIL_VERIFICATION_COMPLETE',
  MFA_ENABLED = 'MFA_ENABLED',
  MFA_DISABLED = 'MFA_DISABLED',
  MFA_VERIFICATION = 'MFA_VERIFICATION',
  MFA_VERIFICATION_FAILED = 'MFA_VERIFICATION_FAILED',
  SESSION_CREATED = 'SESSION_CREATED',
  SESSION_REVOKED = 'SESSION_REVOKED',
  ROLE_ASSIGNED = 'ROLE_ASSIGNED',
  ROLE_REMOVED = 'ROLE_REMOVED',
  PERMISSION_GRANTED = 'PERMISSION_GRANTED',
  PERMISSION_REVOKED = 'PERMISSION_REVOKED',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED',
}

export enum TokenType {
  ACCESS = 'ACCESS',
  REFRESH = 'REFRESH',
  PASSWORD_RESET = 'PASSWORD_RESET',
  EMAIL_VERIFICATION = 'EMAIL_VERIFICATION',
}

// Register enums with GraphQL
registerEnumType(UserStatus, { name: 'UserStatus' });
registerEnumType(MfaType, { name: 'MfaType' });
registerEnumType(SessionStatus, { name: 'SessionStatus' });
registerEnumType(AuditAction, { name: 'AuditAction' });
registerEnumType(TokenType, { name: 'TokenType' });

// Core Types
@ObjectType()
export class User {
  @Field()
  id: string;

  @Field()
  email: string;

  @Field({ nullable: true })
  firstName?: string;

  @Field({ nullable: true })
  lastName?: string;

  @Field()
  isEmailVerified: boolean;

  @Field()
  isMfaEnabled: boolean;

  @Field({ nullable: true })
  lastLoginAt?: Date;

  @Field({ nullable: true })
  passwordChangedAt?: Date;

  @Field(() => UserStatus)
  status: UserStatus;

  @Field({ nullable: true })
  tenantId?: string;

  @Field()
  createdAt: Date;

  @Field()
  updatedAt: Date;

  @Field(() => [Role], { nullable: true })
  roles?: Role[];

  @Field(() => [Permission], { nullable: true })
  permissions?: Permission[];
}

@ObjectType()
export class Role {
  @Field()
  id: string;

  @Field()
  name: string;

  @Field({ nullable: true })
  description?: string;

  @Field()
  isActive: boolean;

  @Field({ nullable: true })
  tenantId?: string;

  @Field()
  createdAt: Date;

  @Field()
  updatedAt: Date;

  @Field(() => [Permission], { nullable: true })
  permissions?: Permission[];
}

@ObjectType()
export class Permission {
  @Field()
  id: string;

  @Field()
  name: string;

  @Field({ nullable: true })
  description?: string;

  @Field()
  resource: string;

  @Field()
  action: string;

  @Field()
  isActive: boolean;

  @Field()
  createdAt: Date;

  @Field()
  updatedAt: Date;
}

@ObjectType()
export class Session {
  @Field()
  id: string;

  @Field()
  userId: string;

  @Field({ nullable: true })
  deviceInfo?: string;

  @Field({ nullable: true })
  ipAddress?: string;

  @Field({ nullable: true })
  userAgent?: string;

  @Field()
  isActive: boolean;

  @Field()
  lastUsedAt: Date;

  @Field()
  createdAt: Date;

  @Field()
  expiresAt: Date;

  @Field(() => SessionStatus)
  status: SessionStatus;
}

@ObjectType()
export class AuditLog {
  @Field()
  id: string;

  @Field({ nullable: true })
  userId?: string;

  @Field(() => AuditAction)
  action: AuditAction;

  @Field({ nullable: true })
  resource?: string;

  @Field({ nullable: true })
  resourceId?: string;

  @Field({ nullable: true })
  ipAddress?: string;

  @Field({ nullable: true })
  userAgent?: string;

  @Field({ nullable: true })
  metadata?: string; // JSON string

  @Field()
  success: boolean;

  @Field({ nullable: true })
  tenantId?: string;

  @Field()
  createdAt: Date;
}

// Auth Response Types
@ObjectType()
export class AuthPayload {
  @Field(() => User)
  user: User;

  @Field()
  accessToken: string;

  @Field()
  refreshToken: string;

  @Field(() => Int)
  expiresIn: number;

  @Field({ nullable: true })
  mfaRequired?: boolean;

  @Field({ nullable: true })
  mfaType?: MfaType;
}

@ObjectType()
export class TokenRefreshPayload {
  @Field()
  accessToken: string;

  @Field()
  refreshToken: string;

  @Field(() => Int)
  expiresIn: number;
}

@ObjectType()
export class MfaSetup {
  @Field()
  secret: string;

  @Field()
  qrCodeUrl: string;

  @Field(() => [String])
  backupCodes: string[];
}

@ObjectType()
export class PasswordResetResponse {
  @Field()
  success: boolean;

  @Field()
  message: string;

  @Field({ nullable: true })
  expiresAt?: Date;
}

@ObjectType()
export class EmailVerificationResponse {
  @Field()
  success: boolean;

  @Field()
  message: string;

  @Field({ nullable: true })
  expiresAt?: Date;
}

@ObjectType()
export class SessionListResponse {
  @Field(() => [Session])
  sessions: Session[];

  @Field(() => Int)
  totalCount: number;

  @Field(() => Int)
  activeCount: number;
}

@ObjectType()
export class AuditLogResponse {
  @Field(() => [AuditLog])
  logs: AuditLog[];

  @Field(() => Int)
  totalCount: number;
}

@ObjectType()
export class PermissionCheckResponse {
  @Field()
  hasPermission: boolean;

  @Field(() => [Permission])
  userPermissions: Permission[];

  @Field(() => [Role])
  userRoles: Role[];
}

// Error Types
@ObjectType()
export class AuthError {
  @Field()
  message: string;

  @Field()
  code: string;

  @Field({ nullable: true })
  field?: string;
}

@ObjectType()
export class ValidationError {
  @Field()
  message: string;

  @Field()
  field: string;

  @Field()
  value: string;
}

// Token Payload Interface
export interface TokenPayload {
  sub: string;
  email: string;
  iat: number;
  type: TokenType;
  tenantId?: string;
  roles?: string[];
  permissions?: string[];
  sessionId?: string;
}

// JWT Claims Interface
export interface JwtClaims {
  sub: string;
  email: string;
  iat: number;
  exp: number;
  type: TokenType;
  tenantId?: string;
  roles?: string[];
  permissions?: string[];
  sessionId?: string;
  jti?: string; // JWT ID for token blacklisting
}
