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
  // Profile Completion Actions
  PROFILE_DRAFT_SAVED = 'PROFILE_DRAFT_SAVED',
  PROFILE_SUBMITTED = 'PROFILE_SUBMITTED',
  PROFILE_APPROVED = 'PROFILE_APPROVED',
  PROFILE_REJECTED = 'PROFILE_REJECTED',
  // OTP Actions
  EMAIL_OTP_REQUEST = 'EMAIL_OTP_REQUEST',
  EMAIL_OTP_VERIFIED = 'EMAIL_OTP_VERIFIED',
  EMAIL_OTP_VERIFICATION_FAILED = 'EMAIL_OTP_VERIFICATION_FAILED',
}

export enum TokenType {
  ACCESS = 'ACCESS',
  REFRESH = 'REFRESH',
  PASSWORD_RESET = 'PASSWORD_RESET',
  EMAIL_VERIFICATION = 'EMAIL_VERIFICATION',
}

export enum UserType {
  SUPERADMIN = 'SUPERADMIN',
  ADMIN = 'ADMIN',
  ATHLETE = 'ATHLETE',
}

export enum ProfileStatus {
  DRAFT = 'DRAFT',
  SUBMITTED = 'SUBMITTED',
  APPROVED = 'APPROVED',
  REJECTED = 'REJECTED',
}

export enum ProfileSection {
  PERSONAL = 'PERSONAL',
  CONTACT = 'CONTACT',
  EDUCATION = 'EDUCATION',
  JOB = 'JOB',
  EVENT = 'EVENT',
}

// Register enums with GraphQL
registerEnumType(UserStatus, { name: 'UserStatus' });
registerEnumType(MfaType, { name: 'MfaType' });
registerEnumType(SessionStatus, { name: 'SessionStatus' });
registerEnumType(AuditAction, { name: 'AuditAction' });
registerEnumType(TokenType, { name: 'TokenType' });
registerEnumType(UserType, { name: 'UserType' });
registerEnumType(ProfileStatus, { name: 'ProfileStatus' });
registerEnumType(ProfileSection, { name: 'ProfileSection' });

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

  @Field(() => UserType)
  userType: UserType;

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

  // Profile Completion Fields
  @Field()
  isFirstLogin: boolean;

  @Field(() => Int)
  profileCompletion: number;

  @Field(() => ProfileStatus)
  profileStatus: ProfileStatus;

  @Field()
  modulesUnlocked: boolean;

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

  @Field({ nullable: true })
  profileComplete?: boolean;

  @Field({ nullable: true })
  requiresConsent?: boolean;

  @Field({ nullable: true })
  sessionId?: string;
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

// New response types for enhanced authentication
@ObjectType()
export class OTPResponse {
  @Field()
  success: boolean;

  @Field()
  message: string;

  @Field({ nullable: true })
  sessionId?: string;

  @Field({ nullable: true })
  expiresAt?: Date;

  @Field({ nullable: true })
  resendAfter?: number; // seconds
}

@ObjectType()
export class ProfileCompletionResponse {
  @Field()
  isComplete: boolean;

  @Field(() => [String])
  missingFields: string[];

  @Field({ nullable: true })
  completionPercentage?: number;
}

@ObjectType()
export class ConsentResponse {
  @Field()
  success: boolean;

  @Field()
  message: string;

  @Field()
  termsAccepted: boolean;

  @Field()
  privacyAccepted: boolean;

  @Field({ nullable: true })
  termsVersion?: string;

  @Field({ nullable: true })
  privacyVersion?: string;

  @Field()
  acceptedAt: Date;
}

@ObjectType()
export class InviteResponse {
  @Field()
  success: boolean;

  @Field()
  message: string;

  @Field({ nullable: true })
  inviteId?: string;

  @Field({ nullable: true })
  expiresAt?: Date;
}

@ObjectType()
export class InviteInfo {
  @Field()
  id: string;

  @Field()
  email: string;

  @Field({ nullable: true })
  firstName?: string;

  @Field({ nullable: true })
  lastName?: string;

  @Field({ nullable: true })
  role?: string;

  @Field({ nullable: true })
  message?: string;

  @Field()
  tenantId: string;

  @Field()
  invitedBy: string;

  @Field()
  status: string;

  @Field()
  expiresAt: Date;

  @Field()
  createdAt: Date;
}

@ObjectType()
export class HealthMetrics {
  @Field()
  authLatency: number;

  @Field()
  errorRate: number;

  @Field()
  activeSessions: number;

  @Field()
  failedLogins: number;

  @Field()
  lockouts: number;

  @Field()
  lastUpdated: Date;
}

@ObjectType()
export class SecurityStatus {
  @Field()
  isSecure: boolean;

  @Field(() => [String])
  issues: string[];

  @Field(() => [String])
  recommendations: string[];

  @Field()
  lastChecked: Date;
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

// Profile Completion Types
@ObjectType()
export class UserProfile {
  @Field()
  id: string;

  @Field()
  userId: string;

  // Personal Information
  @Field({ nullable: true })
  personalData?: string; // JSON string

  @Field()
  personalComplete: boolean;

  @Field({ nullable: true })
  personalUpdatedAt?: Date;

  @Field({ nullable: true })
  personalUpdatedBy?: string;

  // Contact Information
  @Field({ nullable: true })
  contactData?: string; // JSON string

  @Field()
  contactComplete: boolean;

  @Field({ nullable: true })
  contactUpdatedAt?: Date;

  @Field({ nullable: true })
  contactUpdatedBy?: string;

  // Education Information
  @Field({ nullable: true })
  educationData?: string; // JSON string

  @Field()
  educationComplete: boolean;

  @Field({ nullable: true })
  educationUpdatedAt?: Date;

  @Field({ nullable: true })
  educationUpdatedBy?: string;

  // Job Information
  @Field({ nullable: true })
  jobData?: string; // JSON string

  @Field()
  jobComplete: boolean;

  @Field({ nullable: true })
  jobUpdatedAt?: Date;

  @Field({ nullable: true })
  jobUpdatedBy?: string;

  // Event/Sports Information
  @Field({ nullable: true })
  eventData?: string; // JSON string

  @Field()
  eventComplete: boolean;

  @Field({ nullable: true })
  eventUpdatedAt?: Date;

  @Field({ nullable: true })
  eventUpdatedBy?: string;

  // Metadata
  @Field(() => Int)
  dataVersion: number;

  @Field({ nullable: true })
  submittedAt?: Date;

  @Field({ nullable: true })
  approvedAt?: Date;

  @Field({ nullable: true })
  approvedBy?: string;

  @Field({ nullable: true })
  rejectedAt?: Date;

  @Field({ nullable: true })
  rejectedBy?: string;

  @Field({ nullable: true })
  rejectionReason?: string;

  @Field()
  createdAt: Date;

  @Field()
  updatedAt: Date;
}

@ObjectType()
export class UserProfileDraft {
  @Field()
  id: string;

  @Field()
  userId: string;

  @Field(() => ProfileSection)
  section: ProfileSection;

  @Field()
  draftData: string; // JSON string

  @Field()
  lastSavedAt: Date;
}

@ObjectType()
export class ProfileCompletionStatus {
  @Field()
  isComplete: boolean;

  @Field(() => Int)
  completionPercentage: number;

  @Field(() => ProfileStatus)
  profileStatus: ProfileStatus;

  @Field()
  modulesUnlocked: boolean;

  @Field()
  isFirstLogin: boolean;

  @Field(() => [String])
  missingSections: string[];

  @Field(() => [String])
  completedSections: string[];
}

@ObjectType()
export class ProfileSectionStatus {
  @Field(() => ProfileSection)
  section: ProfileSection;

  @Field()
  isComplete: boolean;

  @Field(() => Int)
  completionPercentage: number;

  @Field(() => [String])
  missingFields: string[];

  @Field({ nullable: true })
  lastUpdatedAt?: Date;

  @Field({ nullable: true })
  lastUpdatedBy?: string;
}

@ObjectType()
export class ProfileDraftResponse {
  @Field()
  success: boolean;

  @Field()
  message: string;

  @Field(() => UserProfileDraft, { nullable: true })
  draft?: UserProfileDraft;

  @Field(() => ProfileSectionStatus, { nullable: true })
  sectionStatus?: ProfileSectionStatus;
}

@ObjectType()
export class ProfileSubmissionResponse {
  @Field()
  success: boolean;

  @Field()
  message: string;

  @Field(() => ProfileStatus)
  newStatus: ProfileStatus;

  @Field(() => Int)
  completionPercentage: number;
}

@ObjectType()
export class AdminProfileActionResponse {
  @Field()
  success: boolean;

  @Field()
  message: string;

  @Field(() => ProfileStatus)
  newStatus: ProfileStatus;

  @Field({ nullable: true })
  rejectionReason?: string;

  @Field()
  modulesUnlocked: boolean;
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
