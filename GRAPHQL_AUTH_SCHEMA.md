# GraphQL Authentication API Schema

## Overview

This document describes the comprehensive GraphQL authentication API that has been implemented to replace the old REST-based authentication system. The new system provides enhanced security, scalability, and maintainability through a permission-based RBAC (Role-Based Access Control) approach.

## Core Features

### 🔐 Authentication & Authorization
- **JWT-based authentication** with access and refresh tokens
- **Multi-factor authentication (MFA)** support (TOTP, Email OTP)
- **Role-based access control (RBAC)** with permission bundling
- **Tenant-aware authentication** for multi-tenant support
- **Session management** with device tracking

### 🛡️ Security Features
- **Rate limiting** and brute force protection
- **CSRF protection** for mutations
- **Token blacklisting** on logout/password change
- **Audit logging** for all authentication events
- **Password reset** with secure token-based flow
- **Email verification** system

### 📊 Advanced Features
- **Permission-based authorization** with granular controls
- **Session management** with device tracking
- **Audit trail** for compliance and security monitoring
- **Multi-tenant support** with tenant-scoped permissions
- **Developer-friendly** GraphQL Playground integration

## GraphQL Schema

### Queries

#### `health: String`
Health check endpoint for the authentication service.

#### `me: User`
Get current user profile information.
- **Requires:** Authentication
- **Returns:** Complete user profile with roles and permissions

#### `getSessions(input: SessionListInput): SessionListResponse`
Get user's active sessions with pagination.
- **Requires:** Authentication
- **Input:** `activeOnly: Boolean`, `limit: Int`, `offset: Int`
- **Returns:** List of sessions with metadata

#### `checkPermission(input: PermissionCheckInput): PermissionCheckResponse`
Check if current user has specific permission.
- **Requires:** Authentication
- **Input:** `resource: String`, `action: String`, `tenantId: String`
- **Returns:** Permission check result with user's roles and permissions

#### `getRoles: [Role]` (Admin only)
Get all available roles in the system.
- **Requires:** Authentication + `admin:manage_roles` permission

#### `getPermissions: [Permission]` (Admin only)
Get all available permissions in the system.
- **Requires:** Authentication + `admin:manage_roles` permission

#### `getMyPermissions: [Permission]`
Get current user's effective permissions.
- **Requires:** Authentication

#### `hasPermission(resource: String, action: String): Boolean`
Check if current user has specific permission.
- **Requires:** Authentication

#### `getAuditLogs(input: AuditLogsInput): AuditLogResponse` (Admin only)
Get audit logs with filtering and pagination.
- **Requires:** Authentication + `audit:read` permission

### Mutations

#### Authentication

##### `register(input: CreateUserInput): AuthPayload`
Register a new user account.
- **Input:** `email: String`, `password: String`, `firstName: String`, `lastName: String`, `tenantId: String`
- **Returns:** User data with access and refresh tokens
- **Features:** Email verification required, rate limiting applied

##### `login(input: LoginInput): AuthPayload`
Authenticate user with email and password.
- **Input:** `email: String`, `password: String`, `tenantId: String`, `deviceInfo: String`, `ipAddress: String`, `userAgent: String`
- **Returns:** User data with tokens, MFA requirement if enabled
- **Features:** Rate limiting, device tracking, audit logging

##### `loginAsAdmin(input: AdminLoginInput): AuthPayload`
Admin-specific login with enhanced permissions.
- **Input:** Same as login
- **Returns:** User data with admin permissions
- **Features:** Admin role validation, enhanced audit logging

##### `verifyMfa(input: MfaVerificationInput): AuthPayload`
Complete MFA verification after login.
- **Input:** `token: String`, `type: MfaType`, `backupCode: String`
- **Returns:** User data with tokens
- **Features:** TOTP and Email OTP support

##### `refreshToken(input: RefreshTokenInput): TokenRefreshPayload`
Refresh access token using refresh token.
- **Input:** `refreshToken: String`, `deviceInfo: String`, `ipAddress: String`, `userAgent: String`
- **Returns:** New access and refresh tokens
- **Features:** Token blacklisting, session tracking

##### `logout(input: LogoutInput): Boolean`
Logout user and invalidate refresh token.
- **Requires:** Authentication
- **Input:** `refreshToken: String`
- **Features:** Token blacklisting, audit logging

##### `logoutAll: Boolean`
Logout user from all devices and sessions.
- **Requires:** Authentication
- **Features:** Revokes all sessions and tokens

#### Password Management

##### `requestPasswordReset(input: PasswordResetRequestInput): PasswordResetResponse`
Request password reset via email.
- **Input:** `email: String`, `tenantId: String`
- **Returns:** Success message with expiration time
- **Features:** Rate limiting, email sending, audit logging

##### `resetPassword(input: PasswordResetInput): Boolean`
Reset password using secure token.
- **Input:** `token: String`, `newPassword: String`
- **Features:** Token validation, password hashing, session invalidation

##### `changePassword(input: ChangePasswordInput): Boolean`
Change password for authenticated user.
- **Requires:** Authentication
- **Input:** `currentPassword: String`, `newPassword: String`
- **Features:** Current password verification, session invalidation

#### Email Verification

##### `verifyEmail(input: EmailVerificationInput): Boolean`
Verify email address using token.
- **Input:** `token: String`
- **Features:** Token validation, account activation

##### `resendEmailVerification(input: ResendEmailVerificationInput): EmailVerificationResponse`
Resend email verification.
- **Input:** `email: String`, `tenantId: String`
- **Features:** Rate limiting, new token generation

#### Multi-Factor Authentication

##### `setupMfa(input: MfaSetupInput): MfaSetup`
Set up MFA for user account.
- **Requires:** Authentication
- **Input:** `type: MfaType` (TOTP or EMAIL)
- **Returns:** Secret, QR code, backup codes
- **Features:** TOTP secret generation, QR code creation

##### `enableMfa(input: MfaVerificationInput): Boolean`
Enable MFA after setup verification.
- **Requires:** Authentication
- **Input:** `token: String`, `type: MfaType`
- **Features:** Token verification, MFA activation

##### `disableMfa(input: MfaDisableInput): Boolean`
Disable MFA for user account.
- **Requires:** Authentication
- **Input:** `password: String`, `token: String`, `type: MfaType`
- **Features:** Password verification, MFA deactivation

#### Session Management

##### `revokeSession(input: SessionRevokeInput): Boolean`
Revoke specific user session.
- **Requires:** Authentication
- **Input:** `sessionId: String`
- **Features:** Session validation, audit logging

#### Role & Permission Management (Admin only)

##### `assignRole(input: RoleAssignmentInput): Boolean`
Assign role to user.
- **Requires:** Authentication + `admin:manage_roles` permission
- **Input:** `userId: String`, `roleId: String`, `tenantId: String`

##### `removeRole(input: RoleRemovalInput): Boolean`
Remove role from user.
- **Requires:** Authentication + `admin:manage_roles` permission
- **Input:** `userId: String`, `roleId: String`, `tenantId: String`

##### `createRoleBundle(name: String, description: String, permissions: [String], tenantId: String): Role`
Create new role with permissions.
- **Requires:** Authentication + `admin:manage_roles` permission

##### `updateRoleBundle(roleId: String, name: String, description: String, permissions: [String]): Role`
Update existing role and permissions.
- **Requires:** Authentication + `admin:manage_roles` permission

#### User Management

##### `updateUser(input: UserUpdateInput): User`
Update user profile information.
- **Requires:** Authentication
- **Input:** `firstName: String`, `lastName: String`, `status: UserStatus`

#### System Administration

##### `initializeDefaultRoles: String`
Initialize default roles and permissions in the system.
- **Requires:** Authentication

## Data Types

### Core Types

#### `User`
```graphql
type User {
  id: String!
  email: String!
  firstName: String
  lastName: String
  isEmailVerified: Boolean!
  isMfaEnabled: Boolean!
  lastLoginAt: DateTime
  passwordChangedAt: DateTime
  status: UserStatus!
  tenantId: String
  createdAt: DateTime!
  updatedAt: DateTime!
  roles: [Role!]
  permissions: [Permission!]
}
```

#### `Role`
```graphql
type Role {
  id: String!
  name: String!
  description: String
  isActive: Boolean!
  tenantId: String
  createdAt: DateTime!
  updatedAt: DateTime!
  permissions: [Permission!]
}
```

#### `Permission`
```graphql
type Permission {
  id: String!
  name: String!
  description: String
  resource: String!
  action: String!
  isActive: Boolean!
  createdAt: DateTime!
  updatedAt: DateTime!
}
```

#### `Session`
```graphql
type Session {
  id: String!
  userId: String!
  deviceInfo: String
  ipAddress: String
  userAgent: String
  isActive: Boolean!
  lastUsedAt: DateTime!
  createdAt: DateTime!
  expiresAt: DateTime!
  status: SessionStatus!
}
```

#### `AuditLog`
```graphql
type AuditLog {
  id: String!
  userId: String
  action: AuditAction!
  resource: String
  resourceId: String
  ipAddress: String
  userAgent: String
  metadata: String
  success: Boolean!
  tenantId: String
  createdAt: DateTime!
}
```

### Response Types

#### `AuthPayload`
```graphql
type AuthPayload {
  user: User!
  accessToken: String!
  refreshToken: String!
  expiresIn: Int!
  mfaRequired: Boolean
  mfaType: MfaType
}
```

#### `TokenRefreshPayload`
```graphql
type TokenRefreshPayload {
  accessToken: String!
  refreshToken: String!
  expiresIn: Int!
}
```

#### `MfaSetup`
```graphql
type MfaSetup {
  secret: String!
  qrCodeUrl: String!
  backupCodes: [String!]!
}
```

### Enums

#### `UserStatus`
```graphql
enum UserStatus {
  ACTIVE
  INACTIVE
  SUSPENDED
  PENDING_VERIFICATION
}
```

#### `MfaType`
```graphql
enum MfaType {
  EMAIL
  TOTP
}
```

#### `SessionStatus`
```graphql
enum SessionStatus {
  ACTIVE
  EXPIRED
  REVOKED
}
```

#### `AuditAction`
```graphql
enum AuditAction {
  LOGIN
  LOGOUT
  LOGIN_FAILED
  PASSWORD_CHANGE
  PASSWORD_RESET_REQUEST
  PASSWORD_RESET_COMPLETE
  EMAIL_VERIFICATION_REQUEST
  EMAIL_VERIFICATION_COMPLETE
  MFA_ENABLED
  MFA_DISABLED
  MFA_VERIFICATION
  MFA_VERIFICATION_FAILED
  SESSION_CREATED
  SESSION_REVOKED
  ROLE_ASSIGNED
  ROLE_REMOVED
  PERMISSION_GRANTED
  PERMISSION_REVOKED
  ACCOUNT_LOCKED
  ACCOUNT_UNLOCKED
}
```

## Permission-Based RBAC System

### Role Bundles

The system implements a sophisticated role-based access control system with predefined role bundles:

#### `super_admin`
- **Description:** Full system access
- **Permissions:** All system permissions
- **Use Case:** System administrators

#### `admin`
- **Description:** Management access
- **Permissions:** User management, competition management, athlete management, audit logs
- **Use Case:** Organization administrators

#### `competition_manager`
- **Description:** Competition and athlete management
- **Permissions:** Competition CRUD, athlete CRUD, user read
- **Use Case:** Competition organizers

#### `athlete_manager`
- **Description:** Athlete management
- **Permissions:** Athlete CRUD, competition read, user read
- **Use Case:** Team managers, coaches

#### `judge`
- **Description:** Competition judging
- **Permissions:** Competition read, athlete read
- **Use Case:** Competition judges

#### `athlete`
- **Description:** Athlete self-service
- **Permissions:** Own athlete record read
- **Use Case:** Athletes

#### `spectator`
- **Description:** Public data access
- **Permissions:** Competition read, athlete read
- **Use Case:** General public

### Permission Structure

Permissions follow a `resource:action` pattern:

- **User permissions:** `user:create`, `user:read`, `user:update`, `user:delete`
- **Admin permissions:** `admin:access`, `admin:manage_users`, `admin:manage_roles`
- **Competition permissions:** `competition:create`, `competition:read`, `competition:update`, `competition:delete`, `competition:manage`
- **Athlete permissions:** `athlete:create`, `athlete:read`, `athlete:update`, `athlete:delete`, `athlete:manage`
- **Audit permissions:** `audit:read`, `audit:export`
- **Session permissions:** `session:read`, `session:revoke`, `session:manage`

## Security Features

### Rate Limiting
- **Login attempts:** 5 per 15 minutes per user/IP
- **Password reset:** 3 per hour per user/IP
- **Email verification:** 5 per hour per user/IP
- **MFA attempts:** 3 per 5 minutes per user/IP

### Token Security
- **JWT tokens** with configurable expiration
- **Token blacklisting** on logout/password change
- **Refresh token rotation** for enhanced security
- **CSRF protection** for mutations

### Audit Logging
- **Comprehensive logging** of all authentication events
- **IP address and user agent tracking**
- **Metadata storage** for detailed analysis
- **Tenant-aware logging** for multi-tenant environments

### Multi-Factor Authentication
- **TOTP support** with QR code generation
- **Email OTP** for backup authentication
- **Backup codes** for account recovery
- **Configurable MFA requirements**

## Developer Experience

### GraphQL Playground
- **Apollo Studio Sandbox** integration
- **Authentication headers** support
- **Schema introspection** in development
- **Query complexity analysis**

### Error Handling
- **Detailed error messages** in development
- **Sanitized errors** in production
- **Proper HTTP status codes**
- **GraphQL error extensions**

### Testing Support
- **Comprehensive test coverage**
- **Mock services** for development
- **Integration test utilities**
- **Performance benchmarking**

## Migration from REST

### Key Improvements

1. **Unified API:** Single GraphQL endpoint instead of multiple REST endpoints
2. **Type Safety:** Strong typing with GraphQL schema
3. **Efficient Queries:** Request only needed data
4. **Real-time Subscriptions:** WebSocket support for real-time updates
5. **Better Developer Experience:** Self-documenting API with introspection

### Backward Compatibility

- **JWT token format** remains compatible
- **Database schema** extends existing structure
- **Authentication flow** maintains familiar patterns
- **Error responses** follow GraphQL standards

## Configuration

### Environment Variables

```bash
# JWT Configuration
JWT_SECRET=your-secret-key
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d
JWT_ISS=your-issuer
JWT_AUD=your-audience

# Database
AUTH_DB_URL=postgresql://user:password@localhost:5432/auth_db

# Security
CSRF_SECRET=your-csrf-secret
CORS_ORIGIN=http://localhost:3000,https://yourdomain.com

# Rate Limiting
RATE_LIMIT_LOGIN_MAX=5
RATE_LIMIT_LOGIN_WINDOW=900000
RATE_LIMIT_PASSWORD_RESET_MAX=3
RATE_LIMIT_PASSWORD_RESET_WINDOW=3600000

# GraphQL
GRAPHQL_INTROSPECTION=true
GRAPHQL_DEBUG=true
GRAPHQL_MAX_DEPTH=10
GRAPHQL_MAX_COMPLEXITY=1000

# Super Admin (for initialization)
SUPER_ADMIN_EMAIL=admin@example.com
SUPER_ADMIN_PASSWORD=secure-password

# Email (for notifications)
FRONTEND_URL=http://localhost:3000
APP_NAME=Shooterista
APP_DOMAIN=localhost
```

## Conclusion

The new GraphQL authentication system provides a robust, scalable, and secure foundation for the Shooterista application. The permission-based RBAC approach with role bundling offers excellent flexibility while maintaining security best practices. The comprehensive feature set includes everything needed for a modern authentication system, from basic login/logout to advanced MFA and audit logging.

The system is designed to be developer-friendly with excellent tooling support, comprehensive error handling, and detailed documentation. The migration from REST to GraphQL brings significant improvements in API design, type safety, and developer experience while maintaining backward compatibility where possible.
