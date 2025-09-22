# Enhanced Authentication System Documentation

## Overview

The Shooterista backend now includes a comprehensive, enterprise-grade authentication system with advanced security features, multi-tenant support, and extensive monitoring capabilities.

## Features Implemented

### 🔐 Sign-Up Flow
- **Email Validation**: MX-safe regex validation with format checking
- **OTP Verification**: 6-digit numeric codes with rate limiting and TTL
- **Password Policy**: Strong password requirements with breach checking
- **Tenant Linkage**: Multi-tenant user creation with proper isolation
- **Consent Management**: Terms and privacy policy acceptance tracking
- **Profile Gating**: Block access to modules until required fields completed
- **Welcome Email**: Automated welcome email with verification instructions
- **Audit Logging**: Complete audit trail for all registration events
- **Device/Session Metadata**: IP, User-Agent, and device fingerprinting

### 🔑 Sign-In Flow
- **Brute-Force Protection**: Per-IP and per-identifier rate limiting with backoff
- **JWT Token Management**: Access and refresh token rotation with reuse detection
- **Cookie Management**: HttpOnly, Secure, SameSite=strict cookies with header fallback
- **Role Resolution**: User type resolution (superadmin/admin/athlete) with token claims
- **Tenant Scoping**: Every session bound to tenant with proper isolation
- **Profile Gate**: Redirect to "Complete profile" if incomplete
- **Session Management**: List, revoke, and monitor active sessions
- **Audit Logging**: Success/failure logging with reason codes
- **Security Monitoring**: Suspicious IP detection and blocking

### 🔄 Password Reset
- **One-Time Tokens**: Secure 64-character hex tokens with TTL
- **Single-Use Tokens**: Tokens invalidated after use
- **IP/UA Capture**: Device and location tracking for security
- **Minimum Reset Duration**: Configurable minimum time between resets
- **Session Invalidation**: All active sessions revoked on password change
- **Rate Limiting**: Protection against password reset abuse

### 🛡️ Security Baseline
- **Input Validation**: Comprehensive DTOs with class-validator
- **CORS Configuration**: Allowlist-based CORS with credentials support
- **Security Headers**: Helmet integration with CSP, HSTS, and more
- **Centralized Error Handling**: Enhanced exception filter with proper logging
- **Environment Validation**: Strict environment variable validation
- **Request Size Limits**: Protection against large payload attacks
- **User Agent Validation**: Blocking of suspicious user agents
- **IP Validation**: Private IP blocking in production

### 📊 Health Checks & Metrics
- **Authentication Latency**: Real-time performance monitoring
- **Error Rates**: Success/failure rate tracking
- **Lockout Monitoring**: Account lockout statistics
- **Session Tracking**: Active session monitoring
- **Security Status**: Automated security health checks
- **Recommendations**: Automated security recommendations

## API Endpoints

### Authentication Mutations

#### Register
```graphql
mutation Register($input: CreateUserInput!) {
  register(input: $input) {
    user {
      id
      email
      firstName
      lastName
      isEmailVerified
      status
    }
    accessToken
    refreshToken
    expiresIn
    profileComplete
    requiresConsent
    sessionId
  }
}
```

**Input Fields:**
- `email`: Valid email address (MX-safe validation)
- `password`: Strong password (8-128 chars, uppercase, lowercase, numbers, special chars)
- `firstName`: Optional first name (max 50 chars)
- `lastName`: Optional last name (max 50 chars)
- `tenantId`: Optional tenant ID (CUID format)
- `userType`: Optional user type (superadmin/admin/athlete)
- `acceptTerms`: Required boolean
- `acceptPrivacy`: Required boolean
- `termsVersion`: Optional version string
- `privacyVersion`: Optional version string
- `deviceInfo`: Optional device information
- `ipAddress`: Optional IP address
- `userAgent`: Optional user agent

#### Login
```graphql
mutation Login($input: LoginInput!) {
  login(input: $input) {
    user {
      id
      email
      firstName
      lastName
      isEmailVerified
      isMfaEnabled
      status
    }
    accessToken
    refreshToken
    expiresIn
    profileComplete
    sessionId
    mfaRequired
    mfaType
  }
}
```

#### OTP Verification
```graphql
mutation VerifyOTP($input: OTPVerificationInput!) {
  verifyOTP(input: $input) {
    success
    message
    sessionId
    expiresAt
    resendAfter
  }
}
```

#### Resend OTP
```graphql
mutation ResendOTP($email: String!) {
  resendOTP(email: $email) {
    success
    message
    expiresAt
    resendAfter
  }
}
```

### Profile Management

#### Check Profile Completion
```graphql
query CheckProfileCompletion {
  checkProfileCompletion {
    isComplete
    completionPercentage
    missingFields
    completedFields
    totalFields
  }
}
```

#### Update Profile
```graphql
mutation UpdateProfile($input: ProfileCompletionInput!) {
  updateProfile(input: $input) {
    isComplete
    completionPercentage
    missingFields
    completedFields
    totalFields
  }
}
```

#### Check Module Access
```graphql
query CanAccessModule($moduleName: String!) {
  canAccessModule(moduleName: $moduleName)
}
```

### Consent Management

#### Check Consent
```graphql
query CheckConsent {
  checkConsent
}
```

#### Record Consent
```graphql
mutation RecordConsent($input: ConsentInput!) {
  recordConsent(input: $input) {
    success
    message
    termsAccepted
    privacyAccepted
    termsVersion
    privacyVersion
    acceptedAt
  }
}
```

#### Get Consent Requirements
```graphql
query GetConsentRequirements {
  getConsentRequirements {
    termsVersion
    privacyVersion
    requireConsent
    expiryDays
  }
}
```

### Security & Health

#### Get Security Metrics
```graphql
query GetSecurityMetrics {
  getSecurityMetrics {
    authLatency
    errorRate
    activeSessions
    failedLogins
    lockouts
    lastUpdated
  }
}
```

#### Perform Security Check
```graphql
query PerformSecurityCheck {
  performSecurityCheck {
    isSecure
    issues
    recommendations
    lastChecked
  }
}
```

#### Get Security Recommendations
```graphql
query GetSecurityRecommendations {
  getSecurityRecommendations
}
```

#### Health Check
```graphql
query HealthCheck {
  healthCheck {
    status
    timestamp
    metrics {
      authLatency
      errorRate
      activeSessions
      failedLogins
      lockouts
    }
    security {
      isSecure
      issues
      recommendations
    }
    services {
      otp {
        activeOTPs
        totalStorage
      }
      profile
      consent
      security
    }
  }
}
```

## Configuration

### Environment Variables

#### OTP Configuration
```bash
OTP_LENGTH=6                    # OTP code length
OTP_EXPIRY_MINUTES=5            # OTP expiration time
OTP_MAX_ATTEMPTS=3              # Maximum verification attempts
OTP_COOLDOWN_MINUTES=1         # Cooldown between attempts
```

#### Security Configuration
```bash
SECURITY_MAX_FAILED_LOGINS=5    # Max failed logins before lockout
SECURITY_LOCKOUT_DURATION=30    # Lockout duration in minutes
SECURITY_SESSION_TIMEOUT=30     # Session timeout in minutes
SECURITY_PASSWORD_MIN_AGE=1     # Minimum password age in days
SECURITY_REQUIRE_STRONG_PASSWORDS=true
SECURITY_ENABLE_MFA=true
SECURITY_AUDIT_RETENTION=90     # Audit log retention in days
```

#### Rate Limiting Configuration
```bash
RATE_LIMIT_LOGIN_MAX=5          # Max login attempts per window
RATE_LIMIT_LOGIN_WINDOW=900000  # Login rate limit window (15 min)
RATE_LIMIT_LOGIN_BLOCK=3600000 # Login block duration (1 hour)
RATE_LIMIT_PASSWORD_RESET_MAX=3
RATE_LIMIT_PASSWORD_RESET_WINDOW=3600000
RATE_LIMIT_PASSWORD_RESET_BLOCK=3600000
RATE_LIMIT_EMAIL_VERIFICATION_MAX=5
RATE_LIMIT_EMAIL_VERIFICATION_WINDOW=3600000
RATE_LIMIT_EMAIL_VERIFICATION_BLOCK=3600000
RATE_LIMIT_MFA_MAX=3
RATE_LIMIT_MFA_WINDOW=300000
RATE_LIMIT_MFA_BLOCK=900000
```

## Security Features

### Password Policy
- Minimum 8 characters, maximum 128 characters
- Must contain uppercase letters
- Must contain lowercase letters
- Must contain numbers
- Must contain special characters
- No more than 3 consecutive identical characters
- No common weak patterns (123456, password, etc.)
- Breach checking against common passwords

### Rate Limiting
- Per-IP and per-identifier limits
- Different limits for different operations
- Exponential backoff on repeated violations
- Automatic reset on successful operations

### Session Management
- Secure session creation with device fingerprinting
- Session expiration and cleanup
- Session revocation capabilities
- Multi-device session tracking

### Audit Logging
- Complete audit trail for all authentication events
- Success and failure logging with reason codes
- IP address and user agent tracking
- Metadata capture for security analysis

## Error Handling

### Standardized Error Responses
```json
{
  "error": "Bad Request",
  "message": "Password does not meet security requirements",
  "statusCode": 400,
  "timestamp": "2024-01-15T10:30:00.000Z",
  "path": "/graphql",
  "requestId": "req_1705312200000_abc123def",
  "code": "WEAK_PASSWORD",
  "details": {
    "requirements": [
      "Must contain uppercase letters",
      "Must contain lowercase letters",
      "Must contain numbers",
      "Must contain special characters"
    ]
  }
}
```

### Error Codes
- `WEAK_PASSWORD`: Password doesn't meet requirements
- `EMAIL_INVALID`: Invalid email format
- `EMAIL_EXISTS`: Email already registered
- `RATE_LIMITED`: Too many attempts
- `SUSPICIOUS_IP`: IP blocked for suspicious activity
- `CONSENT_REQUIRED`: Terms/privacy acceptance required
- `PROFILE_INCOMPLETE`: Profile completion required
- `OTP_INVALID`: Invalid or expired OTP
- `SESSION_EXPIRED`: Session has expired
- `TOKEN_BLACKLISTED`: Token has been revoked

## GraphQL Playground Presets

### Authentication Headers
```json
{
  "Authorization": "Bearer YOUR_JWT_TOKEN",
  "X-Tenant-ID": "your-tenant-id",
  "X-Request-ID": "req_1705312200000_abc123def"
}
```

### Sample Queries
```graphql
# Health Check
query HealthCheck {
  healthCheck {
    status
    timestamp
    metrics {
      authLatency
      errorRate
      activeSessions
    }
  }
}

# Profile Status
query ProfileStatus {
  checkProfileCompletion {
    isComplete
    completionPercentage
    missingFields
  }
}

# Security Status
query SecurityStatus {
  performSecurityCheck {
    isSecure
    issues
    recommendations
  }
}
```

## Monitoring & Observability

### Metrics Collected
- Authentication latency (ms)
- Error rates (%)
- Active sessions count
- Failed login attempts
- Account lockouts
- OTP verification rates
- Profile completion rates
- Consent acceptance rates

### Health Checks
- Database connectivity
- Redis connectivity
- S3 connectivity
- Authentication service health
- Security service health
- OTP service health
- Profile service health
- Consent service health

### Logging
- Structured JSON logging
- Request/response logging
- Error logging with stack traces
- Security event logging
- Performance metrics logging
- Audit trail logging

## Best Practices

### Frontend Integration
1. Always check `profileComplete` status after login
2. Redirect to profile completion if incomplete
3. Check `requiresConsent` and prompt for consent
4. Handle OTP verification flow properly
5. Implement proper error handling for all auth flows
6. Use request IDs for debugging
7. Implement proper session management

### Security Considerations
1. Never log sensitive data (passwords, tokens)
2. Always validate input on both client and server
3. Implement proper CORS configuration
4. Use HTTPS in production
5. Regularly rotate JWT secrets
6. Monitor security metrics regularly
7. Implement proper rate limiting
8. Keep audit logs for compliance

### Performance Optimization
1. Use connection pooling for database
2. Implement caching for frequently accessed data
3. Monitor authentication latency
4. Clean up expired data regularly
5. Use proper indexing for queries
6. Implement proper pagination
7. Monitor memory usage

## Troubleshooting

### Common Issues

#### OTP Not Received
- Check email configuration
- Verify OTP service is running
- Check rate limiting
- Verify email address format

#### Login Failures
- Check password policy compliance
- Verify email verification status
- Check consent acceptance
- Review rate limiting status
- Check for suspicious IP blocking

#### Profile Completion Issues
- Verify required fields are provided
- Check field validation rules
- Review profile completion threshold
- Check module access requirements

#### Security Alerts
- Review security metrics
- Check for suspicious activity
- Verify IP allowlists
- Review audit logs
- Check for failed login patterns

### Debug Mode
Enable debug mode by setting:
```bash
NODE_ENV=development
DEBUG=auth:*
VERBOSE_LOGGING=true
```

This will provide detailed logging for troubleshooting authentication issues.

## Future Enhancements

### Planned Features
- [ ] Social login integration (Google, Facebook, etc.)
- [ ] Advanced MFA options (SMS, hardware tokens)
- [ ] Passwordless authentication
- [ ] Advanced threat detection
- [ ] Compliance reporting (GDPR, SOC2)
- [ ] Advanced analytics dashboard
- [ ] Automated security recommendations
- [ ] Integration with external security services

### API Versioning
The authentication system supports API versioning through the `API_VERSION` environment variable. Future versions will maintain backward compatibility while adding new features.

## Support

For technical support or questions about the authentication system:
1. Check the health endpoint: `/health`
2. Review security metrics: `getSecurityMetrics`
3. Perform security check: `performSecurityCheck`
4. Review audit logs: `getAuditLogs`
5. Check system health: `healthCheck`

The system provides comprehensive monitoring and logging to help diagnose and resolve authentication issues quickly and efficiently.
