# Profile Completion Workflow Documentation

## Overview

The profile completion workflow ensures that new users complete their profiles before accessing most application modules. This system includes draft saving, admin approval, and comprehensive audit trails.

## Architecture

### Database Schema

#### User Model (Enhanced)
- `isFirstLogin`: Boolean flag indicating if this is the user's first login
- `profileCompletion`: Integer (0-100) representing completion percentage
- `profileStatus`: Enum (DRAFT, SUBMITTED, APPROVED, REJECTED)
- `modulesUnlocked`: Boolean derived from profileStatus=APPROVED && profileCompletion=100

#### UserProfile Model
- One-to-one relationship with User
- Stores completed profile data in JSONB columns per section
- Tracks completion status and timestamps for each section
- Includes admin approval/rejection metadata

#### UserProfileDraft Model
- One-to-many relationship with User (one draft per section)
- Stores partial JSON data for each profile section
- Allows users to save work in progress

### Profile Sections

1. **Personal**: firstName, lastName, DOB, gender, photo
2. **Contact**: email (verified), phone, address, city, state, country, postalCode
3. **Education**: highestQualification, institution, year
4. **Job**: occupation, company, role, experienceYears
5. **Event/Sports**: primaryDiscipline, experienceLevel, federationId/clubId

## Workflow States

### 1. Registration
- User registers → `isFirstLogin=true`, `profileStatus=DRAFT`, `profileCompletion=0`, `modulesUnlocked=false`
- Email OTP verification required before registration succeeds
- User can immediately start filling profile sections

### 2. Draft Phase
- User can save drafts for any section
- Drafts are stored separately from final profile
- User can edit drafts multiple times
- Completion percentage calculated based on completed sections

### 3. Submission
- User submits profile when ready (minimum 80% completion required)
- All drafts moved to UserProfile table
- `profileStatus` changes to SUBMITTED
- User editing locked until admin action

### 4. Admin Review
- Admin can APPROVE or REJECT submitted profiles
- **Approve**: `profileStatus=APPROVED`, `modulesUnlocked=true`, `isFirstLogin=false`
- **Reject**: `profileStatus=REJECTED`, user can edit again with admin feedback

## GraphQL API

### Queries
```graphql
# Get current user with profile completion status
me: User

# Get detailed profile completion status
getProfileCompletion: ProfileCompletionStatus

# Get user's profile data
getMyProfile: UserProfile

# Get user's draft data
getMyProfileDrafts: [UserProfileDraft]
```

### Mutations
```graphql
# Save draft for a specific section
saveProfileDraft(input: SaveProfileDraftInput!): ProfileDraftResponse

# Submit profile for approval
submitProfile(input: SubmitProfileInput!): ProfileSubmissionResponse

# Admin approve profile
adminApproveProfile(input: AdminApproveProfileInput!): AdminProfileActionResponse

# Admin reject profile
adminRejectProfile(input: AdminRejectProfileInput!): AdminProfileActionResponse

# Request email OTP for registration
requestEmailOtp(input: RequestEmailOtpInput!): OTPResponse

# Verify email OTP for registration
verifyEmailOtp(input: VerifyEmailOtpInput!): OTPResponse
```

## Business Rules

### Completion Calculation
- Each section contributes 20% to total completion
- Section is complete when all required fields are filled
- `modulesUnlocked = (profileCompletion === 100 && profileStatus === APPROVED)`

### Access Control
- Only profile owner can read/write drafts while status is DRAFT or REJECTED
- Only admins can approve/reject profiles
- Users cannot edit profiles while status is SUBMITTED or APPROVED

### Validation
- Email uniqueness enforced at database level
- Phone uniqueness enforced if phone verification enabled
- JSON payload validation for draft data
- Minimum completion percentage required for submission

## Configuration

### Feature Flags
- `FEATURE_REQUIRE_PROFILE_COMPLETION`: Enable/disable profile completion requirement
- `PROFILE_APPROVAL_REQUIRED`: Require admin approval before unlocking modules
- `OTP_EMAIL_REQUIRED_FOR_REGISTER`: Require email OTP verification for registration
- `OTP_PHONE_REQUIRED_FOR_CONTACT`: Require phone OTP verification for contact section

### Thresholds
- `PROFILE_MIN_COMPLETION_PERCENTAGE`: Minimum completion required for submission (default: 80%)
- `PROFILE_SECTION_COMPLETION_THRESHOLD`: Percentage per section (default: 20%)

### OTP Settings
- `OTP_LENGTH`: OTP code length (default: 6)
- `OTP_EXPIRY_MINUTES`: OTP expiration time (default: 5)
- `OTP_MAX_ATTEMPTS`: Max verification attempts (default: 3)
- `OTP_COOLDOWN_MINUTES`: Cooldown between requests (default: 1)

## Audit Trail

All profile-related actions are logged with:
- User ID and admin ID (for admin actions)
- IP address and user agent
- Timestamp and success/failure status
- Metadata including section, completion percentage, rejection reason

### Audit Actions
- `PROFILE_DRAFT_SAVED`: User saves a draft
- `PROFILE_SUBMITTED`: User submits profile for approval
- `PROFILE_APPROVED`: Admin approves profile
- `PROFILE_REJECTED`: Admin rejects profile
- `EMAIL_OTP_REQUEST`: User requests email OTP
- `EMAIL_OTP_VERIFIED`: User verifies email OTP
- `EMAIL_OTP_VERIFICATION_FAILED`: OTP verification fails

## Security Considerations

### Data Protection
- Passwords never logged
- OTP codes never stored in logs
- Sensitive profile data encrypted in transit
- Audit logs include only necessary metadata

### Rate Limiting
- OTP requests rate limited per email/IP
- Profile draft saves rate limited per user
- Admin actions rate limited per admin

### Access Control
- JWT tokens required for all profile operations
- Admin role required for approval/rejection actions
- User can only access their own profile data

## Migration Strategy

### Existing Users
- All existing users backfilled with:
  - `isFirstLogin=false`
  - `profileStatus=APPROVED`
  - `profileCompletion=100`
  - `modulesUnlocked=true`

### New Users
- New registrations automatically enter profile completion workflow
- Email OTP verification required before registration succeeds
- Profile completion enforced based on feature flags

## Monitoring & Metrics

### Key Metrics
- Registration completion rate
- Profile submission rate
- Admin approval/rejection rate
- OTP verification success rate
- Draft save frequency
- Time to profile completion

### Health Checks
- Database connectivity for profile tables
- OTP service availability
- Email service availability
- Audit log service availability

## Error Handling

### Client Errors
- Clear error messages for validation failures
- Specific error codes for different failure types
- Graceful degradation when services unavailable

### Server Errors
- Comprehensive logging for debugging
- Fallback mechanisms for critical operations
- Circuit breaker patterns for external services

## Testing Strategy

### Unit Tests
- Profile completion calculation logic
- Draft save/retrieve operations
- Admin approval/rejection workflows
- OTP generation and verification

### Integration Tests
- End-to-end registration flow
- Profile submission and approval cycle
- Email OTP verification flow
- Database transaction handling

### Load Tests
- Concurrent profile operations
- OTP generation under load
- Admin approval queue processing
- Database performance under scale
