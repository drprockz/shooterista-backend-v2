# Development Guide - Shooterista Backend

## 📋 Overview

This guide provides comprehensive information about the seeded test data, development workflow, frontend integration steps, and end-to-end authentication flows for the Shooterista backend system.

## 🗄️ Seeded Test Data

### Tenant Information
- **Tenant ID**: `clr1234567890abcdef`
- **Tenant Slug**: `club-x`
- **Tenant Name**: `Club X Shooting Range`
- **Status**: `ACTIVE`
- **Contact**: `admin@club-x.com`, `+1-555-0123`
- **Address**: `123 Shooting Range Rd, Sports City, SC 12345`

### User Accounts

#### Admin User
- **Email**: `admin@club-x.com`
- **Password**: `Admin123!`
- **Role**: `ADMIN`
- **Profile Status**: `APPROVED`
- **Profile Completion**: `100%`
- **Modules Unlocked**: `true`
- **Email Verified**: `true`
- **First Login**: `false`

**Profile Data:**
- **Personal**: John Admin, Male, DOB: 1985-01-01
- **Contact**: admin@club-x.com, +1-555-0123, Sports City, SC, USA
- **Education**: Bachelor, Sports University (2007)
- **Job**: Range Manager, Club X Shooting Range, 10 years experience
- **Event**: Air Rifle Expert, USA-SHOOTING federation

#### Test User
- **Email**: `test@club-x.com`
- **Password**: `Test123!`
- **Role**: `ATHLETE`
- **Profile Status**: `DRAFT`
- **Profile Completion**: `0%`
- **Modules Unlocked**: `false`
- **Email Verified**: `true`
- **First Login**: `true`

### Athletes Data
1. **John Doe**
   - Email: `john.doe@club-x.com`
   - Discipline: Air Rifle
   - Classification: Senior
   - Handedness: Right
   - Eye Dominance: Right

2. **Jane Smith**
   - Email: `jane.smith@club-x.com`
   - Discipline: Air Pistol
   - Classification: Senior
   - Handedness: Left
   - Eye Dominance: Left

### Competition Data
- **Name**: Spring Championship 2024
- **Type**: Individual Air Rifle
- **Format**: 60 Shots (6 series × 10 shots)
- **Dates**: April 15, 2024
- **Venue**: Club X Shooting Range
- **Status**: Published
- **Registration**: Open (March 1 - April 10, 2024)
- **Fee**: $25.00

## 🔧 Development Environment Setup

### Prerequisites
- Node.js 18+
- PostgreSQL server running
- Redis server running
- SMTP email service (Gmail configured)

### Environment Configuration
```bash
# Copy development environment
cp .env.development .env

# Key environment variables for development
NODE_ENV=development
PORT=5001

# Tenant Resolution (for local development)
TENANT_RESOLUTION_MODE=env
TENANT_OVERRIDE_SLUG=club-x
TENANT_OVERRIDE_ID=

# Database URLs (update with your server)
AUTH_DB_URL="postgresql://user:pass@server:5432/auth_db"
TENANT_DB_URL="postgresql://user:pass@server:5432/tenant_db"
ATHLETES_DB_URL="postgresql://user:pass@server:5432/athletes_db"
COMPETITIONS_DB_URL="postgresql://user:pass@server:5432/competitions_db"

# SMTP Configuration
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="465"
SMTP_SECURE="true"
SMTP_USER="your-email@gmail.com"
SMTP_PASS="your-app-password"
```

### Setup Commands
```bash
# 1. Install dependencies
npm install

# 2. Generate Prisma clients
npm run prisma:gen

# 3. Run migrations (if needed)
npm run prisma:migrate

# 4. Seed databases
npm run db:seed

# 5. Test auth flows
npm run test:auth

# 6. Start development server
npm run start:dev
```

## 🌐 Frontend Integration Steps

### 1. GraphQL Endpoint Configuration
```typescript
// Frontend GraphQL client configuration
const client = new ApolloClient({
  uri: 'http://localhost:5001/graphql',
  headers: {
    'Content-Type': 'application/json',
    // Add tenant resolution headers if needed
    'X-Tenant-Slug': 'club-x', // For API calls
  },
  credentials: 'include', // For cookies
});
```

### 2. Tenant Resolution in Frontend

#### Option A: Environment Override (Development)
```typescript
// Frontend environment configuration
const TENANT_CONFIG = {
  resolutionMode: 'env', // Use environment override
  overrideSlug: 'club-x',
  apiUrl: 'http://localhost:5001/graphql',
};
```

#### Option B: Subdomain Resolution (Production)
```typescript
// Extract tenant from subdomain
const getTenantFromSubdomain = () => {
  const hostname = window.location.hostname;
  const subdomain = hostname.split('.')[0];
  return subdomain !== 'www' && subdomain !== 'localhost' ? subdomain : null;
};

const TENANT_CONFIG = {
  resolutionMode: 'subdomain',
  tenantSlug: getTenantFromSubdomain(),
  apiUrl: `https://${getTenantFromSubdomain()}.shooterista.com/graphql`,
};
```

### 3. Authentication State Management
```typescript
// Frontend auth context/store
interface AuthState {
  user: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    userType: 'ADMIN' | 'ATHLETE';
    tenantId: string;
    profileStatus: 'DRAFT' | 'SUBMITTED' | 'APPROVED' | 'REJECTED';
    profileCompletion: number;
    modulesUnlocked: boolean;
    isFirstLogin: boolean;
  } | null;
  token: string | null;
  tenant: {
    id: string;
    slug: string;
    name: string;
  } | null;
}
```

### 4. API Integration Examples

#### Login Mutation
```graphql
mutation Login($email: String!, $password: String!) {
  login(email: $email, password: $password) {
    success
    token
    refreshToken
    user {
      id
      email
      firstName
      lastName
      userType
      tenantId
      profileStatus
      profileCompletion
      modulesUnlocked
      isFirstLogin
    }
    tenant {
      id
      slug
      name
    }
  }
}
```

#### Register Flow
```graphql
# Step 1: Request OTP
mutation RequestEmailOtp($email: String!) {
  requestEmailOtp(email: $email) {
    success
    message
    requestId
  }
}

# Step 2: Verify OTP
mutation VerifyEmailOtp($email: String!, $code: String!) {
  verifyEmailOtp(email: $email, code: $code) {
    success
    emailVerificationToken
    expiresAt
  }
}

# Step 3: Register User
mutation Register($input: RegisterInput!) {
  register(input: $input) {
    success
    token
    refreshToken
    user {
      id
      email
      firstName
      lastName
      profileStatus
      profileCompletion
      modulesUnlocked
      isFirstLogin
    }
  }
}
```

## 🔄 End-to-End Authentication Flows

### Flow 1: User Registration (New User)

```mermaid
sequenceDiagram
    participant F as Frontend
    participant B as Backend
    participant E as Email Service
    participant DB as Database

    F->>B: POST /graphql (requestEmailOtp)
    B->>DB: Check user exists
    DB-->>B: User not found
    B->>E: Send OTP email
    E-->>B: Email sent
    B-->>F: OTP sent successfully

    F->>B: POST /graphql (verifyEmailOtp)
    B->>DB: Verify OTP code
    DB-->>B: OTP valid
    B-->>F: EmailVerificationToken

    F->>B: POST /graphql (register)
    B->>DB: Create user with DRAFT profile
    DB-->>B: User created
    B->>E: Send welcome email
    B-->>F: Registration successful, JWT token
```

**Frontend Implementation:**
```typescript
const registerFlow = async (email: string, password: string, userData: any) => {
  try {
    // Step 1: Request OTP
    const otpResponse = await requestEmailOtp({ email });
    if (!otpResponse.success) throw new Error('OTP request failed');
    
    // Step 2: User enters OTP
    const otpCode = await getUserInput('Enter verification code');
    
    // Step 3: Verify OTP
    const verifyResponse = await verifyEmailOtp({ email, code: otpCode });
    if (!verifyResponse.success) throw new Error('OTP verification failed');
    
    // Step 4: Register user
    const registerResponse = await register({
      email,
      password,
      emailVerificationToken: verifyResponse.emailVerificationToken,
      ...userData
    });
    
    if (registerResponse.success) {
      // Store auth state
      setAuthState({
        user: registerResponse.user,
        token: registerResponse.token,
        tenant: registerResponse.tenant
      });
      
      // Redirect based on profile status
      if (registerResponse.user.isFirstLogin) {
        router.push('/profile-completion');
      } else {
        router.push('/dashboard');
      }
    }
  } catch (error) {
    showError(error.message);
  }
};
```

### Flow 2: User Login (Existing User)

```mermaid
sequenceDiagram
    participant F as Frontend
    participant B as Backend
    participant DB as Database

    F->>B: POST /graphql (login)
    B->>DB: Verify credentials
    DB-->>B: User found, password valid
    B->>DB: Update lastLoginAt
    B-->>F: JWT token + user data

    alt Profile Status = DRAFT
        F->>F: Redirect to /profile-completion
    else Profile Status = APPROVED
        F->>F: Redirect to /dashboard
    else Profile Status = SUBMITTED
        F->>F: Show "Pending Approval" message
    end
```

**Frontend Implementation:**
```typescript
const loginFlow = async (email: string, password: string) => {
  try {
    const response = await login({ email, password });
    
    if (response.success) {
      // Store auth state
      setAuthState({
        user: response.user,
        token: response.token,
        tenant: response.tenant
      });
      
      // Handle different profile states
      switch (response.user.profileStatus) {
        case 'DRAFT':
          router.push('/profile-completion');
          break;
        case 'SUBMITTED':
          router.push('/pending-approval');
          break;
        case 'APPROVED':
          router.push('/dashboard');
          break;
        case 'REJECTED':
          router.push('/profile-rejected');
          break;
      }
    }
  } catch (error) {
    showError('Login failed: ' + error.message);
  }
};
```

### Flow 3: Profile Completion Workflow

```mermaid
sequenceDiagram
    participant F as Frontend
    participant B as Backend
    participant DB as Database

    F->>B: POST /graphql (saveProfileDraft)
    B->>DB: Save draft data
    DB-->>B: Draft saved
    B-->>F: Draft saved successfully

    F->>B: POST /graphql (submitProfile)
    B->>DB: Update profile status to SUBMITTED
    DB-->>B: Profile submitted
    B-->>F: Profile submitted for review

    Note over F,B: Admin reviews profile

    F->>B: POST /graphql (getProfileStatus)
    B->>DB: Check profile status
    DB-->>B: Status = APPROVED
    B-->>F: Profile approved, modules unlocked
```

**Frontend Implementation:**
```typescript
const profileCompletionFlow = {
  // Save draft
  saveDraft: async (section: string, data: any) => {
    await saveProfileDraft({ section, data });
  },
  
  // Submit for approval
  submitProfile: async () => {
    const response = await submitProfile();
    if (response.success) {
      showMessage('Profile submitted for review');
      router.push('/pending-approval');
    }
  },
  
  // Check approval status
  checkStatus: async () => {
    const response = await getProfileStatus();
    if (response.profileStatus === 'APPROVED') {
      showMessage('Profile approved! You now have full access.');
      router.push('/dashboard');
    }
  }
};
```

### Flow 4: Admin Profile Approval

```mermaid
sequenceDiagram
    participant A as Admin Frontend
    participant B as Backend
    participant DB as Database
    participant E as Email Service

    A->>B: POST /graphql (getPendingProfiles)
    B->>DB: Query profiles with SUBMITTED status
    DB-->>B: Pending profiles
    B-->>A: List of pending profiles

    A->>B: POST /graphql (approveProfile)
    B->>DB: Update profile status to APPROVED
    B->>DB: Set modulesUnlocked = true
    B->>DB: Set profileCompletion = 100
    DB-->>B: Profile approved
    B->>E: Send approval notification email
    B-->>A: Profile approved successfully
```

## 🧪 Testing the Flows

### Using GraphQL Playground
1. Navigate to `http://localhost:5001/graphql`
2. Use the seeded test credentials
3. Test mutations and queries

### Test Scenarios

#### Scenario 1: New User Registration
```bash
# 1. Request OTP
curl -X POST http://localhost:5001/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { requestEmailOtp(email: \"newuser@club-x.com\") { success message } }"}'

# 2. Verify OTP (use code from email)
curl -X POST http://localhost:5001/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { verifyEmailOtp(email: \"newuser@club-x.com\", code: \"123456\") { success emailVerificationToken } }"}'

# 3. Register user
curl -X POST http://localhost:5001/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { register(input: { email: \"newuser@club-x.com\", password: \"Test123!\", emailVerificationToken: \"token\", firstName: \"New\", lastName: \"User\" }) { success user { profileStatus } } }"}'
```

#### Scenario 2: Admin Login
```bash
curl -X POST http://localhost:5001/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { login(email: \"admin@club-x.com\", password: \"Admin123!\") { success user { profileStatus modulesUnlocked } } }"}'
```

#### Scenario 3: Profile Completion
```bash
# Save profile draft
curl -X POST http://localhost:5001/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"query":"mutation { saveProfileDraft(section: \"PERSONAL\", data: \"{\\\"firstName\\\": \\\"John\\\", \\\"lastName\\\": \\\"Doe\\\"}\") { success } }"}'

# Submit profile
curl -X POST http://localhost:5001/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"query":"mutation { submitProfile { success } }"}'
```

## 🔍 Debugging Tips

### Common Issues

1. **Tenant Resolution Not Working**
   - Check `TENANT_RESOLUTION_MODE` in `.env`
   - Verify `TENANT_OVERRIDE_SLUG` is set correctly
   - Check logs for tenant resolution debugging info

2. **Email Not Sending**
   - Verify SMTP credentials in `.env`
   - Check `EMAIL_ENABLED=true`
   - Test SMTP connection: `npm run diag:notifications`

3. **Profile Completion Issues**
   - Check `FEATURE_REQUIRE_PROFILE_COMPLETION=true`
   - Verify `PROFILE_MIN_COMPLETION_PERCENTAGE=80`
   - Check user's `profileStatus` and `modulesUnlocked` flags

4. **Database Connection Issues**
   - Verify database URLs in `.env`
   - Check if databases are running
   - Test connections: `npm run db:test`

### Logging
- Enable debug logging: `LOG_LEVEL=debug`
- Check tenant resolution logs for debugging
- Monitor email sending logs
- Track profile completion workflow logs

## 📚 Additional Resources

- **API Documentation**: `API_DOCUMENTATION_GUIDE.md`
- **Authentication Flow**: `AUTHENTICATION_FLOW_DOCUMENTATION.md`
- **OTP Testing**: `OTP_TEST_GUIDE.md`
- **Setup Report**: `SETUP_COMPLETE_REPORT.md`

## 🚀 Next Steps

1. **Frontend Development**: Use the provided GraphQL mutations and queries
2. **UI Components**: Build forms for registration, login, and profile completion
3. **State Management**: Implement auth context with the provided interfaces
4. **Testing**: Use the test scenarios to verify your frontend implementation
5. **Production Deployment**: Switch to subdomain-based tenant resolution

The backend is fully functional and ready for frontend integration! 🎉
