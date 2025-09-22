// Temporarily disabled due to missing Prisma methods
export class SecurityService {
  // Placeholder class to prevent import errors
}

export interface SecurityMetrics {
  authLatency: number;
  errorRate: number;
  activeSessions: number;
  failedLogins: number;
  lockouts: number;
}

export interface SecurityStatus {
  status: 'healthy' | 'warning' | 'critical';
  issues: string[];
  lastChecked: Date;
}

export interface SecurityConfig {
  maxFailedLogins: number;
  lockoutDurationMinutes: number;
  sessionTimeoutMinutes: number;
  passwordMinAge: number;
  requireStrongPasswords: boolean;
  enableMFA: boolean;
  auditLogRetentionDays: number;
}