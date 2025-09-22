import { registerDecorator, ValidationOptions, ValidationArguments } from 'class-validator';

// Password policy configuration
export interface PasswordPolicy {
  minLength: number;
  maxLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
  forbiddenPatterns: RegExp[];
  breachCheckEnabled: boolean;
}

export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = {
  minLength: 8,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  forbiddenPatterns: [
    /(.)\1{3,}/, // No more than 3 consecutive identical characters
    /123456|password|qwerty|abc123/i, // Common weak patterns
  ],
  breachCheckEnabled: true,
};

// Common breached passwords (in production, use HaveIBeenPwned API)
const COMMON_BREACHED_PASSWORDS = new Set([
  'password', '123456', 'password123', 'admin', 'qwerty',
  'letmein', 'welcome', 'monkey', '1234567890', 'abc123',
  'password1', '123123', 'dragon', 'master', 'hello',
  'freedom', 'whatever', 'qazwsx', 'trustno1', '654321',
]);

export function IsStrongPassword(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      name: 'isStrongPassword',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: any, args: ValidationArguments) {
          if (typeof value !== 'string') {
            return false;
          }

          const policy = DEFAULT_PASSWORD_POLICY;
          const password = value;

          // Check length
          if (password.length < policy.minLength || password.length > policy.maxLength) {
            return false;
          }

          // Check character requirements
          if (policy.requireUppercase && !/[A-Z]/.test(password)) {
            return false;
          }

          if (policy.requireLowercase && !/[a-z]/.test(password)) {
            return false;
          }

          if (policy.requireNumbers && !/\d/.test(password)) {
            return false;
          }

          if (policy.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            return false;
          }

          // Check forbidden patterns
          for (const pattern of policy.forbiddenPatterns) {
            if (pattern.test(password)) {
              return false;
            }
          }

          // Check against breached passwords
          if (policy.breachCheckEnabled && COMMON_BREACHED_PASSWORDS.has(password.toLowerCase())) {
            return false;
          }

          return true;
        },
        defaultMessage(args: ValidationArguments) {
          return 'Password does not meet security requirements. It must contain uppercase, lowercase, numbers, special characters, and not be a commonly breached password.';
        },
      },
    });
  };
}

export function IsEmailFormat(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      name: 'isEmailFormat',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: any, args: ValidationArguments) {
          if (typeof value !== 'string') {
            return false;
          }

          // Enhanced email regex with MX-safe validation
          const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
          
          if (!emailRegex.test(value)) {
            return false;
          }

          // Additional checks
          const parts = value.split('@');
          if (parts.length !== 2) {
            return false;
          }

          const [localPart, domain] = parts;
          
          // Local part validation
          if (localPart.length === 0 || localPart.length > 64) {
            return false;
          }

          // Domain validation
          if (domain.length === 0 || domain.length > 253) {
            return false;
          }

          // Check for consecutive dots
          if ((typeof localPart === 'string' && localPart.includes('..')) || 
              (typeof domain === 'string' && domain.includes('..'))) {
            return false;
          }

          // Check for leading/trailing dots
          if (localPart.startsWith('.') || localPart.endsWith('.') || 
              domain.startsWith('.') || domain.endsWith('.')) {
            return false;
          }

          return true;
        },
        defaultMessage(args: ValidationArguments) {
          return 'Please provide a valid email address format.';
        },
      },
    });
  };
}

export function IsUniqueEmailPerTenant(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      name: 'isUniqueEmailPerTenant',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: any, args: ValidationArguments) {
          // This will be validated at the service level
          // since we need database access for uniqueness checks
          return true;
        },
        defaultMessage(args: ValidationArguments) {
          return 'Email address is already registered for this tenant.';
        },
      },
    });
  };
}

export function IsValidTenantId(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      name: 'isValidTenantId',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: any, args: ValidationArguments) {
          if (value === null || value === undefined) {
            return true; // Optional field
          }

          if (typeof value !== 'string') {
            return false;
          }

          // Tenant ID format validation (CUID format)
          const tenantIdRegex = /^c[a-z0-9]{24}$/;
          return tenantIdRegex.test(value);
        },
        defaultMessage(args: ValidationArguments) {
          return 'Tenant ID must be a valid CUID format.';
        },
      },
    });
  };
}

export function IsValidUserType(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      name: 'isValidUserType',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: any, args: ValidationArguments) {
          const validTypes = ['superadmin', 'admin', 'athlete'];
          return typeof value === 'string' && validTypes.includes(value);
        },
        defaultMessage(args: ValidationArguments) {
          return 'User type must be one of: superadmin, admin, athlete.';
        },
      },
    });
  };
}

export function IsValidOTP(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      name: 'isValidOTP',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: any, args: ValidationArguments) {
          if (typeof value !== 'string') {
            return false;
          }

          // OTP format validation (6-digit numeric)
          const otpRegex = /^\d{6}$/;
          return otpRegex.test(value);
        },
        defaultMessage(args: ValidationArguments) {
          return 'OTP must be a 6-digit numeric code.';
        },
      },
    });
  };
}

export function IsValidToken(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      name: 'isValidToken',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: any, args: ValidationArguments) {
          if (typeof value !== 'string') {
            return false;
          }

          // Token format validation (hex string, 64 characters)
          const tokenRegex = /^[a-f0-9]{64}$/;
          return tokenRegex.test(value);
        },
        defaultMessage(args: ValidationArguments) {
          return 'Token must be a valid 64-character hex string.';
        },
      },
    });
  };
}

export function IsValidDeviceInfo(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      name: 'isValidDeviceInfo',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: any, args: ValidationArguments) {
          if (value === null || value === undefined) {
            return true; // Optional field
          }

          if (typeof value !== 'string') {
            return false;
          }

          // Device info should be reasonable length and not contain suspicious characters
          if (value.length > 500) {
            return false;
          }

          // Check for potential XSS or injection attempts
          const suspiciousPatterns = [
            /<script/i,
            /javascript:/i,
            /on\w+\s*=/i,
            /eval\s*\(/i,
            /expression\s*\(/i,
          ];

          for (const pattern of suspiciousPatterns) {
            if (pattern.test(value)) {
              return false;
            }
          }

          return true;
        },
        defaultMessage(args: ValidationArguments) {
          return 'Device information contains invalid or suspicious content.';
        },
      },
    });
  };
}
