import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

export interface OTPConfig {
  length: number;
  expiryMinutes: number;
  maxAttempts: number;
  cooldownMinutes: number;
}

export interface OTPData {
  code: string;
  expiresAt: Date;
  attempts: number;
  createdAt: Date;
  lastAttemptAt?: Date;
}

@Injectable()
export class OTPService {
  private readonly logger = new Logger(OTPService.name);
  private readonly otpStorage = new Map<string, OTPData>();
  private readonly config: OTPConfig;

  constructor(private readonly configService: ConfigService) {
    this.config = {
      length: parseInt(this.configService.get<string>('app.OTP_LENGTH', '6')),
      expiryMinutes: parseInt(this.configService.get<string>('app.OTP_EXPIRY_MINUTES', '5')),
      maxAttempts: parseInt(this.configService.get<string>('app.OTP_MAX_ATTEMPTS', '3')),
      cooldownMinutes: parseInt(this.configService.get<string>('app.OTP_COOLDOWN_MINUTES', '1')),
    };
  }

  /**
   * Generate a secure OTP code
   */
  generateOTP(): string {
    const digits = '0123456789';
    let otp = '';
    
    for (let i = 0; i < this.config.length; i++) {
      otp += digits[crypto.randomInt(0, digits.length)];
    }
    
    return otp;
  }

  /**
   * Create and store an OTP for a given identifier
   */
  createOTP(identifier: string): { code: string; expiresAt: Date } {
    const code = this.generateOTP();
    const expiresAt = new Date(Date.now() + this.config.expiryMinutes * 60 * 1000);
    
    const otpData: OTPData = {
      code,
      expiresAt,
      attempts: 0,
      createdAt: new Date(),
    };
    
    this.otpStorage.set(identifier, otpData);
    
    this.logger.log(`OTP created for ${identifier}, expires at ${expiresAt.toISOString()}`);
    
    return { code, expiresAt };
  }

  /**
   * Verify an OTP code
   */
  verifyOTP(identifier: string, code: string): { valid: boolean; reason?: string } {
    const otpData = this.otpStorage.get(identifier);
    
    if (!otpData) {
      return { valid: false, reason: 'OTP not found or expired' };
    }
    
    // Check if OTP has expired
    if (new Date() > otpData.expiresAt) {
      this.otpStorage.delete(identifier);
      return { valid: false, reason: 'OTP has expired' };
    }
    
    // Check if max attempts exceeded
    if (otpData.attempts >= this.config.maxAttempts) {
      this.otpStorage.delete(identifier);
      return { valid: false, reason: 'Maximum attempts exceeded' };
    }
    
    // Check cooldown period
    if (otpData.lastAttemptAt) {
      const cooldownEnd = new Date(otpData.lastAttemptAt.getTime() + this.config.cooldownMinutes * 60 * 1000);
      if (new Date() < cooldownEnd) {
        const remainingSeconds = Math.ceil((cooldownEnd.getTime() - Date.now()) / 1000);
        return { valid: false, reason: `Please wait ${remainingSeconds} seconds before trying again` };
      }
    }
    
    // Increment attempt counter
    otpData.attempts++;
    otpData.lastAttemptAt = new Date();
    
    // Verify the code
    if (otpData.code === code) {
      this.otpStorage.delete(identifier);
      this.logger.log(`OTP verified successfully for ${identifier}`);
      return { valid: true };
    } else {
      this.logger.warn(`OTP verification failed for ${identifier}, attempt ${otpData.attempts}/${this.config.maxAttempts}`);
      return { valid: false, reason: 'Invalid OTP code' };
    }
  }

  /**
   * Check if an OTP exists and is still valid
   */
  isOTPValid(identifier: string): boolean {
    const otpData = this.otpStorage.get(identifier);
    
    if (!otpData) {
      return false;
    }
    
    if (new Date() > otpData.expiresAt) {
      this.otpStorage.delete(identifier);
      return false;
    }
    
    if (otpData.attempts >= this.config.maxAttempts) {
      this.otpStorage.delete(identifier);
      return false;
    }
    
    return true;
  }

  /**
   * Get remaining time until OTP expires
   */
  getRemainingTime(identifier: string): number {
    const otpData = this.otpStorage.get(identifier);
    
    if (!otpData || new Date() > otpData.expiresAt) {
      return 0;
    }
    
    return Math.ceil((otpData.expiresAt.getTime() - Date.now()) / 1000);
  }

  /**
   * Get remaining attempts for an OTP
   */
  getRemainingAttempts(identifier: string): number {
    const otpData = this.otpStorage.get(identifier);
    
    if (!otpData) {
      return 0;
    }
    
    return Math.max(0, this.config.maxAttempts - otpData.attempts);
  }

  /**
   * Resend OTP (creates a new one, invalidates the old)
   */
  resendOTP(identifier: string): { code: string; expiresAt: Date; resendAfter: number } {
    // Remove existing OTP
    this.otpStorage.delete(identifier);
    
    // Create new OTP
    const { code, expiresAt } = this.createOTP(identifier);
    
    // Calculate resend cooldown
    const resendAfter = this.config.cooldownMinutes * 60;
    
    this.logger.log(`OTP resent for ${identifier}`);
    
    return { code, expiresAt, resendAfter };
  }

  /**
   * Clean up expired OTPs
   */
  cleanupExpiredOTPs(): void {
    const now = new Date();
    let cleanedCount = 0;
    
    for (const [identifier, otpData] of this.otpStorage.entries()) {
      if (now > otpData.expiresAt || otpData.attempts >= this.config.maxAttempts) {
        this.otpStorage.delete(identifier);
        cleanedCount++;
      }
    }
    
    if (cleanedCount > 0) {
      this.logger.log(`Cleaned up ${cleanedCount} expired OTPs`);
    }
  }

  /**
   * Get OTP statistics
   */
  getStats(): { activeOTPs: number; totalStorage: number } {
    return {
      activeOTPs: this.otpStorage.size,
      totalStorage: this.otpStorage.size,
    };
  }

  /**
   * Clear all OTPs (for testing or maintenance)
   */
  clearAllOTPs(): void {
    const count = this.otpStorage.size;
    this.otpStorage.clear();
    this.logger.log(`Cleared ${count} OTPs from storage`);
  }
}
