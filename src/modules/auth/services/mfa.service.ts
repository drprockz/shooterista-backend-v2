import { Injectable, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import { MfaType } from '../dto/auth.types';

@Injectable()
export class MfaService {
  constructor(private readonly configService: ConfigService) {}

  generateSecret(): string {
    return speakeasy.generateSecret({
      name: this.configService.get<string>('app.APP_NAME', 'Shooterista'),
      issuer: this.configService.get<string>('app.APP_DOMAIN', 'localhost'),
      length: 32,
    }).base32;
  }

  generateQRCode(secret: string, email: string): Promise<string> {
    const otpauthUrl = speakeasy.otpauthURL({
      secret,
      label: email,
      issuer: this.configService.get<string>('app.APP_NAME', 'Shooterista'),
      algorithm: 'sha1',
      digits: 6,
      period: 30,
    });

    return QRCode.toDataURL(otpauthUrl);
  }

  generateBackupCodes(count: number = 10): string[] {
    const codes: string[] = [];
    for (let i = 0; i < count; i++) {
      codes.push(this.generateRandomCode(8));
    }
    return codes;
  }

  verifyTOTP(token: string, secret: string): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 2, // Allow 2 time steps (60 seconds) of tolerance
    });
  }

  generateEmailOTP(): string {
    return this.generateRandomCode(6);
  }

  private generateRandomCode(length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  validateMfaToken(token: string, type: MfaType, secret?: string): boolean {
    switch (type) {
      case MfaType.TOTP:
        if (!secret) {
          throw new BadRequestException('MFA secret is required for TOTP verification');
        }
        return this.verifyTOTP(token, secret);
      
      case MfaType.EMAIL:
        // Email OTP validation would be handled by the calling service
        // This is just a placeholder for the interface
        return token.length === 6 && /^\d{6}$/.test(token);
      
      default:
        throw new BadRequestException('Invalid MFA type');
    }
  }
}
