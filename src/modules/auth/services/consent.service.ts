// Temporarily disabled due to missing Prisma methods
export class ConsentService {
  // Placeholder class to prevent import errors
}

export interface ConsentRecord {
  userId: number;
  termsAccepted: boolean;
  privacyAccepted: boolean;
  termsVersion: string;
  privacyVersion: string;
  acceptedAt: Date;
}

export interface ConsentInput {
  termsAccepted: boolean;
  privacyAccepted: boolean;
  termsVersion: string;
  privacyVersion: string;
}

export interface ConsentResponse {
  success: boolean;
  consentRecord?: ConsentRecord;
  message?: string;
}