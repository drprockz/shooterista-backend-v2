// Temporarily disabled due to missing Prisma methods
export class ProfileCompletionService {
  // Placeholder class to prevent import errors
}

export interface ProfileField {
  name: string;
  label: string;
  required: boolean;
  type: string;
  options?: string[];
}

export interface ProfileStatus {
  isComplete: boolean;
  completionPercentage: number;
  completedFields: string[];
  missingFields: string[];
  recommendations: string[];
}

export interface ProfileCompletionInput {
  firstName?: string;
  lastName?: string;
  phone?: string;
  country?: string;
  state?: string;
  city?: string;
  title?: string;
  company?: string;
  timezone?: string;
}

export interface ProfileCompletionResponse {
  success: boolean;
  profileStatus: ProfileStatus;
  message?: string;
}