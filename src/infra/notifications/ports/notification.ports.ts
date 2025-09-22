// Notification Ports - Domain interfaces for notification services

export interface NotificationMessage {
  to: string | string[];
  subject: string;
  content: string;
  htmlContent?: string;
  attachments?: NotificationAttachment[];
  metadata?: Record<string, any>;
}

export interface NotificationAttachment {
  filename: string;
  content: Buffer | string;
  contentType: string;
  disposition?: 'attachment' | 'inline';
  cid?: string; // Content-ID for inline attachments
}

export interface NotificationTemplate {
  id: string;
  name: string;
  subject: string;
  htmlTemplate: string;
  textTemplate?: string;
  variables: string[]; // List of required template variables
}

export interface NotificationContext {
  tenantId?: string;
  userId?: string;
  requestId?: string;
  ipAddress?: string;
  userAgent?: string;
  locale?: string;
  timezone?: string;
}

export interface NotificationResult {
  success: boolean;
  messageId?: string;
  error?: string;
  provider?: string;
  timestamp: Date;
}

export interface NotificationProvider {
  name: string;
  version: string;
  capabilities: NotificationCapabilities;
}

export interface NotificationCapabilities {
  supportsHtml: boolean;
  supportsAttachments: boolean;
  supportsTemplates: boolean;
  supportsBulk: boolean;
  maxRecipients: number;
  maxAttachmentSize: number; // in bytes
  supportedAttachmentTypes: string[];
}

// Email-specific interfaces
export interface EmailMessage extends NotificationMessage {
  from?: string;
  replyTo?: string;
  cc?: string | string[];
  bcc?: string | string[];
  headers?: Record<string, string>;
}

export interface EmailProvider extends NotificationProvider {
  sendEmail(message: EmailMessage, context?: NotificationContext): Promise<NotificationResult>;
  sendBulkEmails(messages: EmailMessage[], context?: NotificationContext): Promise<NotificationResult[]>;
  validateEmailAddress(email: string): boolean;
  getDeliveryStatus(messageId: string): Promise<EmailDeliveryStatus>;
}

export interface EmailDeliveryStatus {
  messageId: string;
  status: 'sent' | 'delivered' | 'bounced' | 'failed' | 'unknown';
  timestamp: Date;
  error?: string;
  details?: Record<string, any>;
}

// SMS-specific interfaces (for future use)
export interface SmsMessage {
  to: string;
  message: string;
  from?: string;
  metadata?: Record<string, any>;
}

export interface SmsProvider extends NotificationProvider {
  sendSms(message: SmsMessage, context?: NotificationContext): Promise<NotificationResult>;
  sendBulkSms(messages: SmsMessage[], context?: NotificationContext): Promise<NotificationResult[]>;
  validatePhoneNumber(phone: string): boolean;
}

// Push notification interfaces (for future use)
export interface PushMessage {
  to: string | string[]; // Device tokens or user IDs
  title: string;
  body: string;
  data?: Record<string, any>;
  badge?: number;
  sound?: string;
  imageUrl?: string;
}

export interface PushProvider extends NotificationProvider {
  sendPush(message: PushMessage, context?: NotificationContext): Promise<NotificationResult>;
  sendBulkPush(messages: PushMessage[], context?: NotificationContext): Promise<NotificationResult[]>;
  subscribeToTopic(token: string, topic: string): Promise<boolean>;
  unsubscribeFromTopic(token: string, topic: string): Promise<boolean>;
}

// Main notification service interface
export interface INotificationService {
  // Email methods
  sendEmail(message: EmailMessage, context?: NotificationContext): Promise<NotificationResult>;
  sendBulkEmails(messages: EmailMessage[], context?: NotificationContext): Promise<NotificationResult[]>;
  
  // Template methods
  sendTemplatedEmail(
    templateId: string, 
    to: string | string[], 
    variables: Record<string, any>, 
    context?: NotificationContext
  ): Promise<NotificationResult>;
  
  // Utility methods
  validateEmailAddress(email: string): boolean;
  getProviderInfo(): NotificationProvider;
  getDeliveryStatus(messageId: string): Promise<EmailDeliveryStatus>;
  
  // Future methods (commented out for now)
  // sendSms(message: SmsMessage, context?: NotificationContext): Promise<NotificationResult>;
  // sendPush(message: PushMessage, context?: NotificationContext): Promise<NotificationResult>;
}

// Notification configuration interface
export interface NotificationConfig {
  email: {
    provider: 'console' | 'smtp' | 'ses' | 'sendgrid';
    enabled: boolean;
    defaultFrom: string;
    defaultReplyTo?: string;
    rateLimitPerMinute?: number;
    rateLimitPerHour?: number;
    rateLimitPerDay?: number;
  };
  
  smtp?: {
    host: string;
    port: number;
    secure: boolean;
    username?: string;
    password?: string;
    timeout?: number;
  };
  
  ses?: {
    region: string;
    accessKeyId: string;
    secretAccessKey: string;
    configurationSet?: string;
  };
  
  sendgrid?: {
    apiKey: string;
    fromEmail: string;
    fromName?: string;
  };
  
  templates?: {
    baseUrl: string;
    defaultLocale: string;
    supportedLocales: string[];
  };
  
  tenant?: {
    enabled: boolean;
    defaultBranding: {
      logoUrl?: string;
      primaryColor?: string;
      secondaryColor?: string;
      fontFamily?: string;
    };
  };
}
