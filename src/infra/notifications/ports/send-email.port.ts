// SendEmailPort - Interface for sending emails
export interface SendEmailParams {
  to: string[];
  subject: string;
  html?: string;
  text?: string;
  templateKey?: string;
  data?: Record<string, any>;
  tenantMeta?: any;
}

export interface SendEmailResult {
  success: boolean;
  messageId?: string;
  error?: string;
  provider: string;
  timestamp: Date;
}

export interface SendEmailPort {
  send(params: SendEmailParams): Promise<SendEmailResult>;
}
