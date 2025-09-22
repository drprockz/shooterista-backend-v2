import { Injectable, Logger } from '@nestjs/common';
import { SendEmailPort, SendEmailParams, SendEmailResult } from '../ports/send-email.port';

@Injectable()
export class SesEmailAdapter implements SendEmailPort {
  private readonly logger = new Logger(SesEmailAdapter.name);

  async send(params: SendEmailParams): Promise<SendEmailResult> {
    // TODO: Implement AWS SES integration
    this.logger.warn('SES adapter not implemented yet - using no-op');
    
    return {
      success: false,
      error: 'SES adapter not implemented',
      provider: 'ses',
      timestamp: new Date(),
    };
  }
}