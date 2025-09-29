import { Injectable, Logger } from '@nestjs/common';
import { randomUUID } from 'crypto';

export interface RequestContext {
  requestId: string;
  operationName?: string;
  userEmail?: string;
  tenantId?: string;
  ipAddress?: string;
  userAgent?: string;
  startTime: number;
}

@Injectable()
export class CorrelationService {
  private readonly logger = new Logger(CorrelationService.name);

  generateRequestId(): string {
    return randomUUID();
  }

  createRequestContext(
    operationName?: string,
    userEmail?: string,
    tenantId?: string,
    ipAddress?: string,
    userAgent?: string
  ): RequestContext {
    return {
      requestId: this.generateRequestId(),
      operationName,
      userEmail,
      tenantId,
      ipAddress,
      userAgent,
      startTime: Date.now(),
    };
  }

  createChildLogger(logger: Logger, context: RequestContext): Logger {
    const childLogger = new Logger(`${logger.constructor.name}:${context.requestId}`);
    
    // Override the log method to include context
    const originalLog = childLogger.log.bind(childLogger);
    const originalError = childLogger.error.bind(childLogger);
    const originalWarn = childLogger.warn.bind(childLogger);
    const originalDebug = childLogger.debug.bind(childLogger);

    const logWithContext = (message: any, ...optionalParams: any[]) => {
      const contextData = {
        requestId: context.requestId,
        operationName: context.operationName,
        userEmail: context.userEmail,
        tenantId: context.tenantId,
        elapsed_ms: Date.now() - context.startTime,
      };

      if (typeof message === 'string') {
        originalLog({ message, ...contextData }, ...optionalParams);
      } else if (typeof message === 'object') {
        originalLog({ ...message, ...contextData }, ...optionalParams);
      } else {
        originalLog({ message: String(message), ...contextData }, ...optionalParams);
      }
    };

    const errorWithContext = (message: any, ...optionalParams: any[]) => {
      const contextData = {
        requestId: context.requestId,
        operationName: context.operationName,
        userEmail: context.userEmail,
        tenantId: context.tenantId,
        elapsed_ms: Date.now() - context.startTime,
      };

      if (typeof message === 'string') {
        originalError({ message, ...contextData }, ...optionalParams);
      } else if (typeof message === 'object') {
        originalError({ ...message, ...contextData }, ...optionalParams);
      } else {
        originalError({ message: String(message), ...contextData }, ...optionalParams);
      }
    };

    const warnWithContext = (message: any, ...optionalParams: any[]) => {
      const contextData = {
        requestId: context.requestId,
        operationName: context.operationName,
        userEmail: context.userEmail,
        tenantId: context.tenantId,
        elapsed_ms: Date.now() - context.startTime,
      };

      if (typeof message === 'string') {
        originalWarn({ message, ...contextData }, ...optionalParams);
      } else if (typeof message === 'object') {
        originalWarn({ ...message, ...contextData }, ...optionalParams);
      } else {
        originalWarn({ message: String(message), ...contextData }, ...optionalParams);
      }
    };

    const debugWithContext = (message: any, ...optionalParams: any[]) => {
      const contextData = {
        requestId: context.requestId,
        operationName: context.operationName,
        userEmail: context.userEmail,
        tenantId: context.tenantId,
        elapsed_ms: Date.now() - context.startTime,
      };

      if (typeof message === 'string') {
        originalDebug({ message, ...contextData }, ...optionalParams);
      } else if (typeof message === 'object') {
        originalDebug({ ...message, ...contextData }, ...optionalParams);
      } else {
        originalDebug({ message: String(message), ...contextData }, ...optionalParams);
      }
    };

    childLogger.log = logWithContext;
    childLogger.error = errorWithContext;
    childLogger.warn = warnWithContext;
    childLogger.debug = debugWithContext;

    return childLogger;
  }

  logFeatureFlagsAndConfig(logger: Logger, configService: any): void {
    const flags = {
      OTP_EMAIL_REQUIRED_FOR_REGISTER: !!configService.get('app.OTP_EMAIL_REQUIRED_FOR_REGISTER'),
      SEND_WELCOME_EMAIL: true, // Always true for now
      UPLOAD_AVATAR_ON_REGISTER: false, // Not implemented yet
      ENABLE_WEBHOOKS: false, // Not implemented yet
    };

    const configPresence = {
      DEFAULT_LOGO_URL: !!configService.get('app.DEFAULT_LOGO_URL'),
      SMTP_HOST: !!configService.get('app.SMTP_HOST'),
      SMTP_USER: !!configService.get('app.SMTP_USER'),
      STORAGE_PUBLIC_BASE_URL: !!configService.get('app.STORAGE_PUBLIC_BASE_URL'),
      APP_PUBLIC_URL: !!configService.get('app.FRONTEND_URL'),
    };

    logger.log({
      event: 'register.config_snapshot',
      flags,
      config_presence: configPresence,
    });
  }

  logUrlAccessAttempt(logger: Logger, candidate: any, context: string): void {
    logger.log({
      event: 'guard.check.url',
      context,
      value_type: typeof candidate,
      isObject: candidate && typeof candidate === 'object',
      hasUrlProp: !!candidate?.url,
    });

    if (!candidate?.url) {
      logger.warn({
        event: 'guard.block.url_access',
        context,
        value_type: typeof candidate,
        isObject: candidate && typeof candidate === 'object',
        hasUrlProp: false,
      });
    }
  }
}
