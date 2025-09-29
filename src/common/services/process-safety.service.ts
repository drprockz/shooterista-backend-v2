import { Logger } from '@nestjs/common';

export class ProcessSafetyService {
  private readonly logger = new Logger(ProcessSafetyService.name);
  private isInitialized = false;

  initialize(): void {
    if (this.isInitialized) {
      return;
    }

    this.logger.log('Initializing process safety nets');

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
      this.logger.error({
        event: 'unhandled_rejection',
        error: {
          name: reason?.name || 'UnhandledRejection',
          message: reason?.message || String(reason),
          stack_present: !!reason?.stack,
        },
        promise: promise.toString(),
        timestamp: new Date().toISOString(),
      });

      // Log the stack trace if available
      if (reason?.stack) {
        this.logger.error('Unhandled rejection stack trace:', reason.stack);
      }
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (error: Error) => {
      this.logger.error({
        event: 'uncaught_exception',
        error: {
          name: error.name,
          message: error.message,
          stack_present: !!error.stack,
        },
        timestamp: new Date().toISOString(),
      });

      // Log the stack trace
      this.logger.error('Uncaught exception stack trace:', error.stack);

      // Allow the framework to handle shutdown as configured
      // Don't call process.exit() here - let NestJS handle it
    });

    // Handle SIGTERM and SIGINT gracefully
    process.on('SIGTERM', () => {
      this.logger.log({
        event: 'process_signal',
        signal: 'SIGTERM',
        message: 'Received SIGTERM, starting graceful shutdown',
        timestamp: new Date().toISOString(),
      });
    });

    process.on('SIGINT', () => {
      this.logger.log({
        event: 'process_signal',
        signal: 'SIGINT',
        message: 'Received SIGINT, starting graceful shutdown',
        timestamp: new Date().toISOString(),
      });
    });

    // Handle warnings
    process.on('warning', (warning: Error) => {
      this.logger.warn({
        event: 'process_warning',
        warning: {
          name: warning.name,
          message: warning.message,
          stack_present: !!warning.stack,
        },
        timestamp: new Date().toISOString(),
      });
    });

    this.isInitialized = true;
    this.logger.log('Process safety nets initialized successfully');
  }

  // Method to manually log critical errors with context
  logCriticalError(error: Error, context: Record<string, any> = {}): void {
    this.logger.error({
      event: 'critical_error',
      error: {
        name: error.name,
        message: error.message,
        stack_present: !!error.stack,
      },
      context,
      timestamp: new Date().toISOString(),
    });

    if (error.stack) {
      this.logger.error('Critical error stack trace:', error.stack);
    }
  }

  // Method to log URL access errors specifically
  logUrlAccessError(error: Error, context: Record<string, any> = {}): void {
    this.logger.error({
      event: 'url_access_critical_error',
      error: {
        name: error.name,
        message: error.message,
        stack_present: !!error.stack,
      },
      context: {
        ...context,
        error_type: 'url_access_error',
      },
      timestamp: new Date().toISOString(),
    });

    if (error.stack) {
      this.logger.error('URL access error stack trace:', error.stack);
    }
  }
}
