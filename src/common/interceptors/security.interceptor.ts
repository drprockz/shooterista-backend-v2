import { Injectable, NestInterceptor, ExecutionContext, CallHandler, Logger } from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { GqlExecutionContext } from '@nestjs/graphql';
import { AuditService } from '../../modules/auth/services/audit.service';
import { RateLimitService } from '../../modules/auth/services/rate-limit.service';

@Injectable()
export class SecurityInterceptor implements NestInterceptor {
  private readonly logger = new Logger(SecurityInterceptor.name);

  constructor(
    private readonly auditService: AuditService,
    private readonly rateLimitService: RateLimitService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    try {
      // Try to create GraphQL execution context
      const ctx = GqlExecutionContext.create(context);
      const request = ctx.getContext().req;
      const info = ctx.getInfo();
      
      if (!info || !info.fieldName) {
        // If GraphQL info is not available, pass through
        return next.handle();
      }
      
      const operationName = info.fieldName;
      const operationType = info.operation?.operation || 'unknown';

      const startTime = Date.now();
      const ipAddress = request.ip;
      const userAgent = request.headers['user-agent'];
      const userId = request.user?.id ? parseInt(request.user.id) : undefined;

      // Log the operation start
      this.logger.log(`Operation started: ${operationType}.${operationName} - User: ${userId || 'anonymous'} - IP: ${ipAddress}`);

      return next.handle().pipe(
        tap(async (data) => {
          const duration = Date.now() - startTime;
          
          // Log successful operation
          this.logger.log(`Operation completed: ${operationType}.${operationName} - Duration: ${duration}ms`);
          
          // Log to audit if user is authenticated
          if (userId) {
            await this.auditService.log({
              userId,
              action: 'OPERATION_SUCCESS' as any,
              resource: 'graphql',
              resourceId: operationName,
              ipAddress,
              userAgent,
              metadata: {
                operationType,
                operationName,
                duration,
                success: true,
              },
              success: true,
              tenantId: request.user.tenantId,
            });
          }
        }),
      catchError(async (error) => {
        const duration = Date.now() - startTime;
        
        // Log failed operation
        this.logger.error(`Operation failed: ${operationType}.${operationName} - Duration: ${duration}ms - Error: ${error.message}`);
        
        // Log to audit if user is authenticated
        if (userId) {
          await this.auditService.log({
            userId,
            action: 'OPERATION_FAILED' as any,
            resource: 'graphql',
            resourceId: operationName,
            ipAddress,
            userAgent,
            metadata: {
              operationType,
              operationName,
              duration,
              error: error.message,
              stack: error.stack,
            },
            success: false,
            tenantId: request.user.tenantId,
          });
        }

        // Check for suspicious activity patterns
        await this.checkSuspiciousActivity(operationName, ipAddress, userAgent, error);

        throw error;
      }),
    );
    } catch (error) {
      // If GraphQL context creation fails, just pass through
      this.logger.warn('Failed to create GraphQL context, passing through request');
      return next.handle();
    }
  }

  private async checkSuspiciousActivity(
    operationName: string,
    ipAddress: string,
    userAgent: string,
    error: any,
  ): Promise<void> {
    // Check for potential security threats
    const suspiciousPatterns = [
      /sql/i,
      /script/i,
      /union/i,
      /select/i,
      /insert/i,
      /update/i,
      /delete/i,
      /drop/i,
      /exec/i,
      /eval/i,
    ];

    const isSuspicious = suspiciousPatterns.some(pattern => 
      pattern.test(operationName) || 
      pattern.test(userAgent) || 
      pattern.test(error.message)
    );

    if (isSuspicious) {
      this.logger.warn(`Suspicious activity detected - IP: ${ipAddress} - Operation: ${operationName} - Error: ${error.message}`);
      
      // Log security event
      await this.auditService.log({
        action: 'SECURITY_THREAT_DETECTED' as any,
        resource: 'security',
        resourceId: operationName,
        ipAddress,
        userAgent,
        metadata: {
          operationName,
          error: error.message,
          threatType: 'suspicious_pattern',
        },
        success: false,
      });

      // Consider implementing additional security measures here:
      // - IP blocking
      // - Rate limiting
      // - Alert notifications
    }
  }
}
