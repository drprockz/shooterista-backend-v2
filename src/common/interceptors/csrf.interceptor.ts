import { Injectable, NestInterceptor, ExecutionContext, CallHandler, UnauthorizedException } from '@nestjs/common';
import { Observable } from 'rxjs';
import { GqlExecutionContext } from '@nestjs/graphql';
import * as crypto from 'crypto';

@Injectable()
export class CsrfInterceptor implements NestInterceptor {
  private readonly csrfSecret: string;
  private readonly tokenExpiry = 24 * 60 * 60 * 1000; // 24 hours

  constructor() {
    this.csrfSecret = process.env.CSRF_SECRET || 'default-csrf-secret-change-in-production';
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const ctx = GqlExecutionContext.create(context);
    const request = ctx.getContext().req;
    const operationType = ctx.getInfo().operation.operation;

    // Skip CSRF check for queries (read operations)
    if (operationType === 'query') {
      return next.handle();
    }

    // Skip CSRF check for introspection queries
    const operationName = ctx.getInfo().fieldName;
    if (operationName === 'IntrospectionQuery' || operationName === '__schema') {
      return next.handle();
    }

    // Check CSRF token for mutations
    this.validateCsrfToken(request);

    return next.handle();
  }

  private validateCsrfToken(request: any): void {
    const csrfToken = request.headers['x-csrf-token'] || request.headers['csrf-token'];
    
    if (!csrfToken) {
      throw new UnauthorizedException('CSRF token is required for this operation');
    }

    try {
      const [timestamp, hash] = csrfToken.split('.');
      
      if (!timestamp || !hash) {
        throw new UnauthorizedException('Invalid CSRF token format');
      }

      // Check if token is expired
      const tokenTime = parseInt(timestamp, 36);
      const now = Date.now();
      
      if (now - tokenTime > this.tokenExpiry) {
        throw new UnauthorizedException('CSRF token has expired');
      }

      // Verify token integrity
      const expectedHash = this.generateCsrfHash(timestamp, request.ip, request.headers['user-agent']);
      
      if (hash !== expectedHash) {
        throw new UnauthorizedException('Invalid CSRF token');
      }
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('Invalid CSRF token');
    }
  }

  // Generate a new CSRF token
  generateCsrfToken(ipAddress: string, userAgent: string): string {
    const timestamp = Date.now().toString(36);
    const hash = this.generateCsrfHash(timestamp, ipAddress, userAgent);
    return `${timestamp}.${hash}`;
  }

  private generateCsrfHash(timestamp: string, ipAddress: string, userAgent: string): string {
    const data = `${timestamp}.${ipAddress}.${userAgent}`;
    return crypto
      .createHmac('sha256', this.csrfSecret)
      .update(data)
      .digest('hex')
      .substring(0, 16); // Use first 16 characters for shorter tokens
  }

  // Verify CSRF token (for manual verification)
  verifyCsrfToken(token: string, ipAddress: string, userAgent: string): boolean {
    try {
      const [timestamp, hash] = token.split('.');
      
      if (!timestamp || !hash) {
        return false;
      }

      // Check if token is expired
      const tokenTime = parseInt(timestamp, 36);
      const now = Date.now();
      
      if (now - tokenTime > this.tokenExpiry) {
        return false;
      }

      // Verify token integrity
      const expectedHash = this.generateCsrfHash(timestamp, ipAddress, userAgent);
      return hash === expectedHash;
    } catch {
      return false;
    }
  }
}
