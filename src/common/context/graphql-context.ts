import { Injectable } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { ExecutionContext } from '@nestjs/common';
import { CsrfInterceptor } from '../interceptors/csrf.interceptor';

export interface GraphQLContext {
  req: any;
  res: any;
  user?: {
    id: string;
    email: string;
    tenantId?: string;
    roles?: string[];
    permissions?: string[];
  };
  csrfToken?: string;
  ipAddress?: string;
  userAgent?: string;
}

@Injectable()
export class GraphQLContextService {
  constructor(private readonly csrfInterceptor: CsrfInterceptor) {}

  createContext(executionContext: ExecutionContext): GraphQLContext {
    const ctx = GqlExecutionContext.create(executionContext);
    const request = ctx.getContext().req;
    const response = ctx.getContext().res;

    // Extract user information from request
    const user = request.user ? {
      id: request.user.id,
      email: request.user.email,
      tenantId: request.user.tenantId,
      roles: request.user.roles || [],
      permissions: request.user.permissions || [],
    } : undefined;

    // Generate CSRF token for mutations
    const csrfToken = this.generateCsrfToken(request);

    return {
      req: request,
      res: response,
      user,
      csrfToken,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'],
    };
  }

  private generateCsrfToken(request: any): string {
    return this.csrfInterceptor.generateCsrfToken(
      request.ip,
      request.headers['user-agent']
    );
  }

  // Helper method to get user from context
  getUser(context: GraphQLContext) {
    return context.user;
  }

  // Helper method to check if user is authenticated
  isAuthenticated(context: GraphQLContext): boolean {
    return !!context.user;
  }

  // Helper method to check if user has specific role
  hasRole(context: GraphQLContext, role: string): boolean {
    if (!context.user) return false;
    return Array.isArray(context.user.roles) && context.user.roles.includes(role);
  }

  // Helper method to check if user has specific permission
  hasPermission(context: GraphQLContext, resource: string, action: string): boolean {
    if (!context.user) return false;
    
    const permissionKey = `${resource}:${action}`;
    return Array.isArray(context.user.permissions) && context.user.permissions.includes(permissionKey);
  }

  // Helper method to get tenant ID
  getTenantId(context: GraphQLContext): string | undefined {
    return context.user?.tenantId;
  }

  // Helper method to check if operation requires tenant context
  requiresTenant(context: GraphQLContext): boolean {
    return !!context.user?.tenantId;
  }
}
