import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { Reflector } from '@nestjs/core';

export const TENANT_REQUIRED_KEY = 'tenantRequired';

@Injectable()
export class TenantGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const ctx = GqlExecutionContext.create(context);
    const request = ctx.getContext().req;
    
    if (!request.user) {
      throw new ForbiddenException('Authentication required');
    }

    const tenantRequired = this.reflector.get<boolean>(TENANT_REQUIRED_KEY, context.getHandler());
    
    if (!tenantRequired) {
      return true; // No tenant requirement
    }

    if (!request.user.tenantId) {
      throw new ForbiddenException('Tenant context required for this operation');
    }

    return true;
  }
}
