import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { Reflector } from '@nestjs/core';
import { PrismaAuthService } from '../../modules/auth/prisma-auth.service';

export interface PermissionRequirement {
  resource: string;
  action: string;
  tenantId?: string;
}

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly prismaAuth: PrismaAuthService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const ctx = GqlExecutionContext.create(context);
    const request = ctx.getContext().req;
    
    if (!request.user) {
      throw new ForbiddenException('Authentication required');
    }

    const userId = parseInt(request.user.id);
    const tenantId = request.user.tenantId;

    // Get permission requirements from metadata
    const requirements = this.reflector.get<PermissionRequirement[]>('permissions', context.getHandler());
    
    if (!requirements || requirements.length === 0) {
      return true; // No permission requirements
    }

    // Check each permission requirement
    for (const requirement of requirements) {
      const hasPermission = await this.prismaAuth.checkUserPermission(
        userId,
        requirement.resource,
        requirement.action,
        requirement.tenantId || tenantId,
      );

      if (!hasPermission) {
        throw new ForbiddenException(
          `Insufficient permissions: ${requirement.action} on ${requirement.resource}`
        );
      }
    }

    return true;
  }
}
