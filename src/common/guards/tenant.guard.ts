import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';

@Injectable()
export class TenantGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const ctx = GqlExecutionContext.create(context);
    const request = ctx.getContext().req || context.switchToHttp().getRequest();
    
    // For now, just check if user is authenticated
    // In the future, this can be enhanced to check tenant-specific permissions
    return !!request.user;
  }
}