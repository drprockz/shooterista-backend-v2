import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export interface TenantMeta {
  tenantId?: string;
  brandColors?: {
    primary: string;
    secondary: string;
  };
  logoUrl?: string;
  fromEmail?: string;
  replyToEmail?: string;
  provider: string;
}

@Injectable()
export class TenantContextService {
  private readonly logger = new Logger(TenantContextService.name);

  constructor(private readonly configService: ConfigService) {}

  getTenantMeta(reqCtx: any): TenantMeta {
    // Extract tenant information from request context
    const tenantId = this.extractTenantId(reqCtx);
    
    // For now, return default tenant meta with SMTP provider
    // In a real implementation, you would fetch tenant-specific data from database
    return {
      tenantId,
      brandColors: {
        primary: this.configService.get<string>('app.DEFAULT_PRIMARY_COLOR', '#3B82F6'),
        secondary: this.configService.get<string>('app.DEFAULT_SECONDARY_COLOR', '#1E40AF'),
      },
      logoUrl: this.configService.get<string>('app.DEFAULT_LOGO_URL'),
      fromEmail: this.configService.get<string>('app.EMAIL_FROM', 'noreply@shooterista.com'),
      replyToEmail: this.configService.get<string>('app.EMAIL_REPLY_TO'),
      provider: 'smtp', // For now, always use SMTP
    };
  }

  private extractTenantId(reqCtx: any): string | undefined {
    // Try to extract tenant ID from various sources
    if (reqCtx?.headers?.['x-tenant-id']) {
      return reqCtx.headers['x-tenant-id'];
    }
    
    if (reqCtx?.user?.tenantId) {
      return reqCtx.user.tenantId;
    }
    
    if (reqCtx?.cookies?.['tenant-id']) {
      return reqCtx.cookies['tenant-id'];
    }
    
    // Check domain-based tenant resolution
    if (reqCtx?.headers?.host) {
      const host = reqCtx.headers.host;
      // Example: tenant1.shooterista.com -> tenant1
      const subdomain = host.split('.')[0];
      if (subdomain && subdomain !== 'www' && subdomain !== 'localhost') {
        return subdomain;
      }
    }
    
    return undefined;
  }

  // GraphQL integration helper
  getTenantMetaFromGraphQLContext(context: any): TenantMeta {
    const req = context.req || context.request;
    return this.getTenantMeta(req);
  }

  // REST integration helper
  getTenantMetaFromRestRequest(request: any): TenantMeta {
    return this.getTenantMeta(request);
  }
}
