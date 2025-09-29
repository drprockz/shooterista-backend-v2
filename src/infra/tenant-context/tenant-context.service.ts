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
    
    // Get logo URL safely - ensure it's either a valid URL or undefined
    const logoUrl = this.configService.get<string>('app.DEFAULT_LOGO_URL');
    const safeLogoUrl = logoUrl && logoUrl.trim() !== '' ? logoUrl : undefined;
    
    console.log('🔍 [DEBUG] TenantContextService.getTenantMeta called');
    console.log('🔍 [DEBUG] logoUrl from config:', logoUrl);
    console.log('🔍 [DEBUG] safeLogoUrl:', safeLogoUrl);
    
    // For now, return default tenant meta with SMTP provider
    // In a real implementation, you would fetch tenant-specific data from database
    return {
      tenantId,
      brandColors: {
        primary: this.configService.get<string>('app.DEFAULT_PRIMARY_COLOR', '#3B82F6'),
        secondary: this.configService.get<string>('app.DEFAULT_SECONDARY_COLOR', '#1E40AF'),
      },
      logoUrl: safeLogoUrl,
      fromEmail: this.configService.get<string>('app.EMAIL_FROM', 'noreply@shooterista.com'),
      replyToEmail: this.configService.get<string>('app.EMAIL_REPLY_TO'),
      provider: 'smtp', // For now, always use SMTP
    };
  }

  private extractTenantId(reqCtx: any): string | undefined {
    const resolutionMode = this.configService.get<string>('app.TENANT_RESOLUTION_MODE', 'subdomain');
    
    this.logger.debug(`🔍 Tenant resolution mode: ${resolutionMode}`);
    
    // Priority 1: Environment override (development only)
    if (resolutionMode === 'env') {
      const overrideSlug = this.configService.get<string>('app.TENANT_OVERRIDE_SLUG');
      const overrideId = this.configService.get<string>('app.TENANT_OVERRIDE_ID');
      
      if (overrideSlug || overrideId) {
        this.logger.debug(`🔍 Using tenant override: slug=${overrideSlug}, id=${overrideId}`);
        return overrideSlug || overrideId;
      }
    }
    
    // Priority 2: Header-based resolution (for tests and API calls)
    if (resolutionMode === 'header' || resolutionMode === 'env') {
      if (reqCtx?.headers?.['x-tenant-id']) {
        this.logger.debug(`🔍 Using X-Tenant-Id header: ${reqCtx.headers['x-tenant-id']}`);
        return reqCtx.headers['x-tenant-id'];
      }
      
      if (reqCtx?.headers?.['x-tenant-slug']) {
        this.logger.debug(`🔍 Using X-Tenant-Slug header: ${reqCtx.headers['x-tenant-slug']}`);
        return reqCtx.headers['x-tenant-slug'];
      }
    }
    
    // Priority 3: User context (if authenticated)
    if (reqCtx?.user?.tenantId) {
      this.logger.debug(`🔍 Using user tenantId: ${reqCtx.user.tenantId}`);
      return reqCtx.user.tenantId;
    }
    
    // Priority 4: Cookie-based resolution
    if (reqCtx?.cookies?.['tenant-id']) {
      this.logger.debug(`🔍 Using tenant-id cookie: ${reqCtx.cookies['tenant-id']}`);
      return reqCtx.cookies['tenant-id'];
    }
    
    // Priority 5: Subdomain-based resolution (default)
    if (reqCtx?.headers?.host) {
      const host = reqCtx.headers.host;
      // Example: tenant1.shooterista.com -> tenant1
      const subdomain = host.split('.')[0];
      if (subdomain && subdomain !== 'www' && subdomain !== 'localhost') {
        this.logger.debug(`🔍 Using subdomain resolution: ${subdomain} from host ${host}`);
        return subdomain;
      }
    }
    
    this.logger.debug('🔍 No tenant ID found in any resolution method');
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
