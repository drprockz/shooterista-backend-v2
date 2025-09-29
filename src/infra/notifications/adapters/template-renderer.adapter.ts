import { Injectable, Logger } from '@nestjs/common';
import { RenderTemplatePort, RenderTemplateResult } from '../ports/render-template.port';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class TemplateRendererAdapter implements RenderTemplatePort {
  private readonly logger = new Logger(TemplateRendererAdapter.name);
  private readonly templatesPath = path.join(process.cwd(), 'src', 'templates');

  async render(templateKey: string, data: any, tenantMeta: any): Promise<RenderTemplateResult> {
    const startTime = Date.now();
    const requestId = this.generateRequestId();
    
    console.log('🔍 [DEBUG] TemplateRenderer.render called');
    console.log('🔍 [DEBUG] templateKey:', templateKey);
    console.log('🔍 [DEBUG] data:', JSON.stringify(data, null, 2));
    console.log('🔍 [DEBUG] tenantMeta:', JSON.stringify(tenantMeta, null, 2));
    
    try {
      this.logger.debug(`Starting template render`, {
        event: 'template_render_start',
        templateKey,
        requestId,
        hasData: !!data,
        hasTenantMeta: !!tenantMeta,
        logoUrl: tenantMeta?.logoUrl ? 'present' : 'missing'
      });

      const templatePath = path.join(this.templatesPath, `${templateKey}.html`);
      
      // Check if template exists
      if (!fs.existsSync(templatePath)) {
        this.logger.warn(`Template ${templateKey} not found, using fallback`, {
          event: 'template_not_found',
          templateKey,
          requestId
        });
        return this.getFallbackTemplate(templateKey, data, tenantMeta);
      }

      // Read template
      let html = fs.readFileSync(templatePath, 'utf8');
      
      // Apply tenant branding
      html = this.applyTenantBranding(html, tenantMeta);
      
      // Replace template variables
      html = this.replaceVariables(html, data);
      
      // Generate text version (simple HTML to text conversion)
      const text = this.htmlToText(html);

      const duration = Date.now() - startTime;
      this.logger.log(`Template rendered successfully`, {
        event: 'template_render_success',
        templateKey,
        requestId,
        duration_ms: duration,
        htmlLength: html.length,
        textLength: text.length
      });

      return {
        html,
        text,
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      this.logger.error(`Error rendering template`, {
        event: 'template_render_error',
        templateKey,
        requestId,
        duration_ms: duration,
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : 'Unknown error',
          stack_present: error instanceof Error ? !!error.stack : false
        }
      });
      
      return this.getFallbackTemplate(templateKey, data, tenantMeta);
    }
  }

  private applyTenantBranding(html: string, tenantMeta: any): string {
    console.log('🔍 [DEBUG] applyTenantBranding called');
    console.log('🔍 [DEBUG] tenantMeta:', JSON.stringify(tenantMeta, null, 2));
    
    if (!tenantMeta) return html;

    // Safely extract logo URL - handle both string and object cases
    let safeLogoUrl: string | null = null;
    
    // Guard .url access with comprehensive logging
    this.logger.log({
      event: 'guard.check.url',
      context: 'tenant_branding_logo',
      value_type: typeof tenantMeta.logoUrl,
      isObject: tenantMeta.logoUrl && typeof tenantMeta.logoUrl === 'object',
      hasUrlProp: !!tenantMeta.logoUrl?.url,
    });
    
    console.log('🔍 [DEBUG] About to check logoUrl:', tenantMeta.logoUrl);
    
    if (tenantMeta.logoUrl) {
      if (typeof tenantMeta.logoUrl === 'string' && tenantMeta.logoUrl.trim() !== '') {
        safeLogoUrl = tenantMeta.logoUrl;
        console.log('🔍 [DEBUG] Using string logoUrl:', safeLogoUrl);
      } else if (typeof tenantMeta.logoUrl === 'object' && tenantMeta.logoUrl.url) {
        // Handle case where logoUrl is an object with .url property
        safeLogoUrl = tenantMeta.logoUrl.url;
        console.log('🔍 [DEBUG] Using object logoUrl.url:', safeLogoUrl);
      } else if (typeof tenantMeta.logoUrl === 'object' && !tenantMeta.logoUrl.url) {
        this.logger.warn({
          event: 'guard.block.url_access',
          context: 'tenant_branding_logo',
          value_type: typeof tenantMeta.logoUrl,
          isObject: true,
          hasUrlProp: false,
          reason: 'object_has_no_url_property',
        });
        console.log('🔍 [DEBUG] Object has no url property');
      }
    }

    const branding = {
      logoUrl: safeLogoUrl,
      primaryColor: tenantMeta.brandColors?.primary || '#3B82F6',
      secondaryColor: tenantMeta.brandColors?.secondary || '#1E40AF',
      fontFamily: tenantMeta.fontFamily || 'Inter, sans-serif',
    };

    // Handle Handlebars-style conditionals for branding
    // Temporarily disable to debug the .url error
    // html = this.processHandlebarsConditionals(html, branding);

    // Replace branding placeholders
    html = html.replace(/\{\{logoUrl\}\}/g, branding.logoUrl || '');
    html = html.replace(/\{\{primaryColor\}\}/g, branding.primaryColor);
    html = html.replace(/\{\{secondaryColor\}\}/g, branding.secondaryColor);
    html = html.replace(/\{\{fontFamily\}\}/g, branding.fontFamily);

    return html;
  }

  private replaceVariables(html: string, data: any): string {
    if (!data) return html;

    // Normalize data to ensure all values are strings and safe
    const normalizedData = this.normalizeTemplateData(data);
    
    // Validate required variables for specific templates
    this.validateRequiredVariables(html, normalizedData);

    // Handle Handlebars-style conditionals first
    html = this.processHandlebarsConditionals(html, normalizedData);

    // Replace all {{variable}} placeholders
    for (const [key, value] of Object.entries(normalizedData)) {
      try {
        const placeholder = new RegExp(`\\{\\{${key}\\}\\}`, 'g');
        html = html.replace(placeholder, String(value));
      } catch (error) {
        this.logger.warn(`Error replacing template variable '${key}'`, {
          event: 'template_variable_replace_error',
          variable: key,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }

    return html;
  }

  private normalizeTemplateData(data: any): Record<string, string> {
    const normalized: Record<string, string> = {};
    
    try {
      for (const [key, value] of Object.entries(data)) {
        try {
          // Convert all values to strings and handle null/undefined
          if (value === null || value === undefined) {
            normalized[key] = '';
          } else if (typeof value === 'object') {
            // Handle nested objects by flattening them safely
            // Avoid accessing .url on objects that might be undefined
            if (value && typeof value === 'object') {
              normalized[key] = JSON.stringify(value);
            } else {
              normalized[key] = '';
            }
          } else {
            normalized[key] = String(value);
          }
        } catch (error) {
          this.logger.warn(`Error normalizing template data for key '${key}'`, {
            event: 'template_data_normalize_error',
            key,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
          normalized[key] = '';
        }
      }
    } catch (error) {
      this.logger.error(`Error in normalizeTemplateData`, {
        event: 'template_data_normalize_global_error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
    
    return normalized;
  }

  private validateRequiredVariables(html: string, data: Record<string, string>): void {
    // Extract all {{variable}} placeholders from the template
    const variableMatches = html.match(/\{\{(\w+)\}\}/g);
    if (!variableMatches) return;
    
    const requiredVariables = [...new Set(variableMatches.map(match => match.slice(2, -2)))];
    const missingVariables = requiredVariables.filter(variable => 
      !(variable in data) || data[variable] === ''
    );
    
    if (missingVariables.length > 0) {
      this.logger.warn(`Missing required template variables`, {
        event: 'template_variables_missing',
        missingVariables,
        availableVariables: Object.keys(data)
      });
      
      // Don't throw error, just log warning - templates should have fallbacks
    }
  }

  private processHandlebarsConditionals(html: string, data: any): string {
    console.log('🔍 [DEBUG] processHandlebarsConditionals called');
    console.log('🔍 [DEBUG] html length:', html.length);
    console.log('🔍 [DEBUG] data:', JSON.stringify(data, null, 2));
    
    if (!data) return html;
    
    try {
      // Handle {{#if variable}}...{{/if}} conditionals
      html = html.replace(/\{\{#if\s+(\w+(?:\.\w+)*)\}\}([\s\S]*?)\{\{\/if\}\}/g, (match, variable, content) => {
        console.log('🔍 [DEBUG] Processing conditional for variable:', variable);
        console.log('🔍 [DEBUG] Match:', match);
        console.log('🔍 [DEBUG] Content:', content);
        
        try {
          // Handle dot notation safely (e.g., logo.url)
          const value = this.getNestedValue(data, variable);
          console.log('🔍 [DEBUG] Value for', variable, ':', value);
          
          // Only show content if value exists and is not null, undefined, empty string, false, or 0
          if (value !== null && value !== undefined && value !== '' && value !== false && value !== 0) {
            console.log('🔍 [DEBUG] Showing content for', variable);
            return content;
          }
          console.log('🔍 [DEBUG] Hiding content for', variable);
          return '';
        } catch (error) {
          console.log('🔍 [DEBUG] Error processing conditional for', variable, ':', error.message);
          this.logger.warn(`Error processing Handlebars conditional for variable '${variable}'`, {
            event: 'handlebars_conditional_error',
            variable,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
          return '';
        }
      });
    } catch (error) {
      console.log('🔍 [DEBUG] Error in processHandlebarsConditionals:', error.message);
      this.logger.error(`Error in processHandlebarsConditionals`, {
        event: 'handlebars_processing_error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }

    return html;
  }

  private getNestedValue(obj: any, path: string): any {
    if (!obj || !path) return undefined;
    
    try {
      const keys = path.split('.');
      let value = obj;
      
      for (const key of keys) {
        if (value === null || value === undefined) {
          return undefined;
        }
        value = value[key];
      }
      
      return value;
    } catch (error) {
      console.log('🔍 [DEBUG] Error in getNestedValue for path:', path, 'Error:', error.message);
      this.logger.warn(`Error accessing nested value for path '${path}'`, {
        event: 'nested_value_access_error',
        path,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return undefined;
    }
  }

  private htmlToText(html: string): string {
    // Simple HTML to text conversion
    return html
      .replace(/<[^>]*>/g, '') // Remove HTML tags
      .replace(/&nbsp;/g, ' ') // Replace &nbsp; with space
      .replace(/&amp;/g, '&') // Replace &amp; with &
      .replace(/&lt;/g, '<') // Replace &lt; with <
      .replace(/&gt;/g, '>') // Replace &gt; with >
      .replace(/&quot;/g, '"') // Replace &quot; with "
      .replace(/\s+/g, ' ') // Replace multiple spaces with single space
      .trim();
  }

  private getFallbackTemplate(templateKey: string, data: any, tenantMeta: any): RenderTemplateResult {
    // Safely handle logo URL - handle both string and object cases
    let safeLogoUrl: string | null = null;
    
    // Guard .url access with comprehensive logging
    this.logger.log({
      event: 'guard.check.url',
      context: 'fallback_template_logo',
      value_type: typeof tenantMeta?.logoUrl,
      isObject: tenantMeta?.logoUrl && typeof tenantMeta.logoUrl === 'object',
      hasUrlProp: !!tenantMeta?.logoUrl?.url,
    });
    
    if (tenantMeta?.logoUrl) {
      if (typeof tenantMeta.logoUrl === 'string' && tenantMeta.logoUrl.trim() !== '') {
        safeLogoUrl = tenantMeta.logoUrl;
      } else if (typeof tenantMeta.logoUrl === 'object' && tenantMeta.logoUrl.url) {
        // Handle case where logoUrl is an object with .url property
        safeLogoUrl = tenantMeta.logoUrl.url;
      } else if (typeof tenantMeta.logoUrl === 'object' && !tenantMeta.logoUrl.url) {
        this.logger.warn({
          event: 'guard.block.url_access',
          context: 'fallback_template_logo',
          value_type: typeof tenantMeta.logoUrl,
          isObject: true,
          hasUrlProp: false,
          reason: 'object_has_no_url_property',
        });
      }
    }
    
    const fallbackHtml = `
      <html>
        <body style="font-family: ${tenantMeta?.fontFamily || 'Arial, sans-serif'}; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            ${safeLogoUrl ? `<img src="${safeLogoUrl}" alt="Logo" style="max-width: 200px; margin-bottom: 20px;">` : ''}
            <h1 style="color: ${tenantMeta?.brandColors?.primary || '#3B82F6'};">${this.getFallbackTitle(templateKey)}</h1>
            <p>Hello ${data?.firstName || 'User'},</p>
            <p>${this.getFallbackContent(templateKey, data)}</p>
            <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
            <p style="color: #666; font-size: 14px;">Best regards,<br>The Shooterista Team</p>
          </div>
        </body>
      </html>
    `;

    return {
      html: fallbackHtml,
      text: this.htmlToText(fallbackHtml),
    };
  }

  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private getFallbackTitle(templateKey: string): string {
    switch (templateKey) {
      case 'welcome-email':
        return 'Welcome to Shooterista!';
      case 'otp-email':
        return 'Your Verification Code';
      default:
        return 'Email from Shooterista';
    }
  }

  private getFallbackContent(templateKey: string, data: any): string {
    switch (templateKey) {
      case 'welcome-email':
        return 'Welcome to Shooterista! Your account has been created successfully. Please verify your email address to get started.';
      case 'otp-email':
        return `Your email verification code is: ${data?.code || 'N/A'}. This code will expire in 5 minutes.`;
      default:
        return 'Thank you for using Shooterista.';
    }
  }
}
