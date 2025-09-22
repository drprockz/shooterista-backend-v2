import { Injectable, Logger } from '@nestjs/common';
import { RenderTemplatePort, RenderTemplateResult } from '../ports/render-template.port';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class TemplateRendererAdapter implements RenderTemplatePort {
  private readonly logger = new Logger(TemplateRendererAdapter.name);
  private readonly templatesPath = path.join(process.cwd(), 'src', 'templates');

  async render(templateKey: string, data: any, tenantMeta: any): Promise<RenderTemplateResult> {
    try {
      const templatePath = path.join(this.templatesPath, `${templateKey}.html`);
      
      // Check if template exists
      if (!fs.existsSync(templatePath)) {
        this.logger.warn(`Template ${templateKey} not found, using fallback`);
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

      return {
        html,
        text,
      };
    } catch (error) {
      this.logger.error(`Error rendering template ${templateKey}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return this.getFallbackTemplate(templateKey, data, tenantMeta);
    }
  }

  private applyTenantBranding(html: string, tenantMeta: any): string {
    if (!tenantMeta) return html;

    const branding = {
      logoUrl: tenantMeta.logoUrl || '',
      primaryColor: tenantMeta.brandColors?.primary || '#3B82F6',
      secondaryColor: tenantMeta.brandColors?.secondary || '#1E40AF',
      fontFamily: tenantMeta.fontFamily || 'Inter, sans-serif',
    };

    // Replace branding placeholders
    html = html.replace(/\{\{logoUrl\}\}/g, branding.logoUrl);
    html = html.replace(/\{\{primaryColor\}\}/g, branding.primaryColor);
    html = html.replace(/\{\{secondaryColor\}\}/g, branding.secondaryColor);
    html = html.replace(/\{\{fontFamily\}\}/g, branding.fontFamily);

    return html;
  }

  private replaceVariables(html: string, data: any): string {
    if (!data) return html;

    // Replace all {{variable}} placeholders
    for (const [key, value] of Object.entries(data)) {
      const placeholder = new RegExp(`\\{\\{${key}\\}\\}`, 'g');
      html = html.replace(placeholder, String(value));
    }

    return html;
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
    const fallbackHtml = `
      <html>
        <body style="font-family: ${tenantMeta?.fontFamily || 'Arial, sans-serif'}; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            ${tenantMeta?.logoUrl ? `<img src="${tenantMeta.logoUrl}" alt="Logo" style="max-width: 200px; margin-bottom: 20px;">` : ''}
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
