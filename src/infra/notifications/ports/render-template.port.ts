// RenderTemplatePort - Interface for rendering email templates
export interface RenderTemplateResult {
  html: string;
  text?: string;
}

export interface RenderTemplatePort {
  render(templateKey: string, data: any, tenantMeta: any): Promise<RenderTemplateResult>;
}
