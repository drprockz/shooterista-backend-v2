import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import jwt from 'jsonwebtoken';
import jwkToPem from 'jwk-to-pem';

@Injectable()
export class AuthGuard implements CanActivate {
  private pubKey: string = Buffer.from(process.env.JWT_PUBLIC_KEY_BASE64!, 'base64').toString('utf8');
  canActivate(ctx: ExecutionContext) {
    const req = ctx.switchToHttp().getRequest() || ctx.getArgByIndex(2)?.req; // works for REST/GraphQL
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    if (!token) return false;
    try {
      const payload = jwt.verify(token, this.pubKey, { algorithms: ['RS256'], issuer: process.env.JWT_ISS, audience: process.env.JWT_AUD });
      (req as any).user = payload;
      return true;
    } catch { return false; }
  }
}
