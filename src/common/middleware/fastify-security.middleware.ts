import { ConfigService } from '@nestjs/config';
import { FastifyRequest, FastifyReply } from 'fastify';

// Fastify-compatible CORS configuration
export const createFastifyCorsOptions = (configService: ConfigService) => {
  const corsOrigins = configService.get<string>('app.CORS_ORIGINS') || 'http://localhost:3000';
  const origins = corsOrigins.split(',').map(origin => origin.trim());
  
  return {
    origin: (origin: string, callback: (err: Error | null, allow?: boolean) => void) => {
      // Allow requests with no origin (mobile apps, curl, etc.)
      if (!origin) return callback(null, true);
      
      // Safe check for includes with type guard
      if (typeof origin === 'string' && origins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: configService.get<boolean>('app.CORS_CREDENTIALS') || true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: [
      'Origin',
      'X-Requested-With',
      'Content-Type',
      'Accept',
      'Authorization',
      'X-Tenant-ID',
      'X-Request-ID',
    ],
    exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    maxAge: 86400, // 24 hours
  };
};

// Fastify-compatible request ID middleware
export const fastifyRequestIdMiddleware = async (request: FastifyRequest, reply: FastifyReply) => {
  const requestId = request.headers['x-request-id'] as string || 
                   request.headers['x-correlation-id'] as string ||
                   `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  request.headers['x-request-id'] = requestId;
  reply.header('X-Request-ID', requestId);
};

// Fastify-compatible security headers middleware
export const fastifySecurityHeadersMiddleware = async (request: FastifyRequest, reply: FastifyReply) => {
  // Add security headers
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('X-Frame-Options', 'DENY');
  reply.header('X-XSS-Protection', '1; mode=block');
  reply.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  reply.header('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  // Add cache control for sensitive endpoints
  const path = request.url;
  if (typeof path === 'string' && (path.includes('/auth/') || path.includes('/admin/'))) {
    reply.header('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    reply.header('Pragma', 'no-cache');
    reply.header('Expires', '0');
  }
};

// Fastify-compatible IP validation middleware
export const fastifyIpValidationMiddleware = async (request: FastifyRequest, reply: FastifyReply) => {
  const ip = request.ip || request.socket.remoteAddress;
  
  // Block private IPs in production (except for localhost)
  if (process.env.NODE_ENV === 'production') {
    const privateIPRegex = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/;
    if (ip && privateIPRegex.test(ip) && !ip.startsWith('127.0.0.1')) {
      reply.status(403).send({
        error: 'Access denied from private IP',
        code: 'PRIVATE_IP_BLOCKED',
      });
      return;
    }
  }
};

// Fastify-compatible request size validation middleware
export const createFastifyRequestSizeMiddleware = (maxSize: number = 10 * 1024 * 1024) => {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const contentLength = parseInt(request.headers['content-length'] || '0');
    
    if (contentLength > maxSize) {
      reply.status(413).send({
        error: 'Request entity too large',
        maxSize: `${maxSize / (1024 * 1024)}MB`,
      });
      return;
    }
  };
};

// Fastify-compatible user agent validation middleware
export const fastifyUserAgentValidationMiddleware = async (request: FastifyRequest, reply: FastifyReply) => {
  const userAgent = request.headers['user-agent'];
  
  // Block requests with suspicious user agents
  const suspiciousPatterns = [
    /bot/i,
    /crawler/i,
    /spider/i,
    /scraper/i,
    /curl/i,
    /wget/i,
    /python/i,
    /java/i,
    /php/i,
  ];
  
  // Allow some legitimate user agents
  const allowedPatterns = [
    /chrome/i,
    /firefox/i,
    /safari/i,
    /edge/i,
    /opera/i,
  ];
  
  if (userAgent) {
    const isAllowed = allowedPatterns.some(pattern => pattern.test(userAgent));
    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(userAgent));
    
    if (!isAllowed && isSuspicious) {
      reply.status(403).send({
        error: 'Access denied',
        code: 'SUSPICIOUS_USER_AGENT',
      });
      return;
    }
  }
};

// Simple rate limiting using Fastify hooks
export const createFastifyRateLimitMiddleware = (configService: ConfigService) => {
  const windowMs = (configService.get<number>('app.RATE_LIMIT_TTL') || 60) * 1000;
  const maxRequests = configService.get<number>('app.RATE_LIMIT_LIMIT') || 100;
  const requests = new Map<string, { count: number; resetTime: number }>();

  return async (request: FastifyRequest, reply: FastifyReply) => {
    const ip = request.ip || request.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const windowStart = now - windowMs;

    // Clean up old entries
    for (const [key, value] of requests.entries()) {
      if (value.resetTime < now) {
        requests.delete(key);
      }
    }

    const clientRequests = requests.get(ip);
    
    if (!clientRequests) {
      requests.set(ip, { count: 1, resetTime: now + windowMs });
    } else if (clientRequests.resetTime < now) {
      requests.set(ip, { count: 1, resetTime: now + windowMs });
    } else if (clientRequests.count >= maxRequests) {
      reply.status(429).send({
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: Math.ceil(windowMs / 1000),
      });
      return;
    } else {
      clientRequests.count++;
    }

    // Add rate limit headers
    const remaining = Math.max(0, maxRequests - (clientRequests?.count || 0));
    reply.header('X-RateLimit-Limit', maxRequests.toString());
    reply.header('X-RateLimit-Remaining', remaining.toString());
    reply.header('X-RateLimit-Reset', new Date(clientRequests?.resetTime || now + windowMs).toISOString());
  };
};