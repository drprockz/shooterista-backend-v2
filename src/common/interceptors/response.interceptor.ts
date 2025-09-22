import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { FastifyRequest } from 'fastify';

export interface Response<T> {
  data: T;
  meta?: {
    timestamp: string;
    requestId: string;
    version: string;
  };
}

@Injectable()
export class ResponseInterceptor<T> implements NestInterceptor<T, Response<T>> {
  intercept(context: ExecutionContext, next: CallHandler): Observable<Response<T>> {
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    const isGraphQL = context.getType<'http' | 'graphql'>() === 'graphql';

    // Don't transform GraphQL responses - they should return data directly
    if (isGraphQL) {
      return next.handle();
    }

    // For REST API, check if it's an auth endpoint that should return data directly
    const url = request.url;
    const isAuthEndpoint = url.includes('/auth/login') || url.includes('/auth/register') || url.includes('/auth/refresh');
    
    // Auth endpoints should return data directly, not wrapped in response object
    if (isAuthEndpoint) {
      return next.handle();
    }

    return next.handle().pipe(
      map(data => ({
        data,
        meta: {
          timestamp: new Date().toISOString(),
          requestId: request.headers['x-request-id'] as string || 'unknown',
          version: process.env.API_VERSION || 'v1',
        },
      })),
    );
  }
}
