import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { FastifyRequest, FastifyReply } from 'fastify';
import { ConfigService } from '@nestjs/config';

export interface ErrorResponse {
  error: string;
  message: string;
  statusCode: number;
  timestamp: string;
  path: string;
  requestId?: string;
  code?: string;
  details?: any;
  stack?: string;
}

@Catch()
export class FastifyExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(FastifyExceptionFilter.name);

  constructor(private readonly configService: ConfigService) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<FastifyReply>();
    const request = ctx.getRequest<FastifyRequest>();

    const errorResponse = this.buildErrorResponse(exception, request);
    this.logError(exception, request, errorResponse);

    // Send response using Fastify's reply methods
    response.status(errorResponse.statusCode).send(errorResponse);
  }

  private buildErrorResponse(exception: unknown, request: FastifyRequest): ErrorResponse {
    const timestamp = new Date().toISOString();
    const path = request.url;
    const requestId = request.headers['x-request-id'] as string;

    // Handle HTTP exceptions
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const exceptionResponse = exception.getResponse();
      
      let message: string;
      let error: string;
      let code: string | undefined;
      let details: any;

      if (typeof exceptionResponse === 'string') {
        message = exceptionResponse;
        error = this.getErrorName(status);
      } else {
        const responseObj = exceptionResponse as any;
        message = responseObj.message || exception.message;
        error = responseObj.error || this.getErrorName(status);
        code = responseObj.code;
        details = responseObj.details;
      }

      return {
        error,
        message,
        statusCode: status,
        timestamp,
        path,
        requestId,
        code,
        details,
        stack: this.shouldIncludeStack() ? (exception as Error).stack : undefined,
      };
    }

    // Handle validation errors
    if (exception instanceof Error && exception.name === 'ValidationError') {
      return {
        error: 'Validation Error',
        message: exception.message,
        statusCode: HttpStatus.BAD_REQUEST,
        timestamp,
        path,
        requestId,
        code: 'VALIDATION_ERROR',
        stack: this.shouldIncludeStack() ? exception.stack : undefined,
      };
    }

    // Handle generic errors
    if (exception instanceof Error) {
      return {
        error: 'Internal Server Error',
        message: this.shouldExposeError() ? exception.message : 'An error occurred',
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        timestamp,
        path,
        requestId,
        code: 'INTERNAL_ERROR',
        stack: this.shouldIncludeStack() ? exception.stack : undefined,
      };
    }

    // Handle unknown exceptions
    return {
      error: 'Unknown Error',
      message: 'An unknown error occurred',
      statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
      timestamp,
      path,
      requestId,
      code: 'UNKNOWN_ERROR',
      stack: this.shouldIncludeStack() ? String(exception) : undefined,
    };
  }

  private getErrorName(status: number): string {
    switch (status) {
      case HttpStatus.BAD_REQUEST:
        return 'Bad Request';
      case HttpStatus.UNAUTHORIZED:
        return 'Unauthorized';
      case HttpStatus.FORBIDDEN:
        return 'Forbidden';
      case HttpStatus.NOT_FOUND:
        return 'Not Found';
      case HttpStatus.METHOD_NOT_ALLOWED:
        return 'Method Not Allowed';
      case HttpStatus.CONFLICT:
        return 'Conflict';
      case HttpStatus.UNPROCESSABLE_ENTITY:
        return 'Unprocessable Entity';
      case HttpStatus.TOO_MANY_REQUESTS:
        return 'Too Many Requests';
      case HttpStatus.INTERNAL_SERVER_ERROR:
        return 'Internal Server Error';
      case HttpStatus.BAD_GATEWAY:
        return 'Bad Gateway';
      case HttpStatus.SERVICE_UNAVAILABLE:
        return 'Service Unavailable';
      case HttpStatus.GATEWAY_TIMEOUT:
        return 'Gateway Timeout';
      default:
        return 'Error';
    }
  }

  private logError(exception: unknown, request: FastifyRequest, errorResponse: ErrorResponse): void {
    const { method, url, ip, headers } = request;
    const { statusCode, error, message, code } = errorResponse;

    const logContext = {
      method,
      url,
      ip,
      userAgent: headers['user-agent'],
      statusCode,
      error,
      message,
      code,
    };

    if (statusCode >= 500) {
      this.logger.error(
        `${method} ${url} - ${statusCode} ${error}: ${message}`,
        JSON.stringify(logContext),
      );
    } else if (statusCode >= 400) {
      this.logger.warn(
        `${method} ${url} - ${statusCode} ${error}: ${message}`,
        JSON.stringify(logContext),
      );
    } else {
      this.logger.log(
        `${method} ${url} - ${statusCode} ${error}: ${message}`,
        JSON.stringify(logContext),
      );
    }
  }

  private shouldIncludeStack(): boolean {
    return this.configService.get<string>('app.NODE_ENV') === 'development';
  }

  private shouldExposeError(): boolean {
    return this.configService.get<string>('app.NODE_ENV') === 'development';
  }
}
