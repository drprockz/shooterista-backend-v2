import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { GqlArgumentsHost, GqlExceptionFilter } from '@nestjs/graphql';
import { GraphQLError } from 'graphql';
import { FastifyRequest, FastifyReply } from 'fastify';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter, GqlExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  catch(exception: any, host: ArgumentsHost) {
    const hostType = host.getType<'http' | 'graphql'>();

    if (hostType === 'graphql') {
      return this.catchGraphQLException(exception, host);
    }

    return this.catchHttpException(exception, host);
  }

  private catchHttpException(exception: any, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<FastifyReply>();
    const request = ctx.getRequest<FastifyRequest>();

    const status = exception instanceof HttpException 
      ? exception.getStatus() 
      : HttpStatus.INTERNAL_SERVER_ERROR;

    const message = exception instanceof HttpException 
      ? exception.getResponse() 
      : 'Internal server error';

    const errorResponse = {
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      method: request.method,
      message: typeof message === 'string' ? message : (message as any).message,
      ...(process.env.NODE_ENV === 'development' && { stack: exception.stack }),
    };

    this.logger.error(
      `HTTP ${status} Error: ${JSON.stringify(errorResponse)}`,
      exception.stack,
    );

    // Use Fastify's reply methods
    response.status(status).send(errorResponse);
  }

  private catchGraphQLException(exception: any, host: ArgumentsHost) {
    const gqlHost = GqlArgumentsHost.create(host);
    const info = gqlHost.getInfo();
    const context = gqlHost.getContext();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Internal server error';
    let code = 'INTERNAL_ERROR';

    // Extract request ID from context
    const requestId = context?.requestContext?.requestId || context?.req?.headers?.['x-request-id'] || 'unknown';

    // Special handling for .url access errors
    if (exception instanceof TypeError && exception.message?.includes("Cannot read properties of undefined (reading 'url')")) {
      this.logger.error({
        event: 'url_access_error',
        requestId,
        operation: info.fieldName,
        path: info.path,
        error: {
          name: exception.name,
          message: exception.message,
          stack_present: !!exception.stack,
        },
        timestamp: new Date().toISOString()
      });
      
      message = 'Template processing error - logo configuration issue';
      code = 'TEMPLATE_ERROR';
    }

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const response = exception.getResponse();
      
      if (typeof response === 'object' && response !== null) {
        const responseObj = response as any;
        message = responseObj.message || 'Validation failed';
        
        // Handle detailed validation errors
        if (responseObj.field && responseObj.constraints) {
          return new GraphQLError(message, {
            extensions: {
              code: responseObj.code || this.getGraphQLErrorCode(status),
              field: responseObj.field,
              constraints: responseObj.constraints,
              status,
              requestId,
              timestamp: new Date().toISOString(),
              path: info.path,
              ...(process.env.NODE_ENV === 'development' && { 
                validationErrors: responseObj.validationErrors,
                exception: {
                  stacktrace: exception.stack?.split('\n'),
                }
              }),
            },
          });
        }
      } else {
        message = typeof response === 'string' ? response : 'Validation failed';
      }
      
      code = this.getGraphQLErrorCode(status);
    }

    this.logger.error({
      event: 'graphql_error',
      requestId,
      operation: info.fieldName,
      path: info.path,
      error: {
        name: exception.name,
        message: exception.message,
        stack_present: !!exception.stack,
      },
      timestamp: new Date().toISOString()
    });

    return new GraphQLError(message, {
      extensions: {
        code,
        status,
        requestId,
        timestamp: new Date().toISOString(),
        path: info.path,
        ...(process.env.NODE_ENV === 'development' && { 
          exception: {
            stacktrace: exception.stack?.split('\n'),
          }
        }),
      },
    });
  }

  private getGraphQLErrorCode(status: number): string {
    switch (status) {
      case HttpStatus.BAD_REQUEST:
        return 'BAD_USER_INPUT';
      case HttpStatus.UNAUTHORIZED:
        return 'UNAUTHENTICATED';
      case HttpStatus.FORBIDDEN:
        return 'FORBIDDEN';
      case HttpStatus.NOT_FOUND:
        return 'NOT_FOUND';
      case HttpStatus.CONFLICT:
        return 'CONFLICT';
      case HttpStatus.UNPROCESSABLE_ENTITY:
        return 'VALIDATION_ERROR';
      case HttpStatus.TOO_MANY_REQUESTS:
        return 'RATE_LIMITED';
      default:
        return 'INTERNAL_ERROR';
    }
  }
}
