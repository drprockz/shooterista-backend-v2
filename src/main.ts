import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import fastifyHelmet from '@fastify/helmet';
import pino from 'pino';
import pinoHttp from 'pino-http';
import { v4 as uuid } from 'uuid';

async function bootstrap() {
  const logger = pino({ level: 'info' });
  const app = await NestFactory.create<NestFastifyApplication>(AppModule, new FastifyAdapter({ logger }));
  await app.register(fastifyHelmet as any);

  // request-id + pino-http
  app.use(pinoHttp({
    logger,
    genReqId: (req) => req.headers['x-request-id'] as string || uuid(),
    customProps: (req) => ({ tenant: req.headers['x-tenant-id'] || null }),
  }) as any);

  app.enableCors({ origin: true, credentials: true });
  await app.listen({ port: Number(process.env.PORT) || 4000, host: '0.0.0.0' });
}
bootstrap();
