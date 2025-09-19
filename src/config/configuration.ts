import { registerAs } from '@nestjs/config';
import { z } from 'zod';

const schema = z.object({
  PORT: z.coerce.number().default(4000),
  REDIS_URL: z.string(),
  AUTH_DB_URL: z.string(),
  ATHLETES_DB_URL: z.string(),
  COMPETITIONS_DB_URL: z.string(),
});

export default registerAs('app', () => {
  const parsed = schema.safeParse(process.env);
  if (!parsed.success) throw new Error(parsed.error.message);
  return parsed.data;
});
