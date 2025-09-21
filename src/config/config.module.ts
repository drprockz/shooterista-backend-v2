import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import configuration from './configuration';
import * as fs from 'fs';
import * as path from 'path';

// Determine environment file based on NODE_ENV
const getEnvFilePath = () => {
  const nodeEnv = process.env.NODE_ENV || 'development';
  
  let envFile: string;
  switch (nodeEnv) {
    case 'development':
      envFile = '.env.development';
      break;
    case 'production':
      envFile = '.env.production';
      break;
    case 'test':
      envFile = '.env.test';
      break;
    default:
      envFile = '.env';
  }
  
  // Verify the environment file exists
  const envPath = path.resolve(process.cwd(), envFile);
  if (!fs.existsSync(envPath)) {
    console.warn(`⚠️  Environment file ${envFile} not found. Falling back to .env`);
    return '.env';
  }
  
  console.log(`📁 Loading environment from: ${envFile}`);
  return envFile;
};

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      envFilePath: getEnvFilePath(),
    }),
  ],
})
export class AppConfigModule {}
