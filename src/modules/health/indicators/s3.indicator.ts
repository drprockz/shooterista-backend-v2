import { Injectable } from '@nestjs/common';
import { HealthIndicator, HealthIndicatorResult, HealthCheckError } from '@nestjs/terminus';
import { ConfigService } from '@nestjs/config';
import { S3Client, HeadBucketCommand } from '@aws-sdk/client-s3';

@Injectable()
export class S3HealthIndicator extends HealthIndicator {
  private s3Client: S3Client;
  private bucketName: string;

  constructor(private readonly configService: ConfigService) {
    super();
    
    this.s3Client = new S3Client({
      region: this.configService.get<string>('app.S3_REGION'),
      endpoint: this.configService.get<string>('app.S3_ENDPOINT'),
      forcePathStyle: this.configService.get<boolean>('app.S3_FORCE_PATH_STYLE'),
      credentials: {
        accessKeyId: this.configService.get<string>('app.S3_ACCESS_KEY_ID'),
        secretAccessKey: this.configService.get<string>('app.S3_SECRET_ACCESS_KEY'),
      },
    });
    
    this.bucketName = this.configService.get<string>('app.S3_BUCKET_NAME');
  }

  async isHealthy(key: string): Promise<HealthIndicatorResult> {
    try {
      const command = new HeadBucketCommand({
        Bucket: this.bucketName,
      });
      
      await this.s3Client.send(command);
      
      return this.getStatus(key, true, {
        message: 'S3 connection is healthy',
        bucket: this.bucketName,
      });
    } catch (error) {
      const result = this.getStatus(key, false, {
        message: `S3 connection failed: ${error.message}`,
        bucket: this.bucketName,
      });
      throw new HealthCheckError(`${key} failed`, result);
    }
  }
}
