import { Injectable } from '@nestjs/common';
import { HealthIndicator, HealthIndicatorResult, HealthCheckError } from '@nestjs/terminus';
import { ConfigService } from '@nestjs/config';
import { PrismaClient as AuthPrismaClient } from '.prisma/auth';
import { PrismaClient as AthletesPrismaClient } from '.prisma/athletes';
import { PrismaClient as CompetitionsPrismaClient } from '.prisma/competitions';

@Injectable()
export class DatabaseHealthIndicator extends HealthIndicator {
  private authClient: AuthPrismaClient;
  private athletesClient: AthletesPrismaClient;
  private competitionsClient: CompetitionsPrismaClient;

  constructor(private readonly configService: ConfigService) {
    super();
    
    this.authClient = new AuthPrismaClient({
      datasources: {
        db: { url: this.configService.get<string>('app.AUTH_DB_URL') },
      },
    });

    this.athletesClient = new AthletesPrismaClient({
      datasources: {
        db: { url: this.configService.get<string>('app.ATHLETES_DB_URL') },
      },
    });

    this.competitionsClient = new CompetitionsPrismaClient({
      datasources: {
        db: { url: this.configService.get<string>('app.COMPETITIONS_DB_URL') },
      },
    });
  }

  async isHealthy(key: string): Promise<HealthIndicatorResult> {
    try {
      let client: any;
      
      switch (key) {
        case 'auth-database':
          client = this.authClient;
          break;
        case 'athletes-database':
          client = this.athletesClient;
          break;
        case 'competitions-database':
          client = this.competitionsClient;
          break;
        default:
          throw new Error(`Unknown database: ${key}`);
      }

      await client.$queryRaw`SELECT 1`;
      
      return this.getStatus(key, true, {
        message: 'Database connection is healthy',
      });
    } catch (error) {
      const result = this.getStatus(key, false, {
        message: `Database connection failed: ${error.message}`,
      });
      throw new HealthCheckError(`${key} failed`, result);
    }
  }
}
