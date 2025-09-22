import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RbacService } from './rbac.service';
import { PrismaAuthService } from '../prisma-auth.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class InitializationService implements OnModuleInit {
  private readonly logger = new Logger(InitializationService.name);

  constructor(
    private readonly rbacService: RbacService,
    private readonly prismaAuth: PrismaAuthService,
    private readonly configService: ConfigService,
  ) {}

  async onModuleInit() {
    this.logger.log('Initializing authentication system...');
    
    try {
      // Initialize default roles and permissions
      await this.initializeDefaultRoles();
      
      // Create super admin user if it doesn't exist
      await this.createSuperAdminUser();
      
      // Clean up expired data
      await this.cleanupExpiredData();
      
      this.logger.log('Authentication system initialized successfully');
    } catch (error) {
      this.logger.error('Failed to initialize authentication system', error);
      throw error;
    }
  }

  private async initializeDefaultRoles(): Promise<void> {
    this.logger.log('Initializing default roles and permissions...');
    await this.rbacService.initializeDefaultRoles();
  }

  private async createSuperAdminUser(): Promise<void> {
    const superAdminEmail = this.configService.get<string>('app.SUPER_ADMIN_EMAIL');
    const superAdminPassword = this.configService.get<string>('app.SUPER_ADMIN_PASSWORD');
    
    if (!superAdminEmail || !superAdminPassword) {
      this.logger.warn('Super admin credentials not provided, skipping super admin creation');
      return;
    }

    try {
      // Check if super admin already exists
      const existingUser = await this.prismaAuth.findUserByEmail(superAdminEmail);
      if (existingUser) {
        this.logger.log('Super admin user already exists');
        return;
      }

      // Create super admin user
      const user = await this.prismaAuth.createUser({
        email: superAdminEmail,
        password: superAdminPassword,
        firstName: 'Super',
        lastName: 'Admin',
      });

      // Get super admin role
      const superAdminRole = await this.prismaAuth.findRoleByName('super_admin');
      if (!superAdminRole) {
        this.logger.error('Super admin role not found');
        return;
      }

      // Assign super admin role
      await this.prismaAuth.assignRoleToUser({
        userId: user.id,
        roleId: superAdminRole.id,
      });

      // Mark email as verified and activate account
      await this.prismaAuth.updateUser(user.id, {
        isEmailVerified: true,
        status: 'ACTIVE' as any,
      });

      this.logger.log('Super admin user created successfully');
    } catch (error) {
      this.logger.error('Failed to create super admin user', error);
    }
  }

  private async cleanupExpiredData(): Promise<void> {
    this.logger.log('Cleaning up expired data...');
    await this.prismaAuth.cleanupExpiredData();
    this.logger.log('Expired data cleanup completed');
  }
}
