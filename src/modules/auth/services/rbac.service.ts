import { Injectable, Logger } from '@nestjs/common';
import { PrismaAuthService } from '../prisma-auth.service';
import { Role, Permission } from '../dto/auth.types';

export interface RoleBundle {
  name: string;
  description: string;
  permissions: string[]; // Array of permission names
  tenantId?: string;
}

@Injectable()
export class RbacService {
  private readonly logger = new Logger(RbacService.name);

  constructor(private readonly prismaAuth: PrismaAuthService) {}

  // Initialize default roles and permissions
  async initializeDefaultRoles(): Promise<void> {
    this.logger.log('Initializing default roles and permissions...');

    // Define default permissions
    const defaultPermissions = [
      // User permissions
      { name: 'user:create', description: 'Create users', resource: 'user', action: 'create' },
      { name: 'user:read', description: 'Read user information', resource: 'user', action: 'read' },
      { name: 'user:update', description: 'Update user information', resource: 'user', action: 'update' },
      { name: 'user:delete', description: 'Delete users', resource: 'user', action: 'delete' },
      
      // Admin permissions
      { name: 'admin:access', description: 'Access admin panel', resource: 'admin', action: 'access' },
      { name: 'admin:manage_users', description: 'Manage all users', resource: 'admin', action: 'manage_users' },
      { name: 'admin:manage_roles', description: 'Manage roles and permissions', resource: 'admin', action: 'manage_roles' },
      { name: 'admin:view_audit_logs', description: 'View audit logs', resource: 'admin', action: 'view_audit_logs' },
      
      // Competition permissions
      { name: 'competition:create', description: 'Create competitions', resource: 'competition', action: 'create' },
      { name: 'competition:read', description: 'Read competition information', resource: 'competition', action: 'read' },
      { name: 'competition:update', description: 'Update competitions', resource: 'competition', action: 'update' },
      { name: 'competition:delete', description: 'Delete competitions', resource: 'competition', action: 'delete' },
      { name: 'competition:manage', description: 'Manage competitions', resource: 'competition', action: 'manage' },
      
      // Athlete permissions
      { name: 'athlete:create', description: 'Create athletes', resource: 'athlete', action: 'create' },
      { name: 'athlete:read', description: 'Read athlete information', resource: 'athlete', action: 'read' },
      { name: 'athlete:update', description: 'Update athletes', resource: 'athlete', action: 'update' },
      { name: 'athlete:delete', description: 'Delete athletes', resource: 'athlete', action: 'delete' },
      { name: 'athlete:manage', description: 'Manage athletes', resource: 'athlete', action: 'manage' },
      
      // Audit permissions
      { name: 'audit:read', description: 'Read audit logs', resource: 'audit', action: 'read' },
      { name: 'audit:export', description: 'Export audit logs', resource: 'audit', action: 'export' },
      
      // Session permissions
      { name: 'session:read', description: 'View sessions', resource: 'session', action: 'read' },
      { name: 'session:revoke', description: 'Revoke sessions', resource: 'session', action: 'revoke' },
      { name: 'session:manage', description: 'Manage sessions', resource: 'session', action: 'manage' },
    ];

    // Create permissions
    for (const perm of defaultPermissions) {
      await this.createPermissionIfNotExists(perm);
    }

    // Define role bundles
    const roleBundles: RoleBundle[] = [
      {
        name: 'super_admin',
        description: 'Super Administrator with full system access',
        permissions: [
          'user:create', 'user:read', 'user:update', 'user:delete',
          'admin:access', 'admin:manage_users', 'admin:manage_roles', 'admin:view_audit_logs',
          'competition:create', 'competition:read', 'competition:update', 'competition:delete', 'competition:manage',
          'athlete:create', 'athlete:read', 'athlete:update', 'athlete:delete', 'athlete:manage',
          'audit:read', 'audit:export',
          'session:read', 'session:revoke', 'session:manage',
        ],
      },
      {
        name: 'admin',
        description: 'Administrator with management access',
        permissions: [
          'user:create', 'user:read', 'user:update',
          'admin:access', 'admin:manage_users',
          'competition:create', 'competition:read', 'competition:update', 'competition:manage',
          'athlete:create', 'athlete:read', 'athlete:update', 'athlete:manage',
          'audit:read',
          'session:read', 'session:revoke',
        ],
      },
      {
        name: 'competition_manager',
        description: 'Competition Manager with competition and athlete management',
        permissions: [
          'user:read',
          'competition:create', 'competition:read', 'competition:update', 'competition:manage',
          'athlete:create', 'athlete:read', 'athlete:update', 'athlete:manage',
          'session:read',
        ],
      },
      {
        name: 'athlete_manager',
        description: 'Athlete Manager with athlete management access',
        permissions: [
          'user:read',
          'competition:read',
          'athlete:create', 'athlete:read', 'athlete:update', 'athlete:manage',
          'session:read',
        ],
      },
      {
        name: 'judge',
        description: 'Competition Judge with read access to competitions and athletes',
        permissions: [
          'competition:read',
          'athlete:read',
        ],
      },
      {
        name: 'athlete',
        description: 'Athlete with limited access to own data',
        permissions: [
          'athlete:read', // Only own athlete record
        ],
      },
      {
        name: 'spectator',
        description: 'Spectator with read-only access to public data',
        permissions: [
          'competition:read',
          'athlete:read',
        ],
      },
    ];

    // Create roles and assign permissions
    for (const bundle of roleBundles) {
      await this.createRoleBundleInternal(bundle);
    }

    this.logger.log('Default roles and permissions initialized successfully');
  }

  private async createPermissionIfNotExists(permission: {
    name: string;
    description: string;
    resource: string;
    action: string;
  }): Promise<void> {
    const existing = await this.prismaAuth.permission.findFirst({
      where: { name: permission.name },
    });

    if (!existing) {
      await this.prismaAuth.permission.create({
        data: {
          name: permission.name,
          description: permission.description,
          resource: permission.resource,
          action: permission.action,
        },
      });
      this.logger.log(`Created permission: ${permission.name}`);
    }
  }

  private async createRoleBundleInternal(bundle: RoleBundle): Promise<void> {
    // Create role if it doesn't exist
    let role = await this.prismaAuth.role.findFirst({
      where: { 
        name: bundle.name,
        tenantId: bundle.tenantId,
      },
    });

    if (!role) {
      role = await this.prismaAuth.role.create({
        data: {
          name: bundle.name,
          description: bundle.description,
          tenantId: bundle.tenantId,
        },
      });
      this.logger.log(`Created role: ${bundle.name}`);
    }

    // Get all permissions for this role
    const permissions = await this.prismaAuth.permission.findMany({
      where: {
        name: { in: bundle.permissions },
      },
    });

    // Assign permissions to role
    for (const permission of permissions) {
      const existing = await this.prismaAuth.rolePermission.findFirst({
        where: {
          roleId: role.id,
          permissionId: permission.id,
        },
      });

      if (!existing) {
        await this.prismaAuth.rolePermission.create({
          data: {
            roleId: role.id,
            permissionId: permission.id,
          },
        });
      }
    }

    this.logger.log(`Assigned ${permissions.length} permissions to role: ${bundle.name}`);
  }

  // Create a new role bundle
  async createRoleBundle(bundle: RoleBundle): Promise<Role> {
    const role = await this.prismaAuth.role.create({
      data: {
        name: bundle.name,
        description: bundle.description,
        tenantId: bundle.tenantId,
      },
    });

    // Get permissions
    const permissions = await this.prismaAuth.permission.findMany({
      where: {
        name: { in: bundle.permissions },
      },
    });

    // Assign permissions
    for (const permission of permissions) {
      await this.prismaAuth.rolePermission.create({
        data: {
          roleId: role.id,
          permissionId: permission.id,
        },
      });
    }

    this.logger.log(`Created role bundle: ${bundle.name} with ${permissions.length} permissions`);

    return this.mapRoleToGraphQL(role);
  }

  // Update role bundle
  async updateRoleBundle(roleId: number, bundle: Partial<RoleBundle>): Promise<Role> {
    const role = await this.prismaAuth.role.findUnique({
      where: { id: roleId },
    });

    if (!role) {
      throw new Error('Role not found');
    }

    // Update role details
    const updatedRole = await this.prismaAuth.role.update({
      where: { id: roleId },
      data: {
        name: bundle.name,
        description: bundle.description,
      },
    });

    // Update permissions if provided
    if (bundle.permissions) {
      // Remove all existing permissions
      await this.prismaAuth.rolePermission.deleteMany({
        where: { roleId },
      });

      // Add new permissions
      const permissions = await this.prismaAuth.permission.findMany({
        where: {
          name: { in: bundle.permissions },
        },
      });

      for (const permission of permissions) {
        await this.prismaAuth.rolePermission.create({
          data: {
            roleId,
            permissionId: permission.id,
          },
        });
      }
    }

    this.logger.log(`Updated role bundle: ${updatedRole.name}`);

    return this.mapRoleToGraphQL(updatedRole);
  }

  // Get all roles
  async getRoles(tenantId?: string): Promise<Role[]> {
    const roles = await this.prismaAuth.role.findMany({
      where: {
        ...(tenantId && { tenantId }),
        isActive: true,
      },
      include: {
        rolePermissions: {
          include: {
            permission: true,
          },
        },
      },
      orderBy: { name: 'asc' },
    });

    return roles.map(role => this.mapRoleToGraphQL(role));
  }

  // Get all permissions
  async getPermissions(): Promise<Permission[]> {
    const permissions = await this.prismaAuth.permission.findMany({
      where: { isActive: true },
      orderBy: [{ resource: 'asc' }, { action: 'asc' }],
    });

    return permissions.map(permission => this.mapPermissionToGraphQL(permission));
  }

  // Get user's effective permissions
  async getUserEffectivePermissions(userId: number, tenantId?: string): Promise<Permission[]> {
    const permissions = await this.prismaAuth.getUserPermissions(userId, tenantId);
    return permissions.map(permission => this.mapPermissionToGraphQL(permission));
  }

  // Check if user has specific permission
  async hasPermission(
    userId: number, 
    resource: string, 
    action: string, 
    tenantId?: string
  ): Promise<boolean> {
    return this.prismaAuth.checkUserPermission(userId, resource, action, tenantId);
  }

  // Get permission matrix for a user
  async getUserPermissionMatrix(userId: number, tenantId?: string): Promise<{
    roles: Role[];
    permissions: Permission[];
    matrix: { [resource: string]: { [action: string]: boolean } };
  }> {
    const [roles, permissions] = await Promise.all([
      this.prismaAuth.getUserRoles(userId, tenantId).then(roles => 
        roles.map(role => this.mapRoleToGraphQL(role.role))
      ),
      this.getUserEffectivePermissions(userId, tenantId),
    ]);

    // Build permission matrix
    const matrix: { [resource: string]: { [action: string]: boolean } } = {};
    
    for (const permission of permissions) {
      if (!matrix[permission.resource]) {
        matrix[permission.resource] = {};
      }
      matrix[permission.resource][permission.action] = true;
    }

    return { roles, permissions, matrix };
  }

  // Helper method to map role to GraphQL
  private mapRoleToGraphQL(role: any): Role {
    return {
      id: role.id.toString(),
      name: role.name,
      description: role.description,
      isActive: role.isActive,
      tenantId: role.tenantId,
      createdAt: role.createdAt,
      updatedAt: role.updatedAt,
      permissions: role.rolePermissions?.map((rp: any) => this.mapPermissionToGraphQL(rp.permission)) || [],
    };
  }

  // Helper method to map permission to GraphQL
  private mapPermissionToGraphQL(permission: any): Permission {
    return {
      id: permission.id.toString(),
      name: permission.name,
      description: permission.description,
      resource: permission.resource,
      action: permission.action,
      isActive: permission.isActive,
      createdAt: permission.createdAt,
      updatedAt: permission.updatedAt,
    };
  }
}
