#!/usr/bin/env ts-node

/**
 * Comprehensive Database Seeding Script
 * 
 * This script seeds all databases with minimal viable data for development:
 * - auth_db: Users, tenants, roles, permissions
 * - tenant_db: Tenant management data
 * - athletes_db: Athletes, competitions, basic entities
 * - competitions_db: Competition data
 * 
 * The script is idempotent and safe to run multiple times.
 */

import { PrismaClient as AuthPrismaClient } from '.prisma/auth';
import { PrismaClient as TenantPrismaClient } from '.prisma/tenant';
import { PrismaClient as AthletesPrismaClient } from '.prisma/athletes';
import { PrismaClient as CompetitionsPrismaClient } from '.prisma/competitions';
import * as argon2 from 'argon2';

// Initialize Prisma clients for each database
const authPrisma = new AuthPrismaClient();
const tenantPrisma = new TenantPrismaClient();
const athletesPrisma = new AthletesPrismaClient();
const competitionsPrisma = new CompetitionsPrismaClient();

// Seed data configuration
const SEED_CONFIG = {
  tenant: {
    id: 'clr1234567890abcdef',
    slug: 'club-x',
    name: 'Club X Shooting Range',
    email: 'admin@club-x.com',
    phone: '+1-555-0123',
    address: '123 Shooting Range Rd, Sports City, SC 12345',
  },
  adminUser: {
    email: 'admin@club-x.com',
    password: 'Admin123!', // Will be hashed
    firstName: 'Admin',
    lastName: 'User',
    userType: 'ADMIN' as const,
  },
  testUser: {
    email: 'test@club-x.com',
    password: 'Test123!', // Will be hashed
    firstName: 'Test',
    lastName: 'User',
    userType: 'ATHLETE' as const,
  },
  athletes: [
    {
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@club-x.com',
      dateOfBirth: new Date('1990-05-15'),
      gender: 'MALE' as const,
      country: 'USA',
      state: 'California',
      city: 'Los Angeles',
      phone: '+1-555-0101',
      handedness: 'RIGHT' as const,
      eyeDominance: 'RIGHT' as const,
      discipline: 'Air Rifle',
      classification: 'Senior',
    },
    {
      firstName: 'Jane',
      lastName: 'Smith',
      email: 'jane.smith@club-x.com',
      dateOfBirth: new Date('1995-08-22'),
      gender: 'FEMALE' as const,
      country: 'USA',
      state: 'Texas',
      city: 'Houston',
      phone: '+1-555-0102',
      handedness: 'LEFT' as const,
      eyeDominance: 'LEFT' as const,
      discipline: 'Air Pistol',
      classification: 'Senior',
    },
  ],
  competitions: [
    {
      name: 'Spring Championship 2024',
      description: 'Annual spring shooting championship',
      type: 'INDIVIDUAL' as const,
      discipline: 'Air Rifle',
      format: '60 Shots',
      rounds: 1,
      seriesPerRound: 6,
      shotsPerSeries: 10,
      startDate: new Date('2024-04-15T09:00:00Z'),
      endDate: new Date('2024-04-15T17:00:00Z'),
      timezone: 'America/Los_Angeles',
      venue: 'Club X Shooting Range',
      address: '123 Shooting Range Rd, Sports City, SC 12345',
      status: 'PUBLISHED' as const,
    },
  ],
};

async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 2 ** 16,
    timeCost: 3,
    parallelism: 1,
  });
}

async function seedAuthDatabase() {
  console.log('🌱 Seeding auth database...');
  
  try {
    // 1. Create tenant in auth_db (if not exists)
    const existingTenant = await authPrisma.user.findFirst({
      where: { tenantId: SEED_CONFIG.tenant.id }
    });
    
    if (!existingTenant) {
      console.log(`   Creating tenant context in auth_db: ${SEED_CONFIG.tenant.slug}`);
    }

    // 2. Create admin user
    const adminPassword = await hashPassword(SEED_CONFIG.adminUser.password);
    const adminUser = await authPrisma.user.upsert({
      where: { email: SEED_CONFIG.adminUser.email },
      update: {
        password: adminPassword,
        firstName: SEED_CONFIG.adminUser.firstName,
        lastName: SEED_CONFIG.adminUser.lastName,
        userType: SEED_CONFIG.adminUser.userType,
        tenantId: SEED_CONFIG.tenant.id,
        isEmailVerified: true,
        isFirstLogin: false,
        profileCompletion: 100,
        profileStatus: 'APPROVED',
        modulesUnlocked: true,
      },
      create: {
        email: SEED_CONFIG.adminUser.email,
        password: adminPassword,
        firstName: SEED_CONFIG.adminUser.firstName,
        lastName: SEED_CONFIG.adminUser.lastName,
        userType: SEED_CONFIG.adminUser.userType,
        tenantId: SEED_CONFIG.tenant.id,
        isEmailVerified: true,
        isFirstLogin: false,
        profileCompletion: 100,
        profileStatus: 'APPROVED',
        modulesUnlocked: true,
      },
    });

    // 3. Create test user
    const testPassword = await hashPassword(SEED_CONFIG.testUser.password);
    const testUser = await authPrisma.user.upsert({
      where: { email: SEED_CONFIG.testUser.email },
      update: {
        password: testPassword,
        firstName: SEED_CONFIG.testUser.firstName,
        lastName: SEED_CONFIG.testUser.lastName,
        userType: SEED_CONFIG.testUser.userType,
        tenantId: SEED_CONFIG.tenant.id,
        isEmailVerified: true,
        isFirstLogin: true,
        profileCompletion: 0,
        profileStatus: 'DRAFT',
        modulesUnlocked: false,
      },
      create: {
        email: SEED_CONFIG.testUser.email,
        password: testPassword,
        firstName: SEED_CONFIG.testUser.firstName,
        lastName: SEED_CONFIG.testUser.lastName,
        userType: SEED_CONFIG.testUser.userType,
        tenantId: SEED_CONFIG.tenant.id,
        isEmailVerified: true,
        isFirstLogin: true,
        profileCompletion: 0,
        profileStatus: 'DRAFT',
        modulesUnlocked: false,
      },
    });

    // 4. Create admin user profile
    await authPrisma.userProfile.upsert({
      where: { userId: adminUser.id },
      update: {
        personalData: {
          firstName: SEED_CONFIG.adminUser.firstName,
          lastName: SEED_CONFIG.adminUser.lastName,
          dateOfBirth: new Date('1985-01-01'),
          gender: 'MALE',
        },
        personalComplete: true,
        personalUpdatedAt: new Date(),
        contactData: {
          email: SEED_CONFIG.adminUser.email,
          phone: SEED_CONFIG.tenant.phone,
          address: SEED_CONFIG.tenant.address,
          city: 'Sports City',
          state: 'SC',
          country: 'USA',
          postalCode: '12345',
        },
        contactComplete: true,
        contactUpdatedAt: new Date(),
        educationData: {
          highestQualification: 'Bachelor',
          institution: 'Sports University',
          year: 2007,
        },
        educationComplete: true,
        educationUpdatedAt: new Date(),
        jobData: {
          occupation: 'Range Manager',
          company: SEED_CONFIG.tenant.name,
          role: 'Administrator',
          experienceYears: 10,
        },
        jobComplete: true,
        jobUpdatedAt: new Date(),
        eventData: {
          primaryDiscipline: 'Air Rifle',
          experienceLevel: 'Expert',
          federationId: 'USA-SHOOTING',
        },
        eventComplete: true,
        eventUpdatedAt: new Date(),
        submittedAt: new Date(),
        approvedAt: new Date(),
        approvedBy: adminUser.id,
      },
      create: {
        userId: adminUser.id,
        personalData: {
          firstName: SEED_CONFIG.adminUser.firstName,
          lastName: SEED_CONFIG.adminUser.lastName,
          dateOfBirth: new Date('1985-01-01'),
          gender: 'MALE',
        },
        personalComplete: true,
        personalUpdatedAt: new Date(),
        contactData: {
          email: SEED_CONFIG.adminUser.email,
          phone: SEED_CONFIG.tenant.phone,
          address: SEED_CONFIG.tenant.address,
          city: 'Sports City',
          state: 'SC',
          country: 'USA',
          postalCode: '12345',
        },
        contactComplete: true,
        contactUpdatedAt: new Date(),
        educationData: {
          highestQualification: 'Bachelor',
          institution: 'Sports University',
          year: 2007,
        },
        educationComplete: true,
        educationUpdatedAt: new Date(),
        jobData: {
          occupation: 'Range Manager',
          company: SEED_CONFIG.tenant.name,
          role: 'Administrator',
          experienceYears: 10,
        },
        jobComplete: true,
        jobUpdatedAt: new Date(),
        eventData: {
          primaryDiscipline: 'Air Rifle',
          experienceLevel: 'Expert',
          federationId: 'USA-SHOOTING',
        },
        eventComplete: true,
        eventUpdatedAt: new Date(),
        submittedAt: new Date(),
        approvedAt: new Date(),
        approvedBy: adminUser.id,
      },
    });

    console.log(`   ✅ Created admin user: ${adminUser.email} (ID: ${adminUser.id})`);
    console.log(`   ✅ Created test user: ${testUser.email} (ID: ${testUser.id})`);
    
    return { adminUser, testUser };
  } catch (error) {
    console.error('❌ Error seeding auth database:', error);
    throw error;
  }
}

async function seedTenantDatabase() {
  console.log('🌱 Seeding tenant database...');
  
  try {
    // Create tenant
    const tenant = await tenantPrisma.tenant.upsert({
      where: { slug: SEED_CONFIG.tenant.slug },
      update: {
        name: SEED_CONFIG.tenant.name,
        description: 'Premier shooting range and training facility',
        email: SEED_CONFIG.tenant.email,
        phone: SEED_CONFIG.tenant.phone,
        address: SEED_CONFIG.tenant.address,
        website: 'https://club-x.com',
        logo: 'https://placehold.co/200x60/3B82F6/FFFFFF?text=Club+X',
        settings: {
          features: {
            profileCompletionRequired: true,
            profileApprovalRequired: true,
            minProfileCompletionPercentage: 80,
            otpEmailRequiredForRegister: true,
          },
          branding: {
            primaryColor: '#3B82F6',
            secondaryColor: '#1E40AF',
            logoUrl: 'https://placehold.co/200x60/3B82F6/FFFFFF?text=Club+X',
          },
        },
        isActive: true,
      },
      create: {
        id: SEED_CONFIG.tenant.id,
        slug: SEED_CONFIG.tenant.slug,
        name: SEED_CONFIG.tenant.name,
        description: 'Premier shooting range and training facility',
        email: SEED_CONFIG.tenant.email,
        phone: SEED_CONFIG.tenant.phone,
        address: SEED_CONFIG.tenant.address,
        website: 'https://club-x.com',
        logo: 'https://placehold.co/200x60/3B82F6/FFFFFF?text=Club+X',
        settings: {
          features: {
            profileCompletionRequired: true,
            profileApprovalRequired: true,
            minProfileCompletionPercentage: 80,
            otpEmailRequiredForRegister: true,
          },
          branding: {
            primaryColor: '#3B82F6',
            secondaryColor: '#1E40AF',
            logoUrl: 'https://placehold.co/200x60/3B82F6/FFFFFF?text=Club+X',
          },
        },
        isActive: true,
      },
    });

    // Create tenant roles
    const adminRole = await tenantPrisma.tenantRole.upsert({
      where: { 
        tenantId_name: { 
          tenantId: tenant.id, 
          name: 'ADMIN' 
        } 
      },
      update: {
        description: 'Administrator with full access',
        permissions: [
          'users:read', 'users:write', 'users:delete',
          'athletes:read', 'athletes:write', 'athletes:delete',
          'competitions:read', 'competitions:write', 'competitions:delete',
          'profiles:read', 'profiles:write', 'profiles:approve',
          'settings:read', 'settings:write',
        ],
        isActive: true,
      },
      create: {
        tenantId: tenant.id,
        name: 'ADMIN',
        description: 'Administrator with full access',
        permissions: [
          'users:read', 'users:write', 'users:delete',
          'athletes:read', 'athletes:write', 'athletes:delete',
          'competitions:read', 'competitions:write', 'competitions:delete',
          'profiles:read', 'profiles:write', 'profiles:approve',
          'settings:read', 'settings:write',
        ],
        isActive: true,
      },
    });

    const athleteRole = await tenantPrisma.tenantRole.upsert({
      where: { 
        tenantId_name: { 
          tenantId: tenant.id, 
          name: 'ATHLETE' 
        } 
      },
      update: {
        description: 'Athlete with basic access',
        permissions: [
          'profile:read', 'profile:write',
          'competitions:read',
          'scores:read', 'scores:write',
        ],
        isActive: true,
      },
      create: {
        tenantId: tenant.id,
        name: 'ATHLETE',
        description: 'Athlete with basic access',
        permissions: [
          'profile:read', 'profile:write',
          'competitions:read',
          'scores:read', 'scores:write',
        ],
        isActive: true,
      },
    });

    console.log(`   ✅ Created tenant: ${tenant.name} (ID: ${tenant.id})`);
    console.log(`   ✅ Created roles: ${adminRole.name}, ${athleteRole.name}`);
    
    return { tenant, adminRole, athleteRole };
  } catch (error) {
    console.error('❌ Error seeding tenant database:', error);
    throw error;
  }
}

async function seedAthletesDatabase(tenantId: string) {
  console.log('🌱 Seeding athletes database...');
  
  try {
    // Create tenant in athletes DB
    const tenant = await athletesPrisma.tenant.upsert({
      where: { slug: SEED_CONFIG.tenant.slug },
      update: {
        name: SEED_CONFIG.tenant.name,
        description: 'Premier shooting range and training facility',
        email: SEED_CONFIG.tenant.email,
        phone: SEED_CONFIG.tenant.phone,
        address: SEED_CONFIG.tenant.address,
        website: 'https://club-x.com',
        logo: 'https://placehold.co/200x60/3B82F6/FFFFFF?text=Club+X',
        isActive: true,
      },
      create: {
        id: BigInt(parseInt(tenantId.slice(-8), 16)), // Convert tenant ID to BigInt
        slug: SEED_CONFIG.tenant.slug,
        name: SEED_CONFIG.tenant.name,
        description: 'Premier shooting range and training facility',
        email: SEED_CONFIG.tenant.email,
        phone: SEED_CONFIG.tenant.phone,
        address: SEED_CONFIG.tenant.address,
        website: 'https://club-x.com',
        logo: 'https://placehold.co/200x60/3B82F6/FFFFFF?text=Club+X',
        isActive: true,
      },
    });

    // Create athletes
    const athletes = [];
    for (const athleteData of SEED_CONFIG.athletes) {
      const athlete = await athletesPrisma.athlete.upsert({
        where: { 
          tenantId_email: { 
            tenantId: tenant.id, 
            email: athleteData.email 
          } 
        },
        update: {
          firstName: athleteData.firstName,
          lastName: athleteData.lastName,
          dateOfBirth: athleteData.dateOfBirth,
          gender: athleteData.gender,
          country: athleteData.country,
          state: athleteData.state,
          city: athleteData.city,
          phone: athleteData.phone,
          handedness: athleteData.handedness,
          eyeDominance: athleteData.eyeDominance,
          discipline: athleteData.discipline,
          classification: athleteData.classification,
          bio: `Experienced ${athleteData.discipline} athlete`,
          isActive: true,
        },
        create: {
          tenantId: tenant.id,
          firstName: athleteData.firstName,
          lastName: athleteData.lastName,
          email: athleteData.email,
          dateOfBirth: athleteData.dateOfBirth,
          gender: athleteData.gender,
          country: athleteData.country,
          state: athleteData.state,
          city: athleteData.city,
          phone: athleteData.phone,
          handedness: athleteData.handedness,
          eyeDominance: athleteData.eyeDominance,
          discipline: athleteData.discipline,
          classification: athleteData.classification,
          bio: `Experienced ${athleteData.discipline} athlete`,
          isActive: true,
        },
      });
      athletes.push(athlete);
    }

    // Create memberships
    for (const athlete of athletes) {
      await athletesPrisma.membership.upsert({
        where: { 
          tenantId_athleteId: { 
            tenantId: tenant.id, 
            athleteId: athlete.id 
          } 
        },
        update: {
          role: 'MEMBER',
          status: 'ACTIVE',
        },
        create: {
          tenantId: tenant.id,
          athleteId: athlete.id,
          role: 'MEMBER',
          status: 'ACTIVE',
        },
      });
    }

    console.log(`   ✅ Created ${athletes.length} athletes`);
    console.log(`   ✅ Created ${athletes.length} memberships`);
    
    return { tenant, athletes };
  } catch (error) {
    console.error('❌ Error seeding athletes database:', error);
    throw error;
  }
}

async function seedCompetitionsDatabase(tenantId: string) {
  console.log('🌱 Seeding competitions database...');
  
  try {
    // Create competitions
    const competitions = [];
    for (const compData of SEED_CONFIG.competitions) {
      // Check if competition already exists
      const existingCompetition = await competitionsPrisma.competition.findFirst({
        where: {
          tenantId: BigInt(parseInt(tenantId.slice(-8), 16)),
          name: compData.name
        }
      });

      let competition;
      if (existingCompetition) {
        // Update existing competition
        competition = await competitionsPrisma.competition.update({
          where: { id: existingCompetition.id },
          data: {
            description: compData.description,
            type: compData.type,
            discipline: compData.discipline,
            format: compData.format,
            roundCount: compData.rounds,
            seriesPerRound: compData.seriesPerRound,
            shotsPerSeries: compData.shotsPerSeries,
            startDate: compData.startDate,
            endDate: compData.endDate,
            timezone: compData.timezone,
            venue: compData.venue,
            address: compData.address,
            status: compData.status,
            visibility: 'PUBLIC',
            registrationOpen: new Date('2024-03-01T00:00:00Z'),
            registrationClose: new Date('2024-04-10T23:59:59Z'),
            maxParticipants: 50,
            registrationFee: 25.00,
          }
        });
      } else {
        // Create new competition
        competition = await competitionsPrisma.competition.create({
          data: {
            tenantId: BigInt(parseInt(tenantId.slice(-8), 16)),
            name: compData.name,
            description: compData.description,
            type: compData.type,
            discipline: compData.discipline,
            format: compData.format,
            roundCount: compData.rounds,
            seriesPerRound: compData.seriesPerRound,
            shotsPerSeries: compData.shotsPerSeries,
            startDate: compData.startDate,
            endDate: compData.endDate,
            timezone: compData.timezone,
            venue: compData.venue,
            address: compData.address,
            status: compData.status,
            visibility: 'PUBLIC',
            registrationOpen: new Date('2024-03-01T00:00:00Z'),
            registrationClose: new Date('2024-04-10T23:59:59Z'),
            maxParticipants: 50,
            registrationFee: 25.00,
          }
        });
      }
      competitions.push(competition);
    }

    console.log(`   ✅ Created ${competitions.length} competitions`);
    
    return { competitions };
  } catch (error) {
    console.error('❌ Error seeding competitions database:', error);
    throw error;
  }
}

async function runMigrations() {
  console.log('🔄 Running database migrations...');
  
  try {
    // Note: In a real implementation, you would run Prisma migrations here
    // For now, we'll assume migrations are already applied
    console.log('   ✅ Migrations assumed to be applied');
  } catch (error) {
    console.error('❌ Error running migrations:', error);
    throw error;
  }
}

async function main() {
  console.log('🚀 Starting comprehensive database seeding...');
  console.log('=' .repeat(60));
  
  try {
    // Run migrations first
    await runMigrations();
    
    // Seed databases in order
    const { adminUser, testUser } = await seedAuthDatabase();
    const { tenant, adminRole, athleteRole } = await seedTenantDatabase();
    const { athletes } = await seedAthletesDatabase(tenant.id);
    const { competitions } = await seedCompetitionsDatabase(tenant.id);
    
    console.log('=' .repeat(60));
    console.log('✅ Seeding completed successfully!');
    console.log('');
    console.log('📊 Summary:');
    console.log(`   Tenant: ${tenant.name} (${tenant.slug})`);
    console.log(`   Admin User: ${adminUser.email} (ID: ${adminUser.id})`);
    console.log(`   Test User: ${testUser.email} (ID: ${testUser.id})`);
    console.log(`   Athletes: ${athletes.length}`);
    console.log(`   Competitions: ${competitions.length}`);
    console.log('');
    console.log('🔑 Test Credentials:');
    console.log(`   Admin: ${adminUser.email} / ${SEED_CONFIG.adminUser.password}`);
    console.log(`   Test: ${testUser.email} / ${SEED_CONFIG.testUser.password}`);
    console.log('');
    console.log('🌐 Tenant Resolution:');
    console.log(`   Slug: ${tenant.slug}`);
    console.log(`   ID: ${tenant.id}`);
    console.log(`   Override Mode: Set TENANT_RESOLUTION_MODE=env`);
    console.log(`   Override Slug: Set TENANT_OVERRIDE_SLUG=${tenant.slug}`);
    
  } catch (error) {
    console.error('❌ Seeding failed:', error);
    process.exit(1);
  } finally {
    await authPrisma.$disconnect();
    await tenantPrisma.$disconnect();
    await athletesPrisma.$disconnect();
    await competitionsPrisma.$disconnect();
  }
}

// Run the seeding script
if (require.main === module) {
  main().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

export { main as seedAllDatabases };
