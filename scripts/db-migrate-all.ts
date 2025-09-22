import { execSync } from 'node:child_process';
import * as dotenv from 'dotenv';
import * as path from 'path';

// Load environment variables from .env.development
const envPath = path.resolve(process.cwd(), '.env.development');
dotenv.config({ path: envPath });

const schemas = [
  { name: 'auth', path: 'src/prisma/auth/schema.prisma' },
  { name: 'tenant', path: 'src/prisma/tenant/schema.prisma' },
  { name: 'user', path: 'src/prisma/user/schema.prisma' },
  { name: 'athletes', path: 'src/prisma/athletes/schema.prisma' },
  { name: 'competitions', path: 'src/prisma/competitions/schema.prisma' },
];

console.log('🚀 Running database migrations for all schemas...\n');
console.log(`📁 Using environment file: ${envPath}\n`);

for (const schema of schemas) {
  try {
    console.log(`📦 Migrating ${schema.name} database...`);
    
    // Deploy existing migrations (avoids shadow database issues)
    console.log(`  🚀 Deploying migrations for ${schema.name}...`);
    execSync(`npx prisma migrate deploy --schema ${schema.path}`, {
      stdio: 'inherit',
      env: { ...process.env, FORCE_COLOR: '1' },
    });
    
    console.log(`✅ ${schema.name} migration completed\n`);
  } catch (error) {
    console.error(`❌ Failed to migrate ${schema.name} database:`, error.message);
    process.exit(1);
  }
}

console.log('🎉 All database migrations completed successfully!');
console.log('\n📋 Next steps:');
console.log('1. Run: npm run prisma:gen');
console.log('2. Start development: npm run dev');
