import { execSync } from 'node:child_process';

const schemas = [
  { name: 'auth', path: 'src/prisma/auth/schema.prisma' },
  { name: 'athletes', path: 'src/prisma/athletes/schema.prisma' },
  { name: 'competitions', path: 'src/prisma/competitions/schema.prisma' },
];

console.log('🚀 Running database migrations for all schemas...\n');

for (const schema of schemas) {
  try {
    console.log(`📦 Migrating ${schema.name} database...`);
    
    // Create migration
    execSync(`npx prisma migrate dev --schema ${schema.path} --name init`, {
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
