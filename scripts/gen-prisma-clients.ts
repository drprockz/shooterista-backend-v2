import { execSync } from 'node:child_process';
const schemas = [
  'src/prisma/auth/schema.prisma',
  'src/prisma/tenant/schema.prisma',
  'src/prisma/user/schema.prisma',
  'src/prisma/athletes/schema.prisma',
  'src/prisma/competitions/schema.prisma',
];
for (const s of schemas) {
  console.log('Generating Prisma for', s);
  execSync(`npx prisma generate --schema ${s}`, { stdio: 'inherit' });
}
