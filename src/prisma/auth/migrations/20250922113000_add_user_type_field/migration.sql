-- Create UserType enum
CREATE TYPE "UserType" AS ENUM ('SUPERADMIN', 'ADMIN', 'ATHLETE');

-- Add userType field to users table
ALTER TABLE "users" ADD COLUMN "userType" "UserType" NOT NULL DEFAULT 'ATHLETE';

-- Add indexes for the new field
CREATE INDEX "users_userType_idx" ON "users"("userType");
CREATE INDEX "users_tenantId_idx" ON "users"("tenantId");
