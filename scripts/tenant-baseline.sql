-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "public"."PlanType" AS ENUM ('FREE', 'BASIC', 'PREMIUM', 'ENTERPRISE', 'CUSTOM');

-- CreateEnum
CREATE TYPE "public"."TenantUserRole" AS ENUM ('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER');

-- CreateEnum
CREATE TYPE "public"."MembershipStatus" AS ENUM ('ACTIVE', 'INACTIVE', 'SUSPENDED', 'PENDING');

-- CreateEnum
CREATE TYPE "public"."SubscriptionStatus" AS ENUM ('ACTIVE', 'CANCELLED', 'EXPIRED', 'PENDING', 'SUSPENDED');

-- CreateEnum
CREATE TYPE "public"."BillingCycle" AS ENUM ('MONTHLY', 'QUARTERLY', 'YEARLY');

-- CreateEnum
CREATE TYPE "public"."InvitationStatus" AS ENUM ('PENDING', 'ACCEPTED', 'EXPIRED', 'CANCELLED');

-- CreateTable
CREATE TABLE "public"."tenants" (
    "id" TEXT NOT NULL,
    "name" VARCHAR(200) NOT NULL,
    "slug" VARCHAR(100) NOT NULL,
    "description" TEXT,
    "logo" VARCHAR(500),
    "website" VARCHAR(255),
    "email" VARCHAR(255),
    "phone" VARCHAR(20),
    "address" TEXT,
    "settings" JSONB,
    "timezone" VARCHAR(50) NOT NULL DEFAULT 'UTC',
    "currency" VARCHAR(3) NOT NULL DEFAULT 'USD',
    "planType" "public"."PlanType" NOT NULL DEFAULT 'FREE',
    "planExpiry" TIMESTAMP(3),
    "databaseUrl" VARCHAR(500),
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "tenants_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."tenant_users" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "userId" INTEGER NOT NULL,
    "role" "public"."TenantUserRole" NOT NULL DEFAULT 'MEMBER',
    "status" "public"."MembershipStatus" NOT NULL DEFAULT 'ACTIVE',
    "permissions" JSONB,
    "joinedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "leftAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "tenant_users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."tenant_roles" (
    "id" SERIAL NOT NULL,
    "tenantId" TEXT NOT NULL,
    "name" VARCHAR(100) NOT NULL,
    "description" TEXT,
    "permissions" JSONB NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "tenant_roles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."tenant_role_assignments" (
    "id" SERIAL NOT NULL,
    "tenantUserId" TEXT NOT NULL,
    "roleId" INTEGER NOT NULL,
    "assignedBy" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "tenant_role_assignments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."tenant_subscriptions" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "planType" "public"."PlanType" NOT NULL,
    "status" "public"."SubscriptionStatus" NOT NULL DEFAULT 'ACTIVE',
    "startDate" TIMESTAMP(3) NOT NULL,
    "endDate" TIMESTAMP(3),
    "renewalDate" TIMESTAMP(3),
    "billingCycle" "public"."BillingCycle" NOT NULL DEFAULT 'MONTHLY',
    "amount" DECIMAL(10,2) NOT NULL,
    "currency" VARCHAR(3) NOT NULL DEFAULT 'USD',
    "paymentMethod" VARCHAR(100),
    "lastPaymentDate" TIMESTAMP(3),
    "nextPaymentDate" TIMESTAMP(3),
    "userLimit" INTEGER,
    "storageLimit" BIGINT,
    "apiCallLimit" INTEGER,
    "features" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "tenant_subscriptions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."tenant_invitations" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "email" VARCHAR(255) NOT NULL,
    "role" "public"."TenantUserRole" NOT NULL DEFAULT 'MEMBER',
    "invitedBy" INTEGER NOT NULL,
    "token" TEXT NOT NULL,
    "status" "public"."InvitationStatus" NOT NULL DEFAULT 'PENDING',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "tenant_invitations_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "tenants_slug_key" ON "public"."tenants"("slug");

-- CreateIndex
CREATE INDEX "tenants_isActive_idx" ON "public"."tenants"("isActive");

-- CreateIndex
CREATE INDEX "tenants_slug_idx" ON "public"."tenants"("slug");

-- CreateIndex
CREATE INDEX "tenant_users_tenantId_status_idx" ON "public"."tenant_users"("tenantId", "status");

-- CreateIndex
CREATE INDEX "tenant_users_userId_idx" ON "public"."tenant_users"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "tenant_users_tenantId_userId_key" ON "public"."tenant_users"("tenantId", "userId");

-- CreateIndex
CREATE INDEX "tenant_roles_tenantId_isActive_idx" ON "public"."tenant_roles"("tenantId", "isActive");

-- CreateIndex
CREATE UNIQUE INDEX "tenant_roles_tenantId_name_key" ON "public"."tenant_roles"("tenantId", "name");

-- CreateIndex
CREATE INDEX "tenant_role_assignments_tenantUserId_idx" ON "public"."tenant_role_assignments"("tenantUserId");

-- CreateIndex
CREATE INDEX "tenant_role_assignments_roleId_idx" ON "public"."tenant_role_assignments"("roleId");

-- CreateIndex
CREATE UNIQUE INDEX "tenant_role_assignments_tenantUserId_roleId_key" ON "public"."tenant_role_assignments"("tenantUserId", "roleId");

-- CreateIndex
CREATE INDEX "tenant_subscriptions_tenantId_status_idx" ON "public"."tenant_subscriptions"("tenantId", "status");

-- CreateIndex
CREATE INDEX "tenant_subscriptions_endDate_idx" ON "public"."tenant_subscriptions"("endDate");

-- CreateIndex
CREATE UNIQUE INDEX "tenant_invitations_token_key" ON "public"."tenant_invitations"("token");

-- CreateIndex
CREATE INDEX "tenant_invitations_token_idx" ON "public"."tenant_invitations"("token");

-- CreateIndex
CREATE INDEX "tenant_invitations_expiresAt_idx" ON "public"."tenant_invitations"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "tenant_invitations_tenantId_email_key" ON "public"."tenant_invitations"("tenantId", "email");

-- AddForeignKey
ALTER TABLE "public"."tenant_users" ADD CONSTRAINT "tenant_users_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "public"."tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."tenant_roles" ADD CONSTRAINT "tenant_roles_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "public"."tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."tenant_role_assignments" ADD CONSTRAINT "tenant_role_assignments_tenantUserId_fkey" FOREIGN KEY ("tenantUserId") REFERENCES "public"."tenant_users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."tenant_role_assignments" ADD CONSTRAINT "tenant_role_assignments_roleId_fkey" FOREIGN KEY ("roleId") REFERENCES "public"."tenant_roles"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."tenant_subscriptions" ADD CONSTRAINT "tenant_subscriptions_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "public"."tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."tenant_invitations" ADD CONSTRAINT "tenant_invitations_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "public"."tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

