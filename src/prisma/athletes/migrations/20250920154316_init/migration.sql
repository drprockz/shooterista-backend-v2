-- CreateEnum
CREATE TYPE "public"."Gender" AS ENUM ('MALE', 'FEMALE', 'OTHER', 'PREFER_NOT_TO_SAY');

-- CreateEnum
CREATE TYPE "public"."Handedness" AS ENUM ('RIGHT', 'LEFT', 'AMBIDEXTROUS');

-- CreateEnum
CREATE TYPE "public"."EyeDominance" AS ENUM ('RIGHT', 'LEFT', 'CROSS_DOMINANT');

-- CreateEnum
CREATE TYPE "public"."PlanType" AS ENUM ('FREE', 'BASIC', 'PREMIUM', 'ENTERPRISE');

-- CreateEnum
CREATE TYPE "public"."MembershipRole" AS ENUM ('OWNER', 'ADMIN', 'COACH', 'MEMBER');

-- CreateEnum
CREATE TYPE "public"."MembershipStatus" AS ENUM ('ACTIVE', 'INACTIVE', 'SUSPENDED', 'PENDING');

-- CreateEnum
CREATE TYPE "public"."CompetitionType" AS ENUM ('INDIVIDUAL', 'TEAM', 'MIXED');

-- CreateEnum
CREATE TYPE "public"."CompetitionStatus" AS ENUM ('DRAFT', 'PUBLISHED', 'REGISTRATION_OPEN', 'REGISTRATION_CLOSED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "public"."ParticipationStatus" AS ENUM ('REGISTERED', 'CONFIRMED', 'CHECKED_IN', 'COMPETING', 'COMPLETED', 'WITHDRAWN', 'DISQUALIFIED');

-- CreateTable
CREATE TABLE "public"."athletes" (
    "id" BIGSERIAL NOT NULL,
    "tenantId" BIGINT NOT NULL,
    "userId" BIGINT,
    "firstName" VARCHAR(100) NOT NULL,
    "lastName" VARCHAR(100) NOT NULL,
    "email" VARCHAR(255),
    "dateOfBirth" TIMESTAMP(3),
    "gender" "public"."Gender",
    "country" VARCHAR(3),
    "state" VARCHAR(100),
    "city" VARCHAR(100),
    "phone" VARCHAR(20),
    "handedness" "public"."Handedness",
    "eyeDominance" "public"."EyeDominance",
    "discipline" VARCHAR(100),
    "classification" VARCHAR(50),
    "profileImage" VARCHAR(500),
    "bio" TEXT,
    "achievements" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "athletes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."tenants" (
    "id" BIGSERIAL NOT NULL,
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
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "tenants_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."memberships" (
    "id" BIGSERIAL NOT NULL,
    "tenantId" BIGINT NOT NULL,
    "athleteId" BIGINT NOT NULL,
    "role" "public"."MembershipRole" NOT NULL DEFAULT 'MEMBER',
    "status" "public"."MembershipStatus" NOT NULL DEFAULT 'ACTIVE',
    "joinedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "leftAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "memberships_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."scores" (
    "id" BIGSERIAL NOT NULL,
    "athleteId" BIGINT NOT NULL,
    "competitionId" BIGINT NOT NULL,
    "round" INTEGER NOT NULL,
    "series" INTEGER NOT NULL,
    "shotNumber" INTEGER NOT NULL,
    "score" DECIMAL(4,1) NOT NULL,
    "coordinates" JSONB,
    "conditions" JSONB,
    "equipment" JSONB,
    "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "scores_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."competitions" (
    "id" BIGSERIAL NOT NULL,
    "tenantId" BIGINT NOT NULL,
    "name" VARCHAR(200) NOT NULL,
    "description" TEXT,
    "type" "public"."CompetitionType" NOT NULL,
    "discipline" VARCHAR(100) NOT NULL,
    "format" VARCHAR(100) NOT NULL,
    "rounds" INTEGER NOT NULL DEFAULT 1,
    "seriesPerRound" INTEGER NOT NULL DEFAULT 1,
    "shotsPerSeries" INTEGER NOT NULL DEFAULT 10,
    "startDate" TIMESTAMP(3) NOT NULL,
    "endDate" TIMESTAMP(3) NOT NULL,
    "timezone" VARCHAR(50) NOT NULL,
    "venue" VARCHAR(200),
    "address" TEXT,
    "settings" JSONB,
    "rules" TEXT,
    "status" "public"."CompetitionStatus" NOT NULL DEFAULT 'DRAFT',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "competitions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."athlete_competitions" (
    "id" BIGSERIAL NOT NULL,
    "athleteId" BIGINT NOT NULL,
    "competitionId" BIGINT NOT NULL,
    "registeredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "status" "public"."ParticipationStatus" NOT NULL DEFAULT 'REGISTERED',
    "startNumber" INTEGER,
    "category" VARCHAR(100),
    "division" VARCHAR(100),
    "totalScore" DECIMAL(8,1),
    "ranking" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "athlete_competitions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "athletes_tenantId_isActive_idx" ON "public"."athletes"("tenantId", "isActive");

-- CreateIndex
CREATE INDEX "athletes_tenantId_lastName_firstName_idx" ON "public"."athletes"("tenantId", "lastName", "firstName");

-- CreateIndex
CREATE UNIQUE INDEX "athletes_tenantId_email_key" ON "public"."athletes"("tenantId", "email");

-- CreateIndex
CREATE UNIQUE INDEX "tenants_slug_key" ON "public"."tenants"("slug");

-- CreateIndex
CREATE INDEX "tenants_isActive_idx" ON "public"."tenants"("isActive");

-- CreateIndex
CREATE INDEX "memberships_tenantId_status_idx" ON "public"."memberships"("tenantId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "memberships_tenantId_athleteId_key" ON "public"."memberships"("tenantId", "athleteId");

-- CreateIndex
CREATE INDEX "scores_athleteId_competitionId_idx" ON "public"."scores"("athleteId", "competitionId");

-- CreateIndex
CREATE INDEX "scores_competitionId_round_series_idx" ON "public"."scores"("competitionId", "round", "series");

-- CreateIndex
CREATE UNIQUE INDEX "scores_competitionId_athleteId_round_series_shotNumber_key" ON "public"."scores"("competitionId", "athleteId", "round", "series", "shotNumber");

-- CreateIndex
CREATE INDEX "competitions_tenantId_status_idx" ON "public"."competitions"("tenantId", "status");

-- CreateIndex
CREATE INDEX "competitions_startDate_endDate_idx" ON "public"."competitions"("startDate", "endDate");

-- CreateIndex
CREATE INDEX "athlete_competitions_competitionId_ranking_idx" ON "public"."athlete_competitions"("competitionId", "ranking");

-- CreateIndex
CREATE UNIQUE INDEX "athlete_competitions_athleteId_competitionId_key" ON "public"."athlete_competitions"("athleteId", "competitionId");

-- AddForeignKey
ALTER TABLE "public"."athletes" ADD CONSTRAINT "athletes_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "public"."tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."memberships" ADD CONSTRAINT "memberships_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "public"."tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."memberships" ADD CONSTRAINT "memberships_athleteId_fkey" FOREIGN KEY ("athleteId") REFERENCES "public"."athletes"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."scores" ADD CONSTRAINT "scores_athleteId_fkey" FOREIGN KEY ("athleteId") REFERENCES "public"."athletes"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."scores" ADD CONSTRAINT "scores_competitionId_fkey" FOREIGN KEY ("competitionId") REFERENCES "public"."competitions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."competitions" ADD CONSTRAINT "competitions_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "public"."tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."athlete_competitions" ADD CONSTRAINT "athlete_competitions_athleteId_fkey" FOREIGN KEY ("athleteId") REFERENCES "public"."athletes"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."athlete_competitions" ADD CONSTRAINT "athlete_competitions_competitionId_fkey" FOREIGN KEY ("competitionId") REFERENCES "public"."competitions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
