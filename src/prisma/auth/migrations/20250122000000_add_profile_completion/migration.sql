-- Migration: Add profile completion fields to User table and create profile tables
-- Date: 2025-01-22
-- Description: Adds profile completion workflow fields to User table and creates UserProfile and UserProfileDraft tables

-- Add profile completion fields to User table
ALTER TABLE "User" ADD COLUMN "isFirstLogin" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "User" ADD COLUMN "profileCompletion" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "User" ADD COLUMN "profileStatus" "ProfileStatus" NOT NULL DEFAULT 'DRAFT';
ALTER TABLE "User" ADD COLUMN "modulesUnlocked" BOOLEAN NOT NULL DEFAULT false;

-- Create ProfileStatus enum
CREATE TYPE "ProfileStatus" AS ENUM ('DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED');

-- Create ProfileSection enum
CREATE TYPE "ProfileSection" AS ENUM ('PERSONAL', 'CONTACT', 'EDUCATION', 'JOB', 'EVENT');

-- Create UserProfile table
CREATE TABLE "user_profiles" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "personalData" JSONB,
    "personalComplete" BOOLEAN NOT NULL DEFAULT false,
    "personalUpdatedAt" TIMESTAMP(3),
    "personalUpdatedBy" INTEGER,
    "contactData" JSONB,
    "contactComplete" BOOLEAN NOT NULL DEFAULT false,
    "contactUpdatedAt" TIMESTAMP(3),
    "contactUpdatedBy" INTEGER,
    "educationData" JSONB,
    "educationComplete" BOOLEAN NOT NULL DEFAULT false,
    "educationUpdatedAt" TIMESTAMP(3),
    "educationUpdatedBy" INTEGER,
    "jobData" JSONB,
    "jobComplete" BOOLEAN NOT NULL DEFAULT false,
    "jobUpdatedAt" TIMESTAMP(3),
    "jobUpdatedBy" INTEGER,
    "eventData" JSONB,
    "eventComplete" BOOLEAN NOT NULL DEFAULT false,
    "eventUpdatedAt" TIMESTAMP(3),
    "eventUpdatedBy" INTEGER,
    "dataVersion" INTEGER NOT NULL DEFAULT 1,
    "submittedAt" TIMESTAMP(3),
    "approvedAt" TIMESTAMP(3),
    "approvedBy" INTEGER,
    "rejectedAt" TIMESTAMP(3),
    "rejectedBy" INTEGER,
    "rejectionReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "user_profiles_pkey" PRIMARY KEY ("id")
);

-- Create UserProfileDraft table
CREATE TABLE "user_profile_drafts" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "section" "ProfileSection" NOT NULL,
    "draftData" JSONB NOT NULL,
    "lastSavedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_profile_drafts_pkey" PRIMARY KEY ("id")
);

-- Add foreign key constraints
ALTER TABLE "user_profiles" ADD CONSTRAINT "user_profiles_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "user_profile_drafts" ADD CONSTRAINT "user_profile_drafts_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Create indexes
CREATE INDEX "User_profileStatus_idx" ON "User"("profileStatus");
CREATE INDEX "User_profileCompletion_idx" ON "User"("profileCompletion");
CREATE INDEX "user_profiles_userId_idx" ON "user_profiles"("userId");
CREATE INDEX "user_profiles_submittedAt_idx" ON "user_profiles"("submittedAt");
CREATE INDEX "user_profiles_approvedAt_idx" ON "user_profiles"("approvedAt");
CREATE UNIQUE INDEX "user_profile_drafts_userId_section_key" ON "user_profile_drafts"("userId", "section");
CREATE INDEX "user_profile_drafts_userId_idx" ON "user_profile_drafts"("userId");
CREATE INDEX "user_profile_drafts_section_idx" ON "user_profile_drafts"("section");
CREATE INDEX "user_profile_drafts_lastSavedAt_idx" ON "user_profile_drafts"("lastSavedAt");

-- Backfill existing users with approved status
UPDATE "User" SET 
    "isFirstLogin" = false,
    "profileStatus" = 'APPROVED',
    "profileCompletion" = 100,
    "modulesUnlocked" = true
WHERE "isFirstLogin" = true;