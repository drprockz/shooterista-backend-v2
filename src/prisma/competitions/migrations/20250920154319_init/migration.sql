-- CreateEnum
CREATE TYPE "public"."CompetitionType" AS ENUM ('INDIVIDUAL', 'TEAM', 'MIXED', 'QUALIFICATION', 'FINAL');

-- CreateEnum
CREATE TYPE "public"."CompetitionStatus" AS ENUM ('DRAFT', 'PUBLISHED', 'REGISTRATION_OPEN', 'REGISTRATION_CLOSED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED', 'POSTPONED');

-- CreateEnum
CREATE TYPE "public"."CompetitionVisibility" AS ENUM ('PRIVATE', 'PUBLIC', 'INVITE_ONLY');

-- CreateEnum
CREATE TYPE "public"."RoundStatus" AS ENUM ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "public"."SeriesStatus" AS ENUM ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "public"."ParticipationStatus" AS ENUM ('REGISTERED', 'CONFIRMED', 'CHECKED_IN', 'COMPETING', 'COMPLETED', 'WITHDRAWN', 'DISQUALIFIED', 'NO_SHOW');

-- CreateEnum
CREATE TYPE "public"."PaymentStatus" AS ENUM ('PENDING', 'PAID', 'REFUNDED', 'WAIVED', 'OVERDUE');

-- CreateEnum
CREATE TYPE "public"."EventType" AS ENUM ('REGISTRATION_OPEN', 'REGISTRATION_CLOSE', 'TECHNICAL_MEETING', 'EQUIPMENT_CHECK', 'PRACTICE_START', 'PRACTICE_END', 'COMPETITION_START', 'ROUND_START', 'ROUND_END', 'SERIES_START', 'SERIES_END', 'BREAK', 'AWARDS_CEREMONY', 'COMPETITION_END');

-- CreateEnum
CREATE TYPE "public"."EventStatus" AS ENUM ('SCHEDULED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED', 'POSTPONED');

-- CreateTable
CREATE TABLE "public"."competitions" (
    "id" BIGSERIAL NOT NULL,
    "tenantId" BIGINT NOT NULL,
    "name" VARCHAR(200) NOT NULL,
    "description" TEXT,
    "type" "public"."CompetitionType" NOT NULL,
    "discipline" VARCHAR(100) NOT NULL,
    "format" VARCHAR(100) NOT NULL,
    "roundCount" INTEGER NOT NULL DEFAULT 1,
    "seriesPerRound" INTEGER NOT NULL DEFAULT 1,
    "shotsPerSeries" INTEGER NOT NULL DEFAULT 10,
    "startDate" TIMESTAMP(3) NOT NULL,
    "endDate" TIMESTAMP(3) NOT NULL,
    "timezone" VARCHAR(50) NOT NULL,
    "venue" VARCHAR(200),
    "address" TEXT,
    "coordinates" JSONB,
    "settings" JSONB,
    "rules" TEXT,
    "scoringRules" JSONB,
    "status" "public"."CompetitionStatus" NOT NULL DEFAULT 'DRAFT',
    "visibility" "public"."CompetitionVisibility" NOT NULL DEFAULT 'PRIVATE',
    "registrationOpen" TIMESTAMP(3),
    "registrationClose" TIMESTAMP(3),
    "maxParticipants" INTEGER,
    "registrationFee" DECIMAL(10,2),
    "awards" JSONB,
    "weatherData" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "competitions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."rounds" (
    "id" BIGSERIAL NOT NULL,
    "competitionId" BIGINT NOT NULL,
    "roundNumber" INTEGER NOT NULL,
    "name" VARCHAR(100),
    "seriesCount" INTEGER NOT NULL DEFAULT 1,
    "shotsPerSeries" INTEGER NOT NULL DEFAULT 10,
    "timeLimit" INTEGER,
    "startTime" TIMESTAMP(3),
    "endTime" TIMESTAMP(3),
    "status" "public"."RoundStatus" NOT NULL DEFAULT 'PENDING',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "rounds_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."series" (
    "id" BIGSERIAL NOT NULL,
    "roundId" BIGINT NOT NULL,
    "seriesNumber" INTEGER NOT NULL,
    "name" VARCHAR(100),
    "shotCount" INTEGER NOT NULL DEFAULT 10,
    "timeLimit" INTEGER,
    "conditions" JSONB,
    "status" "public"."SeriesStatus" NOT NULL DEFAULT 'PENDING',
    "startTime" TIMESTAMP(3),
    "endTime" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "series_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."shots" (
    "id" BIGSERIAL NOT NULL,
    "seriesId" BIGINT NOT NULL,
    "participantId" BIGINT NOT NULL,
    "shotNumber" INTEGER NOT NULL,
    "score" DECIMAL(4,1) NOT NULL,
    "coordinates" JSONB,
    "distance" DECIMAL(6,2),
    "angle" DECIMAL(6,2),
    "shotTime" TIMESTAMP(3),
    "timeToShot" INTEGER,
    "conditions" JSONB,
    "equipment" JSONB,
    "isValid" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "shots_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."competition_participants" (
    "id" BIGSERIAL NOT NULL,
    "competitionId" BIGINT NOT NULL,
    "athleteId" BIGINT NOT NULL,
    "registeredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "status" "public"."ParticipationStatus" NOT NULL DEFAULT 'REGISTERED',
    "startNumber" INTEGER,
    "category" VARCHAR(100),
    "division" VARCHAR(100),
    "lane" INTEGER,
    "equipment" JSONB,
    "paymentStatus" "public"."PaymentStatus" NOT NULL DEFAULT 'PENDING',
    "paymentAmount" DECIMAL(10,2),
    "emergencyContact" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "competition_participants_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."competition_results" (
    "id" BIGSERIAL NOT NULL,
    "competitionId" BIGINT NOT NULL,
    "participantId" BIGINT NOT NULL,
    "totalScore" DECIMAL(8,1) NOT NULL,
    "roundScores" JSONB,
    "seriesScores" JSONB,
    "overallRank" INTEGER,
    "categoryRank" INTEGER,
    "divisionRank" INTEGER,
    "averageScore" DECIMAL(4,1),
    "highestSeries" DECIMAL(4,1),
    "centerShots" INTEGER,
    "consistency" DECIMAL(4,3),
    "improvement" DECIMAL(4,1),
    "awards" JSONB,
    "calculatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "isOfficial" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "competition_results_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."competition_events" (
    "id" BIGSERIAL NOT NULL,
    "competitionId" BIGINT NOT NULL,
    "type" "public"."EventType" NOT NULL,
    "title" VARCHAR(200) NOT NULL,
    "description" TEXT,
    "scheduledAt" TIMESTAMP(3) NOT NULL,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "eventData" JSONB,
    "status" "public"."EventStatus" NOT NULL DEFAULT 'SCHEDULED',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "competition_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "competitions_tenantId_status_idx" ON "public"."competitions"("tenantId", "status");

-- CreateIndex
CREATE INDEX "competitions_startDate_endDate_idx" ON "public"."competitions"("startDate", "endDate");

-- CreateIndex
CREATE INDEX "competitions_discipline_status_idx" ON "public"."competitions"("discipline", "status");

-- CreateIndex
CREATE INDEX "rounds_competitionId_status_idx" ON "public"."rounds"("competitionId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "rounds_competitionId_roundNumber_key" ON "public"."rounds"("competitionId", "roundNumber");

-- CreateIndex
CREATE INDEX "series_roundId_status_idx" ON "public"."series"("roundId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "series_roundId_seriesNumber_key" ON "public"."series"("roundId", "seriesNumber");

-- CreateIndex
CREATE INDEX "shots_participantId_seriesId_idx" ON "public"."shots"("participantId", "seriesId");

-- CreateIndex
CREATE UNIQUE INDEX "shots_seriesId_participantId_shotNumber_key" ON "public"."shots"("seriesId", "participantId", "shotNumber");

-- CreateIndex
CREATE INDEX "competition_participants_competitionId_status_idx" ON "public"."competition_participants"("competitionId", "status");

-- CreateIndex
CREATE INDEX "competition_participants_athleteId_idx" ON "public"."competition_participants"("athleteId");

-- CreateIndex
CREATE UNIQUE INDEX "competition_participants_competitionId_athleteId_key" ON "public"."competition_participants"("competitionId", "athleteId");

-- CreateIndex
CREATE UNIQUE INDEX "competition_participants_competitionId_startNumber_key" ON "public"."competition_participants"("competitionId", "startNumber");

-- CreateIndex
CREATE INDEX "competition_results_competitionId_overallRank_idx" ON "public"."competition_results"("competitionId", "overallRank");

-- CreateIndex
CREATE INDEX "competition_results_competitionId_categoryRank_idx" ON "public"."competition_results"("competitionId", "categoryRank");

-- CreateIndex
CREATE UNIQUE INDEX "competition_results_competitionId_participantId_key" ON "public"."competition_results"("competitionId", "participantId");

-- CreateIndex
CREATE INDEX "competition_events_competitionId_scheduledAt_idx" ON "public"."competition_events"("competitionId", "scheduledAt");

-- CreateIndex
CREATE INDEX "competition_events_type_status_idx" ON "public"."competition_events"("type", "status");

-- AddForeignKey
ALTER TABLE "public"."rounds" ADD CONSTRAINT "rounds_competitionId_fkey" FOREIGN KEY ("competitionId") REFERENCES "public"."competitions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."series" ADD CONSTRAINT "series_roundId_fkey" FOREIGN KEY ("roundId") REFERENCES "public"."rounds"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."shots" ADD CONSTRAINT "shots_seriesId_fkey" FOREIGN KEY ("seriesId") REFERENCES "public"."series"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."shots" ADD CONSTRAINT "shots_participantId_fkey" FOREIGN KEY ("participantId") REFERENCES "public"."competition_participants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."competition_participants" ADD CONSTRAINT "competition_participants_competitionId_fkey" FOREIGN KEY ("competitionId") REFERENCES "public"."competitions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."competition_results" ADD CONSTRAINT "competition_results_competitionId_fkey" FOREIGN KEY ("competitionId") REFERENCES "public"."competitions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."competition_results" ADD CONSTRAINT "competition_results_participantId_fkey" FOREIGN KEY ("participantId") REFERENCES "public"."competition_participants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."competition_events" ADD CONSTRAINT "competition_events_competitionId_fkey" FOREIGN KEY ("competitionId") REFERENCES "public"."competitions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
