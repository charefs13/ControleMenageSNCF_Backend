/*
  Warnings:

  - You are about to drop the column `inscriptionToken` on the `Utilisateur` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "Utilisateur" DROP COLUMN "inscriptionToken",
ADD COLUMN     "authToken" TEXT;
