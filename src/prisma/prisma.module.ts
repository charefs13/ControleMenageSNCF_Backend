// src/prisma/prisma.module.ts
import { Module, Global } from '@nestjs/common';
import { PrismaService } from './prisma.service.js';

@Global() // optionnel mais pratique pour l’utiliser partout
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
