// src/main.ts
import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import cookieParser from 'cookie-parser'; 

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const allowedOrigins = (
    process.env.FRONTEND_ORIGINS ??
    process.env.FRONTEND_URL ??
    'http://localhost:5173,http://127.0.0.1:5173'
  )
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

  // Cookie + validation globale pour activer réellement les DTO et éviter
  // l'injection de champs inattendus dans les payloads.
  app.use(cookieParser());
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  app.enableCors({
    origin: allowedOrigins,
    credentials: true,
  });

  const config = new DocumentBuilder()
    .setTitle('Controle Menage SNCF')
    .setDescription("API pour le contrôle de ménage")
    .setVersion('1.0')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  // 0.0.0.0 permet de joindre l'API depuis un autre appareil du même réseau.
  const port = Number(process.env.PORT ?? 3000);
  await app.listen(port, '0.0.0.0');
  console.log(`Server listening on http://0.0.0.0:${port}`);
}

bootstrap();
