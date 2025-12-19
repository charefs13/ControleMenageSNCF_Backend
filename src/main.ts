// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import cookieParser from 'cookie-parser'; // ✅ utiliser default import

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // --- Middleware cookies ---
  app.use(cookieParser()); // ✅ ça fonctionne maintenant

  app.enableCors({
    origin: 'http://localhost:5173',
    credentials: true,
  });

  const config = new DocumentBuilder()
    .setTitle('Controle Menage SNCF')
    .setDescription("API pour le contrôle de ménage")
    .setVersion('1.0')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  await app.listen(3000);
  console.log('Server listening on http://localhost:3000');
}

bootstrap();
