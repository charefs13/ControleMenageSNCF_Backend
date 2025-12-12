import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';
import { SwaggerModule, DocumentBuilder } from "@nestjs/swagger";

async function bootstrap() {
  // Création de l'application NestJS
  const app = await NestFactory.create(AppModule);

  // ⚡ Activer CORS pour autoriser le frontend (React/Vite)
  // Ici, seul http://localhost:5173 est autorisé
  app.enableCors({
    origin: 'http://localhost:5173', // Change si ton frontend est sur une autre URL
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    credentials: true,               // Permet d'envoyer des cookies si besoin
  });

  // ⚙️ Configuration de Swagger pour la documentation API
  const config = new DocumentBuilder()
    .setTitle('Controle Menage SNCF')
    .setDescription("API pour le controle de menage dans l'ESO TGV MED")
    .setVersion('1.0')
    .addTag('controle-menage-sncf')
    .build();

  // Création du document Swagger
  const document = SwaggerModule.createDocument(app, config);

  // Setup Swagger sur /api
  SwaggerModule.setup('api', app, document);

  // Démarrage de l'application sur le port défini dans les variables d'environnement ou 3000
  await app.listen(process.env.PORT ?? 3000);

  console.log(`🚀 Backend démarré sur : http://localhost:${process.env.PORT ?? 3000}`);
  console.log(`📖 Swagger disponible sur : http://localhost:${process.env.PORT ?? 3000}/api`);
}

bootstrap();
