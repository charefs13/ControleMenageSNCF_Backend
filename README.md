# Backend ControleMenageSNCF

API NestJS de l'application interne SNCF de controle de nettoyage.

## Responsabilites

Le backend gere :

- l'authentification JWT via cookie HttpOnly
- la recuperation de l'utilisateur connecte
- la creation, mise a jour et suppression des habilitations
- la reinitialisation et la creation de mot de passe
- l'envoi d'emails transactionnels
- l'acces aux donnees PostgreSQL via Prisma

## Stack technique

- NestJS
- Prisma
- PostgreSQL
- JWT
- Nodemailer

## Modules principaux

- `AuthModule`
- `UsersModule`
- `MailModule`
- `PrismaModule`

## Configuration

Fichiers attendus :

- `.env`
- optionnel : `.env.example` comme base de configuration

Variables principales :

```env
DATABASE_URL=postgres://user:password@localhost:5432/ControleMenageSNCF?schema=public
JWT_SECRET=change-me
FRONTEND_URL=http://localhost:5173
FRONTEND_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=user@example.com
SMTP_PASS=password
PORT=3000
```

Notes :

- `FRONTEND_ORIGINS` pilote le CORS et accepte plusieurs origines separees par des virgules
- `FRONTEND_URL` est reutilisee dans les liens d'email de reset et de creation de mot de passe

## Installation

```bash
npm install
```

## Lancement

```bash
npm run start
```

API disponible sur :

```text
http://localhost:3000
```

Swagger :

```text
http://localhost:3000/api
```

## Scripts

```bash
npm run start
npm run start:dev
npm run build
npm run test
npm run test:e2e
```

## Points techniques importants

- validation globale activee via `ValidationPipe`
- nettoyage des champs non declares dans les DTO (`whitelist`)
- refus des champs inconnus dans les payloads (`forbidNonWhitelisted`)
- ecoute sur `0.0.0.0` pour permettre les tests reseau locaux

## Flux principaux

### Connexion

- `POST /auth/login`
- verifie le CP et le mot de passe
- pose un cookie `accessToken`

### Utilisateur courant

- `GET /auth/me`
- retourne `cp`, `email`, `role`, `acceptedTerms`

### Gestion des habilitations

- `POST /agent`
- `GET /agent/:cp`
- `PATCH /agent/:cp`
- `DELETE /agent/:cp`

Toutes ces routes sont reservees aux administrateurs.

## Validation

Derniere verification effectuee :

```bash
npm run build
```
