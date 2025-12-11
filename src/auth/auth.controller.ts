// // src/auth/auth.controller.ts
// import { Controller, Post, Patch, Body, Param, Headers, NotFoundException, BadRequestException, UnauthorizedException } from '@nestjs/common';
// import { AuthService } from './auth.service.js';
// import { LoginDto } from './dto/login.dto.js';
// import { ApiTags, ApiOkResponse, ApiBadRequestResponse, ApiOperation } from '@nestjs/swagger';

// /**
//  * Classe représentant la réponse des tokens pour Swagger
//  */
// class TokensResponse {
//   accessToken: string;
//   refreshToken?: string; // Pour l'instant, seul accessToken est utilisé
// }

// @ApiTags('auth') // Regroupe toutes les routes sous "auth" dans Swagger
// @Controller('auth')
// export class AuthController {
//   constructor(private authService: AuthService) {}

//   /**
//    * Connexion d'un utilisateur.
//    * Vérifie CP et mot de passe.
//    * Retourne un JWT si connexion réussie.
//    */
//   @Post('login')
//   @ApiOperation({ summary: 'Connexion utilisateur et récupération du token' })
//   @ApiOkResponse({ description: 'Connexion réussie, retourne access token.', type: TokensResponse })
//   @ApiBadRequestResponse({ description: 'CP ou mot de passe invalide.' })
//   async login(@Body() dto: LoginDto) {
//     if (!dto.cp || !dto.mdp) throw new BadRequestException('CP et mot de passe requis');
//     return this.authService.login(dto.cp, dto.mdp);
//   }

//   /**
//    * Génère un token pour un utilisateur donné et le stocke en base.
//    * @param cp Code personnel (identifiant) de l'utilisateur
//    */
//   @Post('token/:cp')
//   @ApiOperation({ summary: 'Génération d’un token pour un utilisateur' })
//   async generateToken(@Param('cp') cp: string) {
//     if (!cp) throw new BadRequestException('CP requis');
//     const token = await this.authService.generateTokenForUser(cp);
//     if (!token) throw new NotFoundException('Utilisateur non trouvé'); // Retour 404 si utilisateur inexistant
//     return token;
//   }

//   /**
//    * Mise à jour du mot de passe d’un utilisateur.
//    * Le mot de passe est haché avant d'être stocké.
//    * CP est récupéré depuis le token JWT pour sécurité.
//    * @body password Nouveau mot de passe
//    */
//   @Patch('update-password')
//   @ApiOperation({ summary: 'Modification du mot de passe utilisateur' })
//   async updatePassword(
//     @Body('mdp') mdp: string,
//     @Headers('Authorization') authHeader: string
//   ) {
//     if (!mdp) throw new BadRequestException('Mot de passe requis');
//     if (!authHeader) throw new UnauthorizedException('Token manquant');

//     const token = authHeader.replace('Bearer ', '');
//     const payload = this.authService.verifyToken(token);
//     if (!payload) throw new UnauthorizedException('Token invalide');

//     await this.authService.updatePassword(payload.sub, mdp);
//     return { message: 'Mot de passe mis à jour avec succès.' };
//   }
// }

// src/auth/auth.controller.ts

import {
  Controller,
  Post,
  Patch,
  Body,
  Param,
  Headers,
  NotFoundException,
  BadRequestException,
  UnauthorizedException
} from '@nestjs/common';
import { AuthService } from './auth.service.js';
import { LoginDto } from './dto/login.dto.js';
import { ApiTags, ApiOkResponse, ApiBadRequestResponse, ApiOperation } from '@nestjs/swagger';

/**
 * Classe utilisée uniquement pour Swagger.
 * Elle décrit la structure de la réponse lors de la connexion.
 */
class TokensResponse {
  accessToken: string;
  refreshToken?: string; // Non utilisé pour l'instant
}

@ApiTags('auth') // Toutes les routes apparaîtront sous "auth" dans Swagger
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  /**
   * POST /auth/login
   * Authentifie un utilisateur via CP + mot de passe
   * Retourne un JWT si les identifiants sont valides
   */
  @Post('login')
  @ApiOperation({ summary: 'Connexion utilisateur et récupération du token' })
  @ApiOkResponse({
    description: 'Connexion réussie, retourne access token.',
    type: TokensResponse,
  })
  @ApiBadRequestResponse({
    description: 'CP ou mot de passe invalide.',
  })
  async login(@Body() dto: LoginDto) {
    // Validation simple côté contrôleur
    if (!dto.cp || !dto.mdp) {
      throw new BadRequestException('CP et mot de passe requis');
    }

    // Appelle le service d'authentification
    return this.authService.login(dto.cp, dto.mdp);
  }

  /**
   * POST /auth/token/:cp
   * Génère un token pour un utilisateur spécifique (ex: onboarding)
   * Retourne 404 si l’utilisateur n’existe pas
   */
  @Post('token/:cp')
  @ApiOperation({ summary: 'Génération d’un token pour un utilisateur' })
  async generateToken(@Param('cp') cp: string) {
    if (!cp) throw new BadRequestException('CP requis');

    const token = await this.authService.generateTokenForUser(cp);

    // Si le service retourne null → aucun utilisateur trouvé
    if (!token) throw new NotFoundException('Utilisateur non trouvé');

    return token;
  }

  /**
   * PATCH /auth/update-password
   * Met à jour le mot de passe d’un utilisateur connecté.
   * Le CP n’est PAS envoyé dans le body → il est extrait du token JWT.
   *
   * Sécurité :
   * - Récupère le header Authorization: Bearer xxx
   * - Vérifie le JWT
   * - Récupère le CP dans payload.sub
   * - Hash le nouveau mot de passe dans le service
   */
  @Patch('update-password')
  @ApiOperation({ summary: 'Modification du mot de passe utilisateur' })
  async updatePassword(
    @Body('mdp') mdp: string,
    @Headers('Authorization') authHeader: string
  ) {
    // Vérification du mot de passe
    if (!mdp) {
      throw new BadRequestException('Mot de passe requis');
    }

    // Vérification que le token est présent dans le header
    if (!authHeader) {
      throw new UnauthorizedException('Token manquant');
    }

    // Extraction du token sans "Bearer "
    const token = authHeader.replace('Bearer ', '');

    // Vérification + décodage du token
    const payload = this.authService.verifyToken(token);
    if (!payload) {
      throw new UnauthorizedException('Token invalide');
    }

    // Mise à jour du mot de passe pour l'utilisateur identifié par le token (payload.sub)
    await this.authService.updatePassword(payload.sub, mdp);

    return { message: 'Mot de passe mis à jour avec succès.' };
  }
}


