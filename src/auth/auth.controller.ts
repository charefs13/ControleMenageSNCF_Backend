import {
  Controller,        // Décorateur pour définir un controller NestJS
  Post,              // Décorateur pour route POST
  Patch,             // Décorateur pour route PATCH
  Body,              // Décorateur pour récupérer le corps de la requête
  Req,               // Décorateur pour récupérer la requête entière
  BadRequestException,   // Exception HTTP 400
  UnauthorizedException,
  UseGuards,
  Get, // Exception HTTP 401
  Res, // Pour manipuler la réponse HTTP
} from '@nestjs/common';

import { AuthService } from './auth.service'; // Service auth (login, token, reset, etc.)
import { UsersService } from '../users/users.service'; // Service utilisateurs
import { Request, Response } from 'express';
import { ApiTags, ApiOperation, ApiBody, ApiResponse } from '@nestjs/swagger';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { GetUser } from './decorators/get-user.decorator';

@ApiTags('auth') // Swagger : regroupe toutes les routes sous "auth"
@Controller('auth') // Préfixe /auth pour toutes les routes
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
  ) {}

  /**
   * GET /auth/me
   * Retourne les informations de l'utilisateur connecté.
   * Nécessite cookie HttpOnly contenant le JWT.
   */
  @Get('me')
  @ApiOperation({ summary: "Récupérer l'utilisateur connecté" })
  @ApiResponse({ status: 200, description: 'Utilisateur récupéré' })
  @ApiResponse({ status: 401, description: 'Utilisateur non connecté' })
  async getMe(@Req() req: Request) {
    const authHeader = req.headers['authorization'] || '';
    let token: string | null = null;

    // Si tu passes le token dans Authorization
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    } else if (req.cookies && req.cookies.accessToken) {
      // Si token via cookie HttpOnly
      token = req.cookies.accessToken;
    }

    if (!token) {
      throw new UnauthorizedException('Utilisateur non connecté');
    }

    const payload = this.authService.verifyToken(token);
    if (!payload) {
      throw new UnauthorizedException('Token invalide ou expiré');
    }

    // Récupère l'utilisateur depuis la base pour sécurité
    const user = await this.usersService.findOne(payload.sub);
    if (!user) {
      throw new UnauthorizedException('Utilisateur introuvable');
    }

    return {
      cp: user.cp,
      email: user.email,
      role: user.role,
      acceptedTerms: user.accepteConditions,
    };
  }

  /**
   * POST /auth/login
   * Connexion via CP + mot de passe
   * Retourne { acceptedTerms } et pose le cookie HttpOnly
   */
  @Post('login')
  @ApiOperation({ summary: 'Connexion utilisateur' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        cp: { type: 'string', example: '0123456A' },
        mdp: { type: 'string', example: 'motdepasse' },
      },
      required: ['cp', 'mdp'],
    },
  })
  @ApiResponse({ status: 200, description: 'Connexion réussie' })
  @ApiResponse({ status: 400, description: 'CP ou mot de passe manquant' })
  @ApiResponse({ status: 401, description: 'Utilisateur non trouvé ou mot de passe invalide' })
  async login(
    @Body() body: { cp: string; mdp: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    const { cp, mdp } = body;

    if (!cp || !mdp) {
      throw new BadRequestException('CP et mot de passe requis');
    }

    try {
      const result = await this.authService.login(cp, mdp);
      // Pose le cookie HttpOnly avec le token JWT
      res.cookie('accessToken', result.accessToken, {
        httpOnly: true,
        secure: false,    // ⚠️ false en localhost
        sameSite: 'lax',  // ⚠️ compatible localhost
        path: '/',
      });

      return { acceptedTerms: result.acceptedTerms };
    } catch (err) {
      throw new UnauthorizedException(err.message);
    }
  }

  /**
   * PATCH /auth/terms
   * Accepter les conditions d'utilisation
   */
@Patch('terms')
@ApiOperation({ summary: "Accepter les conditions d'utilisation" })
@ApiResponse({ status: 200, description: 'Conditions acceptées' })
@ApiResponse({ status: 401, description: 'Token manquant ou invalide' })
async acceptTerms(@Req() req: Request) {
  let token: string | null = null;

  // Lecture depuis cookie
  if (req.cookies && req.cookies.accessToken) {
    token = req.cookies.accessToken;
  }

  if (!token) {
    throw new UnauthorizedException('Utilisateur non connecté');
  }

  const payload = this.authService.verifyToken(token);
  if (!payload) {
    throw new UnauthorizedException('Token invalide ou expiré');
  }

  // Marque les conditions comme acceptées
  await this.authService.acceptTerms(payload.sub);
  return { message: 'Conditions acceptées' };
}

  /**
   * POST /auth/reset-password
   * Envoie un email pour réinitialiser le mot de passe
   */
  @Post('reset-password')
  @ApiOperation({ summary: 'Demande de réinitialisation du mot de passe' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: { email: { type: 'string', example: 'test@example.com' } },
      required: ['email'],
    },
  })
  @ApiResponse({ status: 200, description: 'Email de réinitialisation envoyé' })
  async resetPassword(@Body() body: { email: string }) {
    const { email } = body;
    if (!email) throw new BadRequestException('Email requis');

    return this.authService.resetPassword(email);
  }

  /**
   * POST /auth/update-password
   * Met à jour le mot de passe via token JWT
   */
@Patch('update-password')
@ApiOperation({ summary: 'Mettre à jour le mot de passe' })
@ApiBody({
  schema: {
    type: 'object',
    properties: {
      newPassword: { type: 'string', example: 'nouveauMdp' },
    },
    required: ['newPassword'],
  },
})
async updatePassword(
  @Req() req: Request,
  @Body() body: { newPassword: string }
) {
  const authHeader = req.headers['authorization'] || '';
  let token: string | null = null;

  // Lecture du token depuis le header Authorization
  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  }

  const { newPassword } = body;

  if (!token) {
    throw new UnauthorizedException('Token manquant');
  }
  if (!newPassword) {
    throw new BadRequestException('Nouveau mot de passe requis');
  }

  const payload = this.authService.verifyToken(token);
  if (!payload) {
    throw new UnauthorizedException('Token invalide ou expiré');
  }

  // ✅ PASSER LE TOKEN COMPLET AU SERVICE
  await this.authService.updatePassword(token, newPassword);

  return { message: 'Mot de passe mis à jour avec succès' };
}


  /**
 * POST /auth/logout
 * Déconnexion de l'utilisateur
 * Supprime le cookie HttpOnly contenant le JWT
 */
@Post('logout')
@ApiOperation({ summary: 'Déconnexion utilisateur' })
@ApiResponse({ status: 200, description: 'Utilisateur déconnecté' })
async logout(@Res({ passthrough: true }) res: Response) {
  // Supprime le cookie en le réinitialisant
  res.clearCookie('accessToken', {
    httpOnly: true,
    secure: false, // false en local
    sameSite: 'lax',
    path: '/',
  });

  return { message: 'Utilisateur déconnecté' };
}
}
