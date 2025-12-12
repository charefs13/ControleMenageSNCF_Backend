// src/auth/auth.service.ts

import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException
} from '@nestjs/common';
import { UsersService } from '../users/users.service.js';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { Utilisateur } from '../../generated/prisma/client';

/**
 * Service de gestion de l'authentification.
 *
 * Contient :
 * - La logique de connexion (validation + génération JWT)
 * - La génération de tokens à la demande (ex : onboarding)
 * - La mise à jour sécurisée des mots de passe
 * - La vérification / décodage des tokens
 */
@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,  // Accès aux données des utilisateurs
    private jwtService: JwtService,      // Gestion JWT (signature, vérification)
    private prisma: PrismaService,       // Accès direct à Prisma si nécessaire
  ) { }

  /**
   * Vérifie l'identité d’un utilisateur et retourne un token JWT si valide.
   *
   * Étapes :
   * 1. Vérifier la présence du CP et du mot de passe
   * 2. Vérifier que l'utilisateur existe
   * 3. Comparer le mot de passe en clair avec le hash stocké
   * 4. Générer un JWT si tout est valide
   *
   * @param cp Code personnel
   * @param password Mot de passe en clair
   */
  async login(cp: string, password: string) {
    if (!cp || !password) {
      throw new BadRequestException('CP et mot de passe requis');
    }

    // Récupération de l'utilisateur
    const userExist = await this.usersService.findOne(cp);
    if (!userExist) {
      throw new UnauthorizedException('Utilisateur non trouvé, vérifiez votre habilitation auprès de votre référent');
    } else if (userExist && !userExist.mdp) {
      throw new UnauthorizedException('Mot de passe invalide');
    }
    if (userExist.mdp) {
      // Vérifie le mot de passe en comparant le hash
      const passwordMatches = await bcrypt.compare(password, userExist.mdp);
      if (!passwordMatches) {
        throw new UnauthorizedException('Mot de passe invalide');
      }
    }

    // Réinitialisation du token d'authentification stocké (sécurité)
    await this.prisma.utilisateur.update({
      where: { cp },
      data: { authToken: null },
    });

    // Génération du token JWT
    return this.getToken(userExist);
  }

  /**
   * Génère un token JWT avec les informations essentielles de l'utilisateur.
   *
   * Le payload contient :
   * - sub : identifiant unique (CP)
   * - role : permet la gestion des permissions (admin, utilisateur…)
   * - user : email (utile pour affichage / logs)
   *
   * @param user Objet utilisateur Prisma
   * @returns { accessToken }
   */
  async getToken(user: Utilisateur) {
    const payload = {
      sub: user.cp,
      role: user.role,
      user: user.email,
    };

    const accessToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_SECRET,
      expiresIn: '2h', // Durée de validité du JWT
    });

    return { accessToken };
  }

  /**
   * Génère un token pour un utilisateur donné.
   * Utilisé principalement pour des liens uniques (reset password).
   *
   * @param cp Code personnel
   * @returns { token }
   */
  async generateTokenForUser(cp: string) {
    if (!cp) {
      throw new BadRequestException('CP requis');
    }

    // Vérifie que l'utilisateur existe
    const user = await this.prisma.utilisateur.findUnique({ where: { cp } });
    if (!user) {
      throw new NotFoundException('Utilisateur non trouvé');
    }

    // Création d’un JWT simple
    const payload = {
      sub: user.cp,
      email: user.email,
      role: user.role,
    };

    const token = this.jwtService.sign(payload, {
      secret: process.env.JWT_SECRET,
    });

    // Stockage du token en base (utilisé pour onboarding / reset)
    await this.prisma.utilisateur.update({
      where: { cp },
      data: { authToken: token },
    });

    return { token };
  }

  /**
   * Met à jour le mot de passe d’un utilisateur.
   *
   * Étapes :
   * 1. Vérifier que le nouveau mot de passe est fourni
   * 2. Hacher le mot de passe avec bcrypt
   * 3. Mettre à jour le champ `mdp` dans la base
   *
   * @param cp Code personnel de l’utilisateur
   * @param newPassword Nouveau mot de passe
   */
  async updatePassword(cp: string, newPassword: string) {
    if (!newPassword) {
      throw new BadRequestException('Nouveau mot de passe requis');
    }

    // Hash du mot de passe avant stockage
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Mise à jour sécurisée du mot de passe en base
    await this.prisma.utilisateur.update({
      where: { cp },
      data: { mdp: hashedPassword },
    });
  }

  /**
   * Vérifie un token JWT.
   * - Retourne le payload si token valide
   * - Retourne null si token invalide ou expiré
   *
   * Utilisé par update-password pour extraire le CP depuis le JWT.
   *
   * @param token JWT fourni par le client
   */
  verifyToken(token: string) {
    try {
      return this.jwtService.verify(token, {
        secret: process.env.JWT_SECRET,
      });
    } catch {
      return null; // Le contrôleur gérera l’erreur
    }
  }
}
