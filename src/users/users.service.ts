// src/users/users.service.ts

import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service.js';
import { CreateUserDto } from './dto/create-user.dto.js';
import { UpdateUserDto } from './dto/update-user.dto.js';
import { Role } from '../../generated/prisma/client.js';
import * as jwt from 'jsonwebtoken';
import * as bcrypt from 'bcrypt';

/**
 * Service gérant la logique métier pour les utilisateurs (agents)
 */
@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  /**
   * Création d’un utilisateur (agent).
   * - Génère un token de première connexion valable 24h.
   * - Stocke l'utilisateur en base avec mdp = null (il n’a pas encore défini son mot de passe).
   * - Retourne l'utilisateur + le token.
   */
  async create(createUserDto: CreateUserDto) {
    // Données incluses dans le token temporaire de création
    const tokenPayload = {
      cp: createUserDto.cp,
      email: createUserDto.email,
      role: createUserDto.role ?? Role.UTILISATEUR, // Role par défaut : UTILISATEUR
    };

    // Génération d’un JWT valable 24 heures
    const authToken = jwt.sign(tokenPayload, process.env.JWT_SECRET!, {
      expiresIn: '24h',
    });

    // Création de l’utilisateur dans la base
    const user = await this.prisma.utilisateur.create({
      data: {
        ...createUserDto,
        role: createUserDto.role ?? Role.UTILISATEUR,
        authToken: authToken, // Stockage du token temporaire
        mdp: null,            // Le mot de passe sera défini plus tard
      },
    });

    return { user, authToken };
  }

  /**
   * Récupère tous les utilisateurs dans la base.
   */
  async findAll() {
    return this.prisma.utilisateur.findMany();
  }

  /**
   * Recherche un utilisateur par son CP.
   * @returns l'utilisateur ou null si inexistant
   */
  async findOne(cp: string) {
    return this.prisma.utilisateur.findUnique({
      where: { cp },
    });
  }

  /**
   * Mise à jour d'un utilisateur.
   * - Vérifie qu'il existe
   * - Applique les modifications
   */
  async update(cp: string, updateUserDto: UpdateUserDto) {
    const existing = await this.findOne(cp);
    if (!existing) throw new NotFoundException('Utilisateur non trouvé');

    return this.prisma.utilisateur.update({
      where: { cp },
      data: updateUserDto,
    });
  }

  /**
   * Suppression d’un utilisateur.
   * - Vérifie l’existence
   * - Supprime de la base
   */
  async remove(cp: string) {
    const existing = await this.findOne(cp);
    if (!existing) throw new NotFoundException('Utilisateur non trouvé');

    return this.prisma.utilisateur.delete({
      where: { cp },
    });
  }

  /**
   * Finalise l’inscription d’un agent.
   * Étapes :
   *  1. Vérifie le token reçu en paramètre
   *  2. Vérifie que le token correspond bien à celui stocké pour l’utilisateur
   *  3. Hash le nouveau mot de passe
   *  4. Enregistre le mot de passe et invalide le token
   *
   * Utilisé lorsque l'agent clique sur le lien envoyé par email.
   */
  async completeRegistration(token: string, password: string) {
    try {
      // Vérification du token JWT
      const payload = jwt.verify(token, process.env.JWT_SECRET!) as {
        cp: string;
        email: string;
        role: Role;
      };

      // Vérifie que l'utilisateur existe et que le token correspond
      const user = await this.findOne(payload.cp);
      if (!user || user.authToken !== token) {
        throw new ForbiddenException('Token invalide ou déjà utilisé');
      }

      // Hash du mot de passe
      const hashedPassword = await bcrypt.hash(password, 10);

      // Mise à jour du mot de passe et invalidation du token
      return this.prisma.utilisateur.update({
        where: { cp: payload.cp },
        data: {
          mdp: hashedPassword,
          authToken: null, // Le token ne doit plus jamais être réutilisable
        },
      });
    } catch (err) {
      // Le token est expiré ou invalide
      throw new ForbiddenException('Token invalide ou expiré');
    }
  }
}
