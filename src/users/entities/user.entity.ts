// src/users/user.entity.ts
import { Role } from '../../../generated/prisma/client';

/**
 * Classe représentant un utilisateur
 * Sert de référence pour les retours de l'API
 */
export class UserEntity {
  cp: string;
  email: string;
  nom: string;
  prenom: string;
  mdp: string;
  role: Role;
  dateCreation: Date;
  accepteConditions: boolean;
  tokenInscription: string | null;
}
