// src/users/dto/create-user.dto.ts
import { IsString, IsEmail, IsEnum, IsOptional } from 'class-validator';
import { Role } from '../../../generated/prisma/client';

/**
 * DTO pour la création d'un utilisateur
 * Validation automatique grâce aux décorateurs class-validator
 */
export class CreateUserDto {
  @IsString()
  cp: string;

  @IsEmail()
  email: string;

  @IsString()
  nom: string;

  @IsString()
  prenom: string;

  @IsString()
  @IsOptional()
  mdp: string;

  @IsEnum(Role)
  @IsOptional()
  role?: Role; // Optionnel, par défaut UTILISATEUR

  @IsOptional()
  accepteConditions?: boolean; // Optionnel, par défaut false

  @IsString()
  @IsOptional()
  authToken?: string | null; // Optionnel, peut être null
}
