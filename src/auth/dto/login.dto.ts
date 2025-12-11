
import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

/**
 * DTO pour la connexion d'un utilisateur.
 * Utilisé par la route /auth/login.
 */
export class LoginDto {
  @ApiProperty({ example: '0123456A', description: 'CP' })
  @IsString()
  cp: string;

  @ApiProperty({ example: 'Password123!', description: 'Mot de passe de l’utilisateur' })
  @IsString()
  mdp: string;
}
  