import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * Guard pour protéger les routes nécessitant un token JWT valide
 * 
 * Utilise la stratégie 'jwt' définie dans JwtStrategy
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
