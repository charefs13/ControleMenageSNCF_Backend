import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Décorateur personnalisé pour récupérer l'utilisateur connecté
 * depuis la requête (req.user), injecté par JwtAuthGuard ou JwtRefreshGuard
 *
 * Exemple d'utilisation :
 * @GetUser() user: any
 * @GetUser('email') email: string
 */
export const GetUser = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;

    // Si on fournit un champ spécifique, on retourne seulement ce champ
    return data ? user?.[data] : user;
  },
);
