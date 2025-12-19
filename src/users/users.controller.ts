// src/users/users.controller.ts

import {
  Controller,
  Get,
  Patch,
  Post,
  Delete,
  Param,
  Body,
  UseGuards,
  ForbiddenException,
  NotFoundException,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';

import { UsersService } from './users.service.js';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiBody,
} from '@nestjs/swagger';

import { UpdateUserDto } from './dto/update-user.dto.js';
import { CreateUserDto } from './dto/create-user.dto.js';
import { UserEntity } from './entities/user.entity.js';
import { Role } from '../../generated/prisma/client.js';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { GetUser } from '../auth/decorators/get-user.decorator.js';

@ApiTags('agents')          // Swagger : toutes les routes sous "agents"
@ApiBearerAuth()            // Swagger : JWT requis
@UseGuards(JwtAuthGuard)   // Toutes les routes nécessitent JWT valide
@Controller('agent')       // Préfixe /agent pour toutes les routes
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  /**
   * GET /agent/:cp
   * Récupérer un agent par son CP (Admin uniquement)
   */
  @Get(':cp')
  @ApiOperation({ summary: 'Récupérer un agent via son CP (réservé aux administrateurs)' })
  @ApiResponse({ status: 200, description: 'Agent trouvé et retourné', type: UserEntity })
  @ApiResponse({ status: 403, description: 'Accès refusé : réservé aux administrateurs' })
  @ApiResponse({ status: 404, description: 'Aucun agent trouvé avec ce CP' })
  async getAgent(@GetUser() admin, @Param('cp') cp: string) {
    if (admin.role !== Role.ADMIN) throw new ForbiddenException('Accès réservé aux administrateurs.');

    const user = await this.usersService.findOne(cp);
    if (!user) throw new NotFoundException('Agent non trouvé.');

    return user; // Retourne l'utilisateur trouvé
  }

  /**
   * PATCH /agent/:cp
   * Mettre à jour un agent (Admin uniquement)
   */
  @Patch(':cp')
  @ApiOperation({ summary: 'Mettre à jour un agent via son CP (réservé aux administrateurs)' })
  @ApiBody({ type: UpdateUserDto, description: 'Champs à mettre à jour' })
  @ApiResponse({ status: 200, description: 'Agent mis à jour avec succès', type: UserEntity })
  @ApiResponse({ status: 403, description: 'Accès refusé : réservé aux administrateurs' })
  @ApiResponse({ status: 404, description: 'Aucun agent trouvé avec ce CP' })
  async updateAgent(
    @GetUser() admin,
    @Param('cp') cp: string,
    @Body() updateUserDto: UpdateUserDto,
  ) {
    if (admin.role !== Role.ADMIN) throw new ForbiddenException('Accès réservé aux administrateurs.');

    const existing = await this.usersService.findOne(cp);
    if (!existing) throw new NotFoundException('Agent non trouvé.');

    return this.usersService.update(cp, updateUserDto);
  }

  /**
   * DELETE /agent/:cp
   * Supprimer un agent (Admin uniquement)
   */
  @Delete(':cp')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Supprimer un agent via son CP (réservé aux administrateurs)' })
  @ApiResponse({ status: 204, description: 'Agent supprimé avec succès' })
  @ApiResponse({ status: 403, description: 'Accès refusé : réservé aux administrateurs' })
  @ApiResponse({ status: 404, description: 'Aucun agent trouvé avec ce CP' })
  async remove(@GetUser() admin, @Param('cp') cp: string) {
    if (admin.role !== Role.ADMIN) throw new ForbiddenException('Accès réservé aux administrateurs.');

    const existing = await this.usersService.findOne(cp);
    if (!existing) throw new NotFoundException('Agent non trouvé.');

    await this.usersService.remove(cp); // Supprime l'utilisateur
  }

  /**
   * POST /agent
   * Création d’un nouvel agent (Admin uniquement)
   */
  @Post()
  @ApiOperation({ summary: 'Créer un nouvel agent (réservé aux administrateurs)' })
  @ApiBody({ type: CreateUserDto, description: 'Données de l’agent à créer' })
  @ApiResponse({ status: 201, description: 'Agent créé avec succès', type: UserEntity })
  @ApiResponse({ status: 403, description: 'Accès refusé : réservé aux administrateurs' })
  async createAgent(@GetUser() admin, @Body() createUserDto: CreateUserDto) {
    if (admin.role !== Role.ADMIN) throw new ForbiddenException('Accès réservé aux administrateurs.');

    const { user, authToken } = await this.usersService.create(createUserDto);
    return { user, authToken }; // Retourne l'utilisateur et son token
  }
}
