// src/users/users.service.ts

import { Injectable, NotFoundException, ForbiddenException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service.js';
import { CreateUserDto } from './dto/create-user.dto.js';
import { UpdateUserDto } from './dto/update-user.dto.js';
import { Role } from '../../generated/prisma/client.js';
import * as jwt from 'jsonwebtoken';
import * as bcrypt from 'bcrypt';
import { MailService } from '../mail/mail.service.js';


/**
 * Service gérant la logique métier pour les utilisateurs (agents)
 */
@Injectable()
export class UsersService {
  constructor(
    private prisma: PrismaService,
    private mailService: MailService,
  ) {}

  /**
   * Création d’un utilisateur (agent).
   */
  async create(createUserDto: CreateUserDto) {
    // 🔍 Vérification CP ou email déjà existant
    const existingUser = await this.prisma.utilisateur.findFirst({
      where: {
        OR: [
          { cp: createUserDto.cp },
          { email: createUserDto.email },
        ],
      },
    });

    if (existingUser) {
      throw new BadRequestException(
        'Un utilisateur avec ce CP ou cet email existe déjà',
      );
    }

    const tokenPayload = {
      cp: createUserDto.cp,
      email: createUserDto.email,
      role: createUserDto.role ?? Role.UTILISATEUR,
    };

    const authToken = jwt.sign(tokenPayload, process.env.JWT_SECRET!, {
      expiresIn: '24h',
    });

    const user = await this.prisma.utilisateur.create({
      data: {
        ...createUserDto,
        role: createUserDto.role ?? Role.UTILISATEUR,
        authToken,
        mdp: null,
      },
    });

    const resetLink = `${process.env.FRONTEND_URL}/update-password/?cp=${user.cp}&token=${authToken}`;

    await this.mailService.sendCreatePasswordEmail(user.email, resetLink);

    return { user, authToken };
  }



  async findAll() {
    return this.prisma.utilisateur.findMany();
  }

  async findOne(cp: string) {
    return this.prisma.utilisateur.findUnique({
      where: { cp },
    });
  }

  async update(cp: string, updateUserDto: UpdateUserDto) {
    const existing = await this.findOne(cp);
    if (!existing) throw new NotFoundException('Utilisateur non trouvé');

    return this.prisma.utilisateur.update({
      where: { cp },
      data: updateUserDto,
    });
  }

  async remove(cp: string) {
    const existing = await this.findOne(cp);
    if (!existing) throw new NotFoundException('Utilisateur non trouvé');

    return this.prisma.utilisateur.delete({
      where: { cp },
    });
  }

  async completeRegistration(token: string, password: string) {
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET!) as {
        cp: string;
        email: string;
        role: Role;
      };

      const user = await this.findOne(payload.cp);
      if (!user || user.authToken !== token) {
        throw new ForbiddenException('Token invalide ou déjà utilisé');
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      return this.prisma.utilisateur.update({
        where: { cp: payload.cp },
        data: {
          mdp: hashedPassword,
          authToken: null,
        },
      });
    } catch {
      throw new ForbiddenException('Token invalide ou expiré');
    }
  }
}
