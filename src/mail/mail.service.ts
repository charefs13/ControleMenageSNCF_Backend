// src/mail/mail.service.ts

import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

/**
 * Service dédié à l'envoi d'emails.
 */
@Injectable()
export class MailService {
  private transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT),
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }

  async sendMail(to: string, subject: string, html: string) {
    await this.transporter.sendMail({
      from: `"Support SNCF" <${process.env.SMTP_USER}>`,
      to,
      subject,
      html,
    });
  }

  async sendResetPasswordEmail(to: string, resetLink: string) {
    const html = `
      <p>Bonjour,</p>
      <br/>
      <p>Cliquez sur le lien ci-dessous pour réinitialiser votre mot de passe :</p>
      <a href="${resetLink}">${resetLink}</a>
      <br/>
      <p>Ce lien expire dans 2 heures.</p>
      <br/>
      <p>Si vous n'avez pas demandé cette réinitialisation, ignorez cet email.</p>
      <br/>
      <p>Cordialement,<br/>L'équipe SNCF FMLP PACA</p>
    `;

    await this.sendMail(to, 'Réinitialisation de votre mot de passe', html);
  }

  async sendCreatePasswordEmail(to: string, resetLink: string) {
    const html = `
      <p>Bonjour,</p>
      <br/>
      <p>Un administrateur vous a ajouté en tant qu'utilisateur de l'application de contrôle de nettoyage de la SNCF.</p>
      <br/>
      <p>Cliquez sur le lien ci-dessous pour créer votre mot de passe :</p>
      <a href="${resetLink}">${resetLink}</a>
      <br/>
      <p>Ce lien expire dans 24 heures.</p>
      <br/>
      <p>Cordialement,<br/>L'équipe SNCF FMLP PACA</p>
    `;

    await this.sendMail(to, 'Création de votre mot de passe', html);
  }
}
