import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Tokens } from './types';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async signupLocal(dto: AuthDto): Promise<Tokens> {
    const password = await this.hashData(dto.password);

    const newUser = await this.prisma.user.create({
      data: {
        email: dto.email,
        password,
      },
    });

    const tokens = await this.getTokens(newUser.id, newUser.email);
    this.updateRtHash(newUser.id, tokens.refresh_token);
    return tokens;
  }

  signinLocal() {}

  logout() {}

  refreshToken() {}

  async updateRtHash(userId: string, refreshToken: string) {
    const hash = await this.hashData(refreshToken);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }
  hashData(data: string) {
    return bcrypt.hash(data, 12);
  }

  async getTokens(userId: string, email: string): Promise<Tokens> {
    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: process.env.JWT_SECRET,
          expiresIn: '15m',
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: process.env.JWT_RT_SECRET,
          expiresIn: '2H',
        },
      ),
    ]);

    return {
      access_token,
      refresh_token,
    };
  }
}
