import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import { PrismaAuthService } from './prisma-auth.service';
import { CreateUserInput, LoginInput, RefreshTokenInput } from './dto/auth.input';
import { AuthPayload, TokenPayload } from './dto/auth.types';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly prismaAuth: PrismaAuthService,
  ) {}

  async register(input: CreateUserInput): Promise<AuthPayload> {
    const existingUser = await this.prismaAuth.findUserByEmail(input.email);
    if (existingUser) {
      throw new BadRequestException('User already exists');
    }

    const hashedPassword = await this.hashPassword(input.password);
    const user = await this.prismaAuth.createUser({
      ...input,
      password: hashedPassword,
    });

    const tokens = await this.generateTokens(user.id, user.email);
    await this.storeRefreshToken(user.id, tokens.refreshToken);

    return {
      user: {
        id: user.id.toString(),
        email: user.email,
        createdAt: user.createdAt,
      },
      ...tokens,
    };
  }

  async login(input: LoginInput): Promise<AuthPayload> {
    const user = await this.prismaAuth.findUserByEmail(input.email);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await this.verifyPassword(input.password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const tokens = await this.generateTokens(user.id, user.email);
    await this.storeRefreshToken(user.id, tokens.refreshToken);

    return {
      user: {
        id: user.id.toString(),
        email: user.email,
        createdAt: user.createdAt,
      },
      ...tokens,
    };
  }

  async refreshTokens(input: RefreshTokenInput): Promise<Omit<AuthPayload, 'user'>> {
    try {
      const payload = this.jwtService.verify(input.refreshToken, {
        secret: this.configService.get<string>('app.JWT_SECRET'),
      });

      const storedToken = await this.prismaAuth.findRefreshToken(payload.sub, input.refreshToken);
      if (!storedToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      const user = await this.prismaAuth.findUserById(parseInt(payload.sub));
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Revoke old refresh token
      await this.prismaAuth.revokeRefreshToken(payload.sub, input.refreshToken);

      // Generate new tokens
      const tokens = await this.generateTokens(user.id, user.email);
      await this.storeRefreshToken(user.id, tokens.refreshToken);

      return tokens;
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async logout(userId: string, refreshToken: string): Promise<void> {
    await this.prismaAuth.revokeRefreshToken(userId, refreshToken);
  }

  async logoutAll(userId: string): Promise<void> {
    await this.prismaAuth.revokeAllRefreshTokens(userId);
  }

  async validateUser(payload: TokenPayload) {
    const user = await this.prismaAuth.findUserById(parseInt(payload.sub));
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    return {
      id: user.id.toString(),
      email: user.email,
    };
  }

  private async generateTokens(userId: number, email: string) {
    const payload: TokenPayload = {
      sub: userId.toString(),
      email,
      iat: Math.floor(Date.now() / 1000),
      type: 'access',
    };

    const refreshPayload: TokenPayload = {
      ...payload,
      type: 'refresh',
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        expiresIn: this.configService.get<string>('app.JWT_EXPIRES_IN'),
      }),
      this.jwtService.signAsync(refreshPayload, {
        expiresIn: this.configService.get<string>('app.JWT_REFRESH_EXPIRES_IN'),
      }),
    ]);

    return {
      accessToken,
      refreshToken,
      expiresIn: this.parseExpirationTime(this.configService.get<string>('app.JWT_EXPIRES_IN')),
    };
  }

  private async storeRefreshToken(userId: number, refreshToken: string): Promise<void> {
    const expiresAt = new Date();
    const expirationTime = this.parseExpirationTime(
      this.configService.get<string>('app.JWT_REFRESH_EXPIRES_IN')
    );
    expiresAt.setSeconds(expiresAt.getSeconds() + expirationTime);

    await this.prismaAuth.createRefreshToken({
      userId,
      token: refreshToken,
      expiresAt,
    });
  }

  private async hashPassword(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16,
      timeCost: 3,
      parallelism: 1,
    });
  }

  private async verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
    try {
      return await argon2.verify(hashedPassword, password);
    } catch {
      return false;
    }
  }

  private parseExpirationTime(expiration: string): number {
    const unit = expiration.slice(-1);
    const value = parseInt(expiration.slice(0, -1));
    
    switch (unit) {
      case 's': return value;
      case 'm': return value * 60;
      case 'h': return value * 60 * 60;
      case 'd': return value * 60 * 60 * 24;
      default: return 900; // 15 minutes default
    }
  }
}
