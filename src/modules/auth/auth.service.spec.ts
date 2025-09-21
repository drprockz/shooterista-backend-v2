import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException, BadRequestException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { PrismaAuthService } from './prisma-auth.service';

describe('AuthService', () => {
  let service: AuthService;
  let prismaAuth: jest.Mocked<PrismaAuthService>;
  let jwtService: jest.Mocked<JwtService>;
  let configService: jest.Mocked<ConfigService>;

  const mockUser = {
    id: 1,
    email: 'test@example.com',
    password: 'hashedpassword',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: PrismaAuthService,
          useValue: {
            findUserByEmail: jest.fn(),
            findUserById: jest.fn(),
            createUser: jest.fn(),
            createRefreshToken: jest.fn(),
            findRefreshToken: jest.fn(),
            revokeRefreshToken: jest.fn(),
            revokeAllRefreshTokens: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            signAsync: jest.fn(),
            verify: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    prismaAuth = module.get(PrismaAuthService);
    jwtService = module.get(JwtService);
    configService = module.get(ConfigService);

    // Setup default config values
    configService.get.mockImplementation((key: string) => {
      const config = {
        'app.JWT_SECRET': 'test-secret',
        'app.JWT_EXPIRES_IN': '15m',
        'app.JWT_REFRESH_EXPIRES_IN': '7d',
        'app.JWT_ISS': 'test-issuer',
        'app.JWT_AUD': 'test-audience',
      };
      return config[key];
    });
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('register', () => {
    it('should register a new user successfully', async () => {
      const createUserInput = {
        email: 'test@example.com',
        password: 'password123',
      };

      prismaAuth.findUserByEmail.mockResolvedValue(null);
      prismaAuth.createUser.mockResolvedValue(mockUser);
      jwtService.signAsync.mockResolvedValueOnce('access-token');
      jwtService.signAsync.mockResolvedValueOnce('refresh-token');

      const result = await service.register(createUserInput);

      expect(result).toHaveProperty('user');
      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(result.user.email).toBe(createUserInput.email);
    });

    it('should throw BadRequestException if user already exists', async () => {
      const createUserInput = {
        email: 'test@example.com',
        password: 'password123',
      };

      prismaAuth.findUserByEmail.mockResolvedValue(mockUser);

      await expect(service.register(createUserInput)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('login', () => {
    it('should login user with valid credentials', async () => {
      const loginInput = {
        email: 'test@example.com',
        password: 'password123',
      };

      prismaAuth.findUserByEmail.mockResolvedValue(mockUser);
      jwtService.signAsync.mockResolvedValueOnce('access-token');
      jwtService.signAsync.mockResolvedValueOnce('refresh-token');

      // Mock password verification
      jest.spyOn(service as any, 'verifyPassword').mockResolvedValue(true);

      const result = await service.login(loginInput);

      expect(result).toHaveProperty('user');
      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
    });

    it('should throw UnauthorizedException for invalid credentials', async () => {
      const loginInput = {
        email: 'test@example.com',
        password: 'wrongpassword',
      };

      prismaAuth.findUserByEmail.mockResolvedValue(null);

      await expect(service.login(loginInput)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  describe('validateUser', () => {
    it('should validate user with valid payload', async () => {
      const payload = {
        sub: '1',
        email: 'test@example.com',
        iat: Date.now(),
        type: 'access' as const,
      };

      prismaAuth.findUserById.mockResolvedValue(mockUser);

      const result = await service.validateUser(payload);

      expect(result).toEqual({
        id: '1',
        email: 'test@example.com',
      });
    });

    it('should throw UnauthorizedException for non-existent user', async () => {
      const payload = {
        sub: '999',
        email: 'nonexistent@example.com',
        iat: Date.now(),
        type: 'access' as const,
      };

      prismaAuth.findUserById.mockResolvedValue(null);

      await expect(service.validateUser(payload)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });
});
