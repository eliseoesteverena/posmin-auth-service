/**
 * Example Unit Tests
 * Run with: npm test
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuthService, AuthError } from '../src/core/auth-service.js';

describe('AuthService', () => {
  let authService;
  let mockDeps;

  beforeEach(() => {
    // Create mocks for all dependencies
    mockDeps = {
      userRepo: {
        findByEmail: vi.fn(),
        findById: vi.fn(),
        isAccountLocked: vi.fn(),
        isTenantActive: vi.fn(),
        resetFailedAttempts: vi.fn(),
        updateFailedAttempts: vi.fn()
      },
      sessionRepo: {
        create: vi.fn(),
        findByRefreshToken: vi.fn(),
        findByJti: vi.fn(),
        revoke: vi.fn(),
        revokeAllForUser: vi.fn()
      },
      authLogRepo: {
        log: vi.fn()
      },
      passwordService: {
        verify: vi.fn()
      },
      jwtService: {
        generate: vi.fn(),
        verify: vi.fn()
      },
      refreshTokenService: {
        generate: vi.fn(),
        hash: vi.fn()
      },
      config: {
        maxFailedAttempts: 5,
        lockoutMinutes: 15
      }
    };

    authService = new AuthService(mockDeps);
  });

  describe('login', () => {
    it('should successfully authenticate valid credentials', async () => {
      // Arrange
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        password_hash: '$2b$12$hash',
        tenant_id: 'tenant-1',
        tenant_name: 'Test Tenant',
        tenant_status: 'active',
        role: 'user',
        failed_attempts: 0
      };

      mockDeps.userRepo.findByEmail.mockResolvedValue(mockUser);
      mockDeps.userRepo.isTenantActive.mockResolvedValue(true);
      mockDeps.userRepo.isAccountLocked.mockResolvedValue(false);
      mockDeps.passwordService.verify.mockResolvedValue(true);
      mockDeps.jwtService.generate.mockResolvedValue({
        token: 'jwt-token',
        jti: 'jti-123',
        expiresAt: 1234567890
      });
      mockDeps.refreshTokenService.generate.mockResolvedValue({
        token: 'refresh-token',
        hash: 'refresh-hash',
        expiresAt: '2024-01-01T00:00:00.000Z'
      });

      // Act
      const result = await authService.login(
        { email: 'test@example.com', password: 'password123' },
        { ip: '127.0.0.1', userAgent: 'test-agent' }
      );

      // Assert
      expect(result.accessToken).toBe('jwt-token');
      expect(result.refreshToken).toBe('refresh-token');
      expect(result.user.email).toBe('test@example.com');
      expect(mockDeps.userRepo.resetFailedAttempts).toHaveBeenCalledWith('user-123');
      expect(mockDeps.sessionRepo.create).toHaveBeenCalled();
      expect(mockDeps.authLogRepo.log).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'login_success'
        })
      );
    });

    it('should reject invalid password', async () => {
      // Arrange
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        password_hash: '$2b$12$hash',
        tenant_id: 'tenant-1',
        tenant_status: 'active',
        role: 'user',
        failed_attempts: 0
      };

      mockDeps.userRepo.findByEmail.mockResolvedValue(mockUser);
      mockDeps.userRepo.isTenantActive.mockResolvedValue(true);
      mockDeps.userRepo.isAccountLocked.mockResolvedValue(false);
      mockDeps.passwordService.verify.mockResolvedValue(false);

      // Act & Assert
      await expect(
        authService.login(
          { email: 'test@example.com', password: 'wrong-password' },
          { ip: '127.0.0.1', userAgent: 'test-agent' }
        )
      ).rejects.toThrow(AuthError);

      expect(mockDeps.userRepo.updateFailedAttempts).toHaveBeenCalledWith(
        'user-123',
        1,
        null
      );
    });

    it('should lock account after max failed attempts', async () => {
      // Arrange
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        password_hash: '$2b$12$hash',
        tenant_id: 'tenant-1',
        tenant_status: 'active',
        role: 'user',
        failed_attempts: 4 // One more attempt will lock
      };

      mockDeps.userRepo.findByEmail.mockResolvedValue(mockUser);
      mockDeps.userRepo.isTenantActive.mockResolvedValue(true);
      mockDeps.userRepo.isAccountLocked.mockResolvedValue(false);
      mockDeps.passwordService.verify.mockResolvedValue(false);

      // Act
      try {
        await authService.login(
          { email: 'test@example.com', password: 'wrong-password' },
          { ip: '127.0.0.1', userAgent: 'test-agent' }
        );
      } catch (error) {
        // Expected to throw
      }

      // Assert
      expect(mockDeps.userRepo.updateFailedAttempts).toHaveBeenCalledWith(
        'user-123',
        5,
        expect.any(String) // lockedUntil timestamp
      );
    });

    it('should reject login for suspended tenant', async () => {
      // Arrange
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        tenant_id: 'tenant-1',
        tenant_status: 'suspended'
      };

      mockDeps.userRepo.findByEmail.mockResolvedValue(mockUser);
      mockDeps.userRepo.isTenantActive.mockResolvedValue(false);

      // Act & Assert
      await expect(
        authService.login(
          { email: 'test@example.com', password: 'password123' },
          { ip: '127.0.0.1', userAgent: 'test-agent' }
        )
      ).rejects.toThrow('Account suspended');
    });
  });

  describe('refresh', () => {
    it('should rotate refresh token', async () => {
      // Arrange
      const mockSession = {
        id: 'session-123',
        user_id: 'user-123',
        tenant_id: 'tenant-1',
        role: 'user',
        email: 'test@example.com'
      };

      mockDeps.refreshTokenService.hash.mockResolvedValue('token-hash');
      mockDeps.sessionRepo.findByRefreshToken.mockResolvedValue(mockSession);
      mockDeps.jwtService.generate.mockResolvedValue({
        token: 'new-jwt-token',
        jti: 'new-jti',
        expiresAt: 1234567890
      });
      mockDeps.refreshTokenService.generate.mockResolvedValue({
        token: 'new-refresh-token',
        hash: 'new-refresh-hash',
        expiresAt: '2024-01-01T00:00:00.000Z'
      });

      // Act
      const result = await authService.refresh(
        'old-refresh-token',
        { ip: '127.0.0.1', userAgent: 'test-agent' }
      );

      // Assert
      expect(result.accessToken).toBe('new-jwt-token');
      expect(result.refreshToken).toBe('new-refresh-token');
      expect(mockDeps.sessionRepo.revoke).toHaveBeenCalledWith('session-123');
      expect(mockDeps.sessionRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-123',
          refreshTokenHash: 'new-refresh-hash',
          jti: 'new-jti'
        })
      );
    });
  });

  describe('verify', () => {
    it('should validate token with active session', async () => {
      // Arrange
      const mockPayload = {
        sub: 'user-123',
        jti: 'jti-123',
        tenant: 'tenant-1'
      };

      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        role: 'user',
        tenant_id: 'tenant-1'
      };

      mockDeps.jwtService.verify.mockResolvedValue({
        valid: true,
        payload: mockPayload
      });
      mockDeps.sessionRepo.findByJti.mockResolvedValue({ id: 'session-123' });
      mockDeps.userRepo.findById.mockResolvedValue(mockUser);

      // Act
      const result = await authService.verify('valid-token');

      // Assert
      expect(result.valid).toBe(true);
      expect(result.user.id).toBe('user-123');
    });

    it('should reject token with revoked session', async () => {
      // Arrange
      mockDeps.jwtService.verify.mockResolvedValue({
        valid: true,
        payload: { sub: 'user-123', jti: 'jti-123' }
      });
      mockDeps.sessionRepo.findByJti.mockResolvedValue(null);

      // Act
      const result = await authService.verify('token-with-revoked-session');

      // Assert
      expect(result.valid).toBe(false);
    });
  });
});
