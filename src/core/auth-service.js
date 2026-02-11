/**
 * Authentication Service
 * Core business logic for authentication operations
 */

export class AuthService {
  constructor(dependencies) {
    this.userRepo = dependencies.userRepo;
    this.sessionRepo = dependencies.sessionRepo;
    this.authLogRepo = dependencies.authLogRepo;
    this.passwordService = dependencies.passwordService;
    this.jwtService = dependencies.jwtService;
    this.refreshTokenService = dependencies.refreshTokenService;
    
    this.maxFailedAttempts = dependencies.config?.maxFailedAttempts || 5;
    this.lockoutMinutes = dependencies.config?.lockoutMinutes || 15;
  }

  /**
   * Register new user
   */
  async register(userData, context) {
    const { email, password, role, tenantId, companyName, isSelfRegistration } = userData;
    const { ip, userAgent } = context;

    let finalTenantId = tenantId;

    // SELF-REGISTRATION: Crear nuevo tenant
    if (isSelfRegistration) {
      // Generar ID único para el tenant
      finalTenantId = this._generateId();

      // Crear tenant
      const tenantData = {
        id: finalTenantId,
        name: companyName,
        legalName: companyName,
        plan: 'basic',
        status: 'active',
        maxUsers: 5,
        maxProducts: 100,
        createdAt: new Date().toISOString()
      };

      await this.userRepo.createTenant(tenantData);

      await this._logEvent(null, finalTenantId, 'tenant_created', ip, userAgent, {
        tenantName: companyName
      });
    } else {
      // INVITE-REGISTRATION: Validar tenant existente
      const tenant = await this.userRepo.getTenantById(finalTenantId);
      if (!tenant) {
        throw new AuthError('Invalid tenant', 400);
      }
      if (tenant.status !== 'active') {
        throw new AuthError('Tenant is not active', 403);
      }

      // Verificar límite de usuarios del tenant
      const userCount = await this.userRepo.countActiveUsers(finalTenantId);
      if (userCount >= tenant.max_users) {
        throw new AuthError('Tenant user limit reached', 403, {
          max_users: tenant.max_users,
          current_users: userCount
        });
      }
    }

    // Validar email único
    const existingUser = await this.userRepo.findByEmail(email);
    if (existingUser) {
      await this._logEvent(null, finalTenantId, 'register_failed', ip, userAgent, {
        email,
        reason: 'email_already_exists'
      });
      throw new AuthError('Email already registered', 409);
    }

    // Validar fortaleza de contraseña
    this._validatePasswordStrength(password);

    // Hash de contraseña
    const passwordHash = await this.passwordService.hash(password);

    // Crear usuario
    const userId = this._generateId();
    const now = new Date().toISOString();

    const newUser = {
      id: userId,
      tenantId: finalTenantId,
      email,
      passwordHash,
      role,
      isActive: true,
      emailVerified: false,
      mfaEnabled: false,
      failedAttempts: 0,
      createdAt: now,
      updatedAt: now
    };

    await this.userRepo.create(newUser);

    // Log registro exitoso
    await this._logEvent(userId, finalTenantId, 'user_registered', ip, userAgent, {
      email,
      role,
      registrationType: isSelfRegistration ? 'self' : 'invite'
    });

    return {
      id: userId,
      email,
      role,
      tenant_id: finalTenantId,
      tenant_name: isSelfRegistration ? companyName : undefined,
      message: 'User registered successfully'
    };
  }

  /**
   * Authenticate user with email and password
   */
  async login(credentials, context) {
    const { email, password } = credentials;
    const { ip, userAgent } = context;

    // Find user
    const user = await this.userRepo.findByEmail(email);
    
    if (!user) {
      await this._logEvent(null, null, 'login_failed', ip, userAgent, {
        email,
        reason: 'user_not_found'
      });
      throw new AuthError('Invalid credentials', 401);
    }

    // Check tenant status
    if (!(await this.userRepo.isTenantActive(user))) {
      await this._logEvent(user.id, user.tenant_id, 'login_failed', ip, userAgent, {
        email,
        reason: 'tenant_suspended'
      });
      throw new AuthError('Account suspended. Contact administrator.', 403);
    }

    // Check account lock
    if (await this.userRepo.isAccountLocked(user)) {
      await this._logEvent(user.id, user.tenant_id, 'login_failed', ip, userAgent, {
        email,
        reason: 'account_locked'
      });
      throw new AuthError(`Account locked until ${user.locked_until}`, 403);
    }

    // Verify password
    const isValidPassword = await this.passwordService.verify(password, user.password_hash);
    
    if (!isValidPassword) {
      await this._handleFailedLogin(user, email, ip, userAgent);
      const attemptsRemaining = Math.max(0, this.maxFailedAttempts - (user.failed_attempts + 1));
      throw new AuthError('Invalid credentials', 401, { attempts_remaining: attemptsRemaining });
    }

    // Reset failed attempts
    await this.userRepo.resetFailedAttempts(user.id);

    // Generate tokens
    const { token: accessToken, jti } = await this.jwtService.generate({
      sub: user.id,
      tenant: user.tenant_id,
      role: user.role,
      email: user.email
    });

    const refreshTokenData = await this.refreshTokenService.generate();

    // Create session
    await this.sessionRepo.create({
      id: this._generateId(),
      userId: user.id,
      tenantId: user.tenant_id,
      refreshTokenHash: refreshTokenData.hash,
      jti,
      expiresAt: refreshTokenData.expiresAt,
      createdAt: new Date().toISOString()
    });

    // Log success
    await this._logEvent(user.id, user.tenant_id, 'login_success', ip, userAgent, { email });

    return {
      accessToken,
      refreshToken: refreshTokenData.token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        tenantId: user.tenant_id,
        tenantName: user.tenant_name
      },
      expiresIn: 28800
    };
  }

  /**
   * Refresh access token with rotation
   */
  async refresh(refreshToken, context) {
    const { ip, userAgent } = context;

    const tokenHash = await this.refreshTokenService.hash(refreshToken);
    const session = await this.sessionRepo.findByRefreshToken(tokenHash);

    if (!session) {
      throw new AuthError('Invalid or expired token', 401);
    }

    // Revoke old session (rotation)
    await this.sessionRepo.revoke(session.id);

    // Generate new tokens
    const { token: newAccessToken, jti: newJti } = await this.jwtService.generate({
      sub: session.user_id,
      tenant: session.tenant_id,
      role: session.role,
      email: session.email
    });

    const newRefreshTokenData = await this.refreshTokenService.generate();

    // Create new session
    await this.sessionRepo.create({
      id: this._generateId(),
      userId: session.user_id,
      tenantId: session.tenant_id,
      refreshTokenHash: newRefreshTokenData.hash,
      jti: newJti,
      expiresAt: newRefreshTokenData.expiresAt,
      createdAt: new Date().toISOString()
    });

    // Log refresh
    await this._logEvent(session.user_id, session.tenant_id, 'token_refresh', ip, userAgent, {});

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshTokenData.token,
      expiresIn: 28800
    };
  }

  /**
   * Logout user
   */
  async logout(token, context) {
    const { ip, userAgent } = context;

    const verification = await this.jwtService.verify(token);
    
    if (!verification.valid) {
      throw new AuthError('Invalid token', 401);
    }

    const { payload } = verification;

    // Revoke all sessions for user
    await this.sessionRepo.revokeAllForUser(payload.sub);

    // Log logout
    await this._logEvent(payload.sub, payload.tenant, 'logout', ip, userAgent, {});

    return { message: 'Logout successful' };
  }

  /**
   * Verify access token
   */
  async verify(token) {
    const verification = await this.jwtService.verify(token);
    
    if (!verification.valid) {
      return { valid: false };
    }

    const { payload } = verification;

    // Check if session is still valid (not revoked)
    const session = await this.sessionRepo.findByJti(payload.jti);
    if (!session) {
      return { valid: false };
    }

    // Get user data
    const user = await this.userRepo.findById(payload.sub);
    if (!user) {
      return { valid: false };
    }

    return {
      valid: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        tenantId: user.tenant_id
      }
    };
  }

  async _handleFailedLogin(user, email, ip, userAgent) {
    const newFailedAttempts = user.failed_attempts + 1;
    let lockedUntil = null;

    if (newFailedAttempts >= this.maxFailedAttempts) {
      lockedUntil = new Date(Date.now() + this.lockoutMinutes * 60 * 1000).toISOString();
    }

    await this.userRepo.updateFailedAttempts(user.id, newFailedAttempts, lockedUntil);

    await this._logEvent(user.id, user.tenant_id, 'login_failed', ip, userAgent, {
      email,
      reason: 'invalid_password',
      attempts: newFailedAttempts
    });
  }

  async _logEvent(userId, tenantId, event, ip, userAgent, metadata) {
    await this.authLogRepo.log({
      id: this._generateId(),
      userId,
      tenantId,
      event,
      ip,
      userAgent,
      metadata,
      createdAt: new Date().toISOString()
    });
  }

  _generateId() {
    const timestamp = Date.now();
    const random = Math.random().toString(36).slice(2, 11);
    return `${timestamp}-${random}`;
  }

  _validatePasswordStrength(password) {
    if (!password || password.length < 8) {
      throw new AuthError('Password must be at least 8 characters', 400);
    }

    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
      throw new AuthError(
        'Password must contain uppercase, lowercase, number and special character',
        400
      );
    }
  }
}

export class AuthError extends Error {
  constructor(message, statusCode, data = {}) {
    super(message);
    this.statusCode = statusCode;
    this.data = data;
  }
}
