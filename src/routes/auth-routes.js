/**
 * Auth Routes Handler
 * HTTP layer - translates HTTP requests to service calls
 */

import { AuthError } from '../core/auth-service.js';

export class AuthRoutes {
  constructor(authService) {
    this.authService = authService;
  }

  async handleLogin(request) {
    const { email, password } = await request.json();

    if (!email || !password) {
      return this._errorResponse('Email and password required', 400);
    }

    try {
      const result = await this.authService.login(
        { email, password },
        this._getContext(request)
      );

      return this._successResponse(result);
    } catch (error) {
      return this._handleError(error);
    }
  }

  async handleRefresh(request) {
    const { refresh_token } = await request.json();

    if (!refresh_token) {
      return this._errorResponse('Refresh token required', 400);
    }

    try {
      const result = await this.authService.refresh(
        refresh_token,
        this._getContext(request)
      );

      return this._successResponse(result);
    } catch (error) {
      return this._handleError(error);
    }
  }

  async handleLogout(request) {
    const token = this._extractToken(request);

    if (!token) {
      return this._errorResponse('No authorization', 401);
    }

    try {
      const result = await this.authService.logout(
        token,
        this._getContext(request)
      );

      return this._successResponse(result);
    } catch (error) {
      return this._handleError(error);
    }
  }

  async handleVerify(request) {
    const token = this._extractToken(request);

    if (!token) {
      return this._successResponse({ valid: false }, 401);
    }

    try {
      const result = await this.authService.verify(token);
      return this._successResponse(result, result.valid ? 200 : 401);
    } catch (error) {
      return this._handleError(error);
    }
  }

  _extractToken(request) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader) return null;
    return authHeader.replace('Bearer ', '');
  }

  _getContext(request) {
    return {
      ip: request.headers.get('cf-connecting-ip') || 
          request.headers.get('x-forwarded-for') || 
          'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown'
    };
  }

  _successResponse(data, status = 200) {
    return {
      status,
      data
    };
  }

  _errorResponse(message, status = 400, data = {}) {
    return {
      status,
      data: {
        error: message,
        ...data
      }
    };
  }

  _handleError(error) {
    if (error instanceof AuthError) {
      return this._errorResponse(error.message, error.statusCode, error.data);
    }

    console.error('Unexpected error:', error);
    return this._errorResponse('Internal server error', 500);
  }
}
