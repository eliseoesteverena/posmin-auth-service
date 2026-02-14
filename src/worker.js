/**
 * Cloudflare Worker - Auth Service
 * Main entry point with dependency injection
 */

import { UserRepository } from './persistence/user-repository.js';
import { SessionRepository } from './persistence/session-repository.js';
import { AuthLogRepository } from './persistence/auth-log-repository.js';
import { PasswordService } from './crypto/password.js';
import { JWTService } from './crypto/jwt.js';
import { RefreshTokenService } from './crypto/refresh-token.js';
import { AuthService } from './core/auth-service.js';
import { AuthRoutes } from './routes/auth-routes.js';
import { CorsMiddleware } from './middleware/cors.js';
import { RateLimitMiddleware } from './middleware/rate-limit.js';

export default {
  async fetch(request, env, ctx) {
    // Initialize dependencies
    const dependencies = this._initializeDependencies(env);
    const { authRoutes, cors, rateLimit } = dependencies;

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Handle CORS preflight
    if (method === 'OPTIONS') {
      return cors.handlePreflight(request);
    }

    try {
      // Rate limiting (optional, can be enabled per route)
      // const rateLimitCheck = await rateLimit.checkLimit(request);
      // if (!rateLimitCheck.allowed) {
      //   return rateLimit.createRateLimitResponse(rateLimitCheck.resetAt);
      // }

      // Route handling
      let response;

      if (path === '/health' && method === 'GET') {
        response = this._jsonResponse({
          status: 'ok',
          timestamp: new Date().toISOString()
        });
      } 

      // Auth
      
      else if ((path === '/register' || path === '/auth/register') && method === 'POST') {
        const result = await authRoutes.handleRegister(request);
        response = this._jsonResponse(result.data, result.status);
      } else if ((path === '/login' || path === '/auth/login') && method === 'POST') {
        const result = await authRoutes.handleLogin(request);
        response = this._jsonResponse(result.data, result.status);
      } else if ((path === '/refresh' || path === '/auth/refresh') && method === 'POST') {
        const result = await authRoutes.handleRefresh(request);
        response = this._jsonResponse(result.data, result.status);
      } else if ((path === '/logout' || path === '/auth/logout') && method === 'POST') {
        const result = await authRoutes.handleLogout(request);
        response = this._jsonResponse(result.data, result.status);
      } else if ((path === '/verify' || path === '/auth/verify') && method === 'GET') {
        const result = await authRoutes.handleVerify(request);
        response = this._jsonResponse(result.data, result.status);
      } 
      // Negocio
      // Rutas de productos
      if (path === '/api/products' && method === 'GET') {
        const result = await productRoutes.handleListProducts(request, context);
        response = this._jsonResponse(result.data, result.status);
      }
      else if (path === '/api/products' && method === 'POST') {
        const result = await productRoutes.handleCreateProduct(request, context);
        response = this._jsonResponse(result.data, result.status);
      }
      
      else {
        response = this._jsonResponse({ error: 'Route not found' }, 404);
      }

      // Add CORS headers
      return cors.addHeaders(response, request);

    } catch (error) {
      console.error('Worker error:', error);
      const errorResponse = this._jsonResponse(
        { error: 'Internal server error' },
        500
      );
      return cors.addHeaders(errorResponse, request);
    }
  },

  _initializeDependencies(env) {
    // Repositories
    const userRepo = new UserRepository(env.DB);
    const sessionRepo = new SessionRepository(env.DB);
    const authLogRepo = new AuthLogRepository(env.DB);

    // Crypto services
    const passwordService = new PasswordService({
      saltRounds: 12
    });

    const jwtService = new JWTService(env.JWT_SECRET, {
      issuer: 'auth-service',
      audience: 'api-client'
    });

    const refreshTokenService = new RefreshTokenService({
      tokenLength: 32,
      expiryDays: 30
    });

    // Core service
    const authService = new AuthService({
      userRepo,
      sessionRepo,
      authLogRepo,
      passwordService,
      jwtService,
      refreshTokenService,
      config: {
        maxFailedAttempts: 5,
        lockoutMinutes: 15
      }
    });

    // Routes
    const authRoutes = new AuthRoutes(authService);

    // Middleware
    const cors = new CorsMiddleware({
      allowedOrigins: ['*'],
      allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization']
    });

    const rateLimit = new RateLimitMiddleware({
      windowMs: 15 * 60 * 1000,
      maxRequests: 100
    });

    return {
      authRoutes,
      cors,
      rateLimit,
      authService,
      userRepo,
      sessionRepo,
      authLogRepo
    };
  },

  _jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};
