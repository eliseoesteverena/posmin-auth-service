/**
 * JWT Service
 * Handles token generation and validation with standard claims
 */

export class JWTService {
  constructor(secret, options = {}) {
    if (!secret) {
      throw new Error('JWT secret is required');
    }
    this.secret = secret;
    this.issuer = options.issuer || 'auth-service';
    this.audience = options.audience || 'api-client';
    this.algorithm = 'HS256';
  }

  /**
   * Generate JWT with standard claims
   */
  async generate(payload, expiresInHours = 8) {
    const now = Math.floor(Date.now() / 1000);
    
    const claims = {
      ...payload,
      iat: now,
      exp: now + (expiresInHours * 3600),
      iss: this.issuer,
      aud: this.audience,
      jti: this._generateJti()
    };

    const header = {
      alg: this.algorithm,
      typ: 'JWT'
    };

    const encodedHeader = this._base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this._base64UrlEncode(JSON.stringify(claims));
    const signatureInput = `${encodedHeader}.${encodedPayload}`;

    const signature = await this._sign(signatureInput);
    const encodedSignature = this._base64UrlEncode(
      String.fromCharCode(...new Uint8Array(signature))
    );

    return {
      token: `${encodedHeader}.${encodedPayload}.${encodedSignature}`,
      jti: claims.jti,
      expiresAt: claims.exp
    };
  }

  /**
   * Verify and decode JWT
   */
  async verify(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return { valid: false, error: 'Invalid token format' };
      }

      const [encodedHeader, encodedPayload, encodedSignature] = parts;
      
      // Verify signature
      const signatureInput = `${encodedHeader}.${encodedPayload}`;
      const signatureBytes = this._base64UrlDecode(encodedSignature);
      
      const isValidSignature = await this._verifySignature(
        signatureInput,
        signatureBytes
      );

      if (!isValidSignature) {
        return { valid: false, error: 'Invalid signature' };
      }

      // Decode and validate payload
      const payload = JSON.parse(
        atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/'))
      );

      // Validate standard claims
      const now = Math.floor(Date.now() / 1000);

      if (!payload.exp || payload.exp < now) {
        return { valid: false, error: 'Token expired' };
      }

      if (!payload.iss || payload.iss !== this.issuer) {
        return { valid: false, error: 'Invalid issuer' };
      }

      if (!payload.aud || payload.aud !== this.audience) {
        return { valid: false, error: 'Invalid audience' };
      }

      if (!payload.jti) {
        return { valid: false, error: 'Missing jti claim' };
      }

      return {
        valid: true,
        payload
      };

    } catch (error) {
      return { valid: false, error: error.message };
    }
  }

  async _sign(data) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(this.secret);
    
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    return await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  }

  async _verifySignature(data, signature) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(this.secret);
    
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    return await crypto.subtle.verify(
      'HMAC',
      key,
      signature,
      encoder.encode(data)
    );
  }

  _base64UrlEncode(str) {
    return btoa(str)
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }

  _base64UrlDecode(str) {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  }

  _generateJti() {
    const timestamp = Date.now();
    const random = crypto.getRandomValues(new Uint8Array(16));
    const randomHex = Array.from(random, b => b.toString(16).padStart(2, '0')).join('');
    return `${timestamp}-${randomHex}`;
  }
}
