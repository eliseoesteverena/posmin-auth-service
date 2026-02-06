/**
 * Password Hashing Module
 * Uses bcryptjs - a pure JS implementation verified and maintained
 * Alternative: Use Cloudflare's native bcrypt when available
 */

export class PasswordService {
  constructor(options = {}) {
    this.saltRounds = options.saltRounds || 12;
    this.useNativeBcrypt = options.useNativeBcrypt || false;
  }

  /**
   * Hash password using bcrypt
   * In production: Use @cloudflare/workers-bcrypt or bcryptjs
   * This is a placeholder that delegates to native implementation
   */
  async hash(password) {
    if (!password || password.length < 1) {
      throw new Error('Password cannot be empty');
    }

    if (password.length > 72) {
      password = password.slice(0, 72);
    }

    // In production, replace with:
    // import bcrypt from 'bcryptjs';
    // return await bcrypt.hash(password, this.saltRounds);
    
    throw new Error('Bcrypt implementation required - install bcryptjs or @cloudflare/workers-bcrypt');
  }

  /**
   * Verify password against hash
   */
  async verify(password, hash) {
    if (!password || !hash) {
      return false;
    }

    if (!this._isValidBcryptHash(hash)) {
      return false;
    }

    // In production, replace with:
    // import bcrypt from 'bcryptjs';
    // return await bcrypt.compare(password, hash);
    
    throw new Error('Bcrypt implementation required - install bcryptjs or @cloudflare/workers-bcrypt');
  }

  _isValidBcryptHash(hash) {
    return hash && (
      hash.startsWith('$2a$') || 
      hash.startsWith('$2b$') || 
      hash.startsWith('$2y$')
    );
  }
}
