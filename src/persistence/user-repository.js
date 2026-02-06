/**
 * User Repository
 * Handles all user-related database operations
 */

export class UserRepository {
  constructor(db) {
    this.db = db;
  }

  async findByEmail(email) {
    const query = `
      SELECT 
        u.*,
        t.name as tenant_name,
        t.status as tenant_status
      FROM users u
      JOIN tenants t ON u.tenant_id = t.id
      WHERE u.email = ?
    `;

    return await this.db
      .prepare(query)
      .bind(email)
      .first();
  }

  async findById(id) {
    return await this.db
      .prepare('SELECT * FROM users WHERE id = ?')
      .bind(id)
      .first();
  }

  async updateFailedAttempts(userId, attempts, lockedUntil = null) {
    return await this.db
      .prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?')
      .bind(attempts, lockedUntil, userId)
      .run();
  }

  async resetFailedAttempts(userId) {
    return await this.db
      .prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?')
      .bind(new Date().toISOString(), userId)
      .run();
  }

  async isAccountLocked(user) {
    if (!user.locked_until) {
      return false;
    }
    return new Date(user.locked_until) > new Date();
  }

  async isTenantActive(user) {
    return user.tenant_status === 'active';
  }
}
