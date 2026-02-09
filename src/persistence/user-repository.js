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

  async create(userData) {
    const query = `
      INSERT INTO users (
        id, tenant_id, email, password_hash, role,
        is_active, email_verified, mfa_enabled, failed_attempts,
        created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    return await this.db
      .prepare(query)
      .bind(
        userData.id,
        userData.tenantId,
        userData.email,
        userData.passwordHash,
        userData.role,
        userData.isActive ? 1 : 0,
        userData.emailVerified ? 1 : 0,
        userData.mfaEnabled ? 1 : 0,
        userData.failedAttempts || 0,
        userData.createdAt,
        userData.updatedAt
      )
      .run();
  }

  async getTenantById(tenantId) {
    return await this.db
      .prepare('SELECT * FROM tenants WHERE id = ?')
      .bind(tenantId)
      .first();
  }

  async createTenant(tenantData) {
    const query = `
      INSERT INTO tenants (
        id, name, legal_name, plan, status, 
        max_users, max_products, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

    return await this.db
      .prepare(query)
      .bind(
        tenantData.id,
        tenantData.name,
        tenantData.legalName || tenantData.name,
        tenantData.plan || 'basic',
        tenantData.status || 'active',
        tenantData.maxUsers || 5,
        tenantData.maxProducts || 100,
        tenantData.createdAt
      )
      .run();
  }

  async countActiveUsers(tenantId) {
    const result = await this.db
      .prepare('SELECT COUNT(*) as count FROM users WHERE tenant_id = ? AND is_active = 1')
      .bind(tenantId)
      .first();
    
    return result ? result.count : 0;
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
