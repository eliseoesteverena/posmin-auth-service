/**
 * Session Repository
 * Handles all session-related database operations
 */

export class SessionRepository {
  constructor(db) {
    this.db = db;
  }

  async create(sessionData) {
    const query = `
      INSERT INTO sessions (id, user_id, refresh_token_hash, jti, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

    return await this.db
      .prepare(query)
      .bind(
        sessionData.id,
        sessionData.userId,
        sessionData.refreshTokenHash,
        sessionData.jti,
        sessionData.expiresAt,
        sessionData.createdAt
      )
      .run();
  }

  async findByRefreshToken(tokenHash) {
    const query = `
      SELECT 
        s.*,
        u.email,
        u.role,
        u.tenant_id
      FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.refresh_token_hash = ?
        AND s.revoked_at IS NULL
        AND datetime(s.expires_at) > datetime('now')
    `;

    return await this.db
      .prepare(query)
      .bind(tokenHash)
      .first();
  }

  async findByJti(jti) {
    return await this.db
      .prepare(`
        SELECT id 
        FROM sessions 
        WHERE jti = ? 
          AND revoked_at IS NULL 
          AND datetime(expires_at) > datetime('now')
      `)
      .bind(jti)
      .first();
  }

  async revoke(sessionId) {
    return await this.db
      .prepare('UPDATE sessions SET revoked_at = ? WHERE id = ?')
      .bind(new Date().toISOString(), sessionId)
      .run();
  }

  async revokeAllForUser(userId) {
    return await this.db
      .prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL')
      .bind(new Date().toISOString(), userId)
      .run();
  }

  async cleanupExpired() {
    return await this.db
      .prepare("DELETE FROM sessions WHERE datetime(expires_at) < datetime('now')")
      .run();
  }
}
