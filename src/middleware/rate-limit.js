/**
 * Rate Limiting Middleware
 * Uses Cloudflare Durable Objects for distributed rate limiting
 */

export class RateLimitMiddleware {
  constructor(options = {}) {
    this.windowMs = options.windowMs || 15 * 60 * 1000; // 15 minutes
    this.maxRequests = options.maxRequests || 100;
  }

  /**
   * Check rate limit for IP
   * In production, use Cloudflare Durable Objects or KV for distributed state
   */
  async checkLimit(request, identifier = null) {
    const key = identifier || this._getIdentifier(request);
    
    // TODO: Implement with Durable Objects or KV
    // For now, return allowed
    return {
      allowed: true,
      remaining: this.maxRequests,
      resetAt: Date.now() + this.windowMs
    };
  }

  _getIdentifier(request) {
    return request.headers.get('cf-connecting-ip') || 
           request.headers.get('x-forwarded-for') || 
           'unknown';
  }

  createRateLimitResponse(resetAt) {
    return new Response(
      JSON.stringify({ error: 'Too many requests' }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': Math.ceil((resetAt - Date.now()) / 1000).toString()
        }
      }
    );
  }
}
