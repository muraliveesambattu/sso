/**
 * State Store — in-memory, TTL-based key/value store.
 *
 * Backs the OIDC login flow's short-lived entries (state / nonce / code_verifier),
 * keyed by `state` with a 10-minute TTL. Self-expiring and single-use.
 *
 * NOTE: this is per-instance memory. If the /domain-check and /token-exchange
 * requests land on different Cloud Run instances, a shared store would be needed;
 * the short TTL + low concurrency make in-memory sufficient here.
 *
 * Usage:
 *   const { stateStore } = require('./stateStore');
 *   await stateStore.set(key, value, ttlSeconds);
 *   await stateStore.get(key);
 *   await stateStore.del(key);
 */

const { logger } = require('./logger');

class MemoryStateStore {
  constructor() {
    this.map = new Map();
    // No module-load setInterval — background timers can delay Cloud Function
    // instance recycling. Expiry is lazy: get() purges on read, and set() does
    // an opportunistic sweep so abandoned (never-read) entries can't accumulate.
  }

  async set(key, value, ttlSeconds = 600) {
    this._cleanup();
    this.map.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  }

  async get(key) {
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.map.delete(key);
      return null;
    }
    return entry.value;
  }

  async del(key) {
    this.map.delete(key);
  }

  _cleanup() {
    const now = Date.now();
    for (const [key, entry] of this.map.entries()) {
      if (now > entry.expiresAt) this.map.delete(key);
    }
  }
}

const stateStore = new MemoryStateStore();
logger.debug('[STATE-STORE] In-memory state store initialised');

module.exports = { stateStore };
