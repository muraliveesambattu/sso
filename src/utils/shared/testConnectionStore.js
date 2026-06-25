'use strict';

/**
 * Test Connection Store (tcStore)
 *
 * Server-side, single-use store for the admin "Test Connection" OIDC flow.
 * Holds the internal config (client secret, code_verifier, state, nonce)
 * so secrets never reach the browser. Entries are single-use and expire
 * after TTL_MS.
 *
 * NOTE: in-process Map — correct for a single instance. Under horizontal
 * scaling a session created on instance A is invisible to instance B,
 * surfacing as TC_STORE_EXPIRED. For multi-instance production, back this
 * with a shared store (set/get/del with TTL).
 */

const TTL_MS   = 600000; // 10 minutes
const MAX_SIZE = 500;    // hard cap — DoS guard for the in-process store

const store = new Map();

// Remove expired entries on write so memory stays bounded WITHOUT a
// module-load setInterval (which keeps Cloud Function instances warm).
// Map preserves insertion order (oldest first), so we can stop at the first
// still-live entry instead of scanning the whole store on every write.
const cleanExpired = () => {
  const cutoff = Date.now() - TTL_MS;
  for (const [key, entry] of store.entries()) {
    if (entry.timestamp > cutoff) break; // newer entries follow — all still live
    store.delete(key);
  }
};

const set = (sessionRef, data) => {
  cleanExpired();
  if (store.size >= MAX_SIZE) {
    store.delete(store.keys().next().value); // evict oldest
  }
  store.set(sessionRef, { ...data, timestamp: Date.now() });
};

// Internal lookup — returns the live entry (with its timestamp) or null,
// deleting it if expired. Shared by the public read methods below.
const peek = (sessionRef) => {
  const entry = store.get(sessionRef);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > TTL_MS) {
    store.delete(sessionRef);
    return null;
  }
  return entry;
};

// Non-destructive read. Returns the stored data WITHOUT the internal
// timestamp bookkeeping field, or null if missing/expired.
const get = (sessionRef) => {
  const entry = peek(sessionRef);
  if (!entry) return null;
  const { timestamp, ...data } = entry;
  return data;
};

// Single-use read — returns the data (timestamp stripped) and removes the
// entry so it cannot be replayed. This is the credential-grade read path.
const consume = (sessionRef) => {
  const entry = peek(sessionRef);
  if (!entry) return null;
  store.delete(sessionRef);
  const { timestamp, ...data } = entry;
  return data;
};

// Explicit delete. Returns true if an entry was present, false otherwise.
const remove = (sessionRef) => {
  if (!store.has(sessionRef)) return false;
  store.delete(sessionRef);
  return true;
};

module.exports = { set, get, consume, remove };
