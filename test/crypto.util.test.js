process.env.NODE_ENV = 'test';
// 64-hex (32-byte) AES key for tests
process.env.ENCRYPTION_KEY = '4b93b9e48d450f5cbcaacbdee1fad5ea28d1e853522efc3a3e34a281ff0c9847';

const { encrypt, decrypt, isEncrypted, resolveSecret } = require('../src/utils/crypto.util');

describe('utils/crypto.util', () => {
  describe('encrypt', () => {
    test('returns null for empty/falsy input', () => {
      expect(encrypt(null)).toBeNull();
      expect(encrypt('')).toBeNull();
      expect(encrypt(undefined)).toBeNull();
    });

    test('produces the enc:<iv>:<tag>:<ciphertext> format', () => {
      const out = encrypt('super-secret');
      expect(out.startsWith('enc:')).toBe(true);
      const parts = out.slice('enc:'.length).split(':');
      expect(parts).toHaveLength(3);
      parts.forEach(p => expect(p).toMatch(/^[0-9a-f]+$/));
    });

    test('is non-deterministic (random IV) — same input encrypts differently', () => {
      expect(encrypt('same')).not.toBe(encrypt('same'));
    });

    test('does not double-encrypt an already-encrypted value', () => {
      const once = encrypt('value');
      expect(encrypt(once)).toBe(once);
    });
  });

  describe('decrypt', () => {
    test('round-trips: decrypt(encrypt(x)) === x', () => {
      const secret = 'MO48Q~someClientSecretValue!23';
      expect(decrypt(encrypt(secret))).toBe(secret);
    });

    test('returns plain text unchanged when not encrypted', () => {
      expect(decrypt('plain-text')).toBe('plain-text');
    });

    test('returns null for falsy input', () => {
      expect(decrypt(null)).toBeNull();
      expect(decrypt('')).toBeNull();
    });

    test('throws on malformed encrypted value (wrong part count)', () => {
      expect(() => decrypt('enc:onlyonepart')).toThrow(/Invalid encrypted value format/);
    });

    test('throws on tampered ciphertext (auth tag mismatch)', () => {
      const enc = encrypt('integrity-check');
      const tampered = enc.slice(0, -2) + (enc.endsWith('00') ? 'ff' : '00');
      expect(() => decrypt(tampered)).toThrow();
    });
  });

  describe('isEncrypted', () => {
    test('true only for enc:-prefixed strings', () => {
      expect(isEncrypted(encrypt('x'))).toBe(true);
      expect(isEncrypted('enc:anything')).toBe(true);
    });
    test('false for plain text, env refs, and non-strings', () => {
      expect(isEncrypted('plain')).toBe(false);
      expect(isEncrypted('env:MY_VAR')).toBe(false);
      expect(isEncrypted(null)).toBe(false);
      expect(isEncrypted(123)).toBe(false);
    });
  });

  describe('resolveSecret', () => {
    test('resolves env:VAR_NAME from process.env', () => {
      process.env.TEST_OIDC_SECRET = 'resolved-from-env';
      expect(resolveSecret('env:TEST_OIDC_SECRET')).toBe('resolved-from-env');
    });
    test('returns null when env var is missing', () => {
      expect(resolveSecret('env:DOES_NOT_EXIST_VAR')).toBeNull();
    });
    test('decrypts an encrypted value', () => {
      expect(resolveSecret(encrypt('vault-value'))).toBe('vault-value');
    });
    test('returns plain values as-is', () => {
      expect(resolveSecret('just-a-string')).toBe('just-a-string');
    });
    test('returns null for falsy input', () => {
      expect(resolveSecret(null)).toBeNull();
      expect(resolveSecret('')).toBeNull();
    });
  });
});
