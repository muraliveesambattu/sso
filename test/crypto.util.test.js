process.env.NODE_ENV = 'test';
// 64-hex (32-byte) AES key for tests
process.env.ENCRYPTION_KEY = '0123456789abcdef'.repeat(4); // test-only key, never a real one

jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

const {
  encrypt,
  decrypt,
  isEncrypted,
  resolveSecret,
  validateThumbprint,
  validatePrivateKey,
  decryptStoredPrivateKey,
} = require('../src/utils/crypto.util');
const { logger } = require('../src/config/logger');

// Runs fn and returns the error it throws (fails the test if it does not throw).
const thrownBy = (fn) => {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error('expected the call to throw');
};

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

  describe('ENCRYPTION_KEY check', () => {
    const goodKey = process.env.ENCRYPTION_KEY;
    afterEach(() => { process.env.ENCRYPTION_KEY = goodKey; });

    test('throws when ENCRYPTION_KEY is missing', () => {
      delete process.env.ENCRYPTION_KEY;
      expect(() => encrypt('x')).toThrow(/ENCRYPTION_KEY must be a 64-character hex string/);
    });

    test('throws when ENCRYPTION_KEY has the wrong length', () => {
      process.env.ENCRYPTION_KEY = 'abc123';
      expect(() => encrypt('x')).toThrow(/ENCRYPTION_KEY must be a 64-character hex string/);
    });

    test('decrypt also needs the key', () => {
      const enc = encrypt('needs-key');
      delete process.env.ENCRYPTION_KEY;
      expect(() => decrypt(enc)).toThrow(/ENCRYPTION_KEY/);
    });
  });

  describe('validateThumbprint', () => {
    const sha1 = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
    const sha256 = 'ab'.repeat(32);

    test('accepts a 40-character SHA-1 thumbprint and returns it in upper case', () => {
      expect(validateThumbprint(sha1)).toBe(sha1.toUpperCase());
    });

    test('accepts a 64-character SHA-256 thumbprint', () => {
      expect(validateThumbprint(sha256)).toBe(sha256.toUpperCase());
    });

    test('removes colons and spaces before checking', () => {
      const pretty = sha1.match(/../g).join(':');
      expect(validateThumbprint(pretty)).toBe(sha1.toUpperCase());
      expect(validateThumbprint(`  ${sha1.slice(0, 20)} ${sha1.slice(20)}  `)).toBe(sha1.toUpperCase());
    });

    test.each([
      ['not a string', 12345],
      ['missing', undefined],
      ['empty', ''],
      ['only separators', ' : : '],
      ['too short', 'ABCDEF'],
      ['wrong length', 'A'.repeat(50)],
      ['not hex', 'Z'.repeat(40)],
    ])('rejects a thumbprint that is %s', (_label, value) => {
      const error = thrownBy(() => validateThumbprint(value));
      expect(error.code).toBe('SSO_CERT_THUMBPRINT_INVALID');
      expect(error.statusCode).toBe(400);
      expect(error.message).toMatch(/re-upload the certificate/);
    });
  });

  describe('validatePrivateKey', () => {
    test('returns the key when it is a non-empty string', () => {
      const key = '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----';
      expect(validatePrivateKey(key)).toBe(key);
    });

    test('accepts a key exactly at the 64 KB limit', () => {
      const key = 'k'.repeat(64 * 1024);
      expect(validatePrivateKey(key)).toBe(key);
    });

    test.each([
      ['not a string', 42],
      ['null', null],
      ['empty', ''],
      ['only spaces', '   '],
    ])('rejects a key that is %s', (_label, value) => {
      const error = thrownBy(() => validatePrivateKey(value));
      expect(error.code).toBe('SSO_CERT_REFERENCE_MISSING');
      expect(error.statusCode).toBe(400);
    });

    test('rejects a key larger than 64 KB', () => {
      const error = thrownBy(() => validatePrivateKey('k'.repeat(64 * 1024 + 1)));
      expect(error.code).toBe('SSO_PRIVATE_KEY_TOO_LARGE');
      expect(error.statusCode).toBe(400);
    });
  });

  describe('decryptStoredPrivateKey', () => {
    beforeEach(() => { logger.error.mockClear(); });

    test('decrypts and returns a stored private key', () => {
      const key = '-----BEGIN PRIVATE KEY-----\nstored\n-----END PRIVATE KEY-----';
      expect(decryptStoredPrivateKey(encrypt(key))).toBe(key);
    });

    test('returns a plain (not encrypted) stored key as-is', () => {
      expect(decryptStoredPrivateKey('plain-key')).toBe('plain-key');
    });

    test.each([null, undefined, ''])('rejects a missing reference (%p)', (value) => {
      const error = thrownBy(() => decryptStoredPrivateKey(value));
      expect(error.code).toBe('SSO_CERT_REFERENCE_MISSING');
      expect(error.message).toMatch(/reference is missing/);
    });

    test('passes on the missing-key error when the decrypted key is blank', () => {
      const error = thrownBy(() => decryptStoredPrivateKey(encrypt('   ')));
      expect(error.code).toBe('SSO_CERT_REFERENCE_MISSING');
      expect(logger.error).not.toHaveBeenCalled();
    });

    test('passes on the too-large error when the decrypted key is over 64 KB', () => {
      const error = thrownBy(() => decryptStoredPrivateKey(encrypt('k'.repeat(64 * 1024 + 1))));
      expect(error.code).toBe('SSO_PRIVATE_KEY_TOO_LARGE');
      expect(logger.error).not.toHaveBeenCalled();
    });

    test('turns a tampered value into a 500 decryption error and logs it', () => {
      const enc = encrypt('original-key');
      const tampered = enc.slice(0, -2) + (enc.endsWith('00') ? 'ff' : '00');

      const error = thrownBy(() => decryptStoredPrivateKey(tampered));

      expect(error.code).toBe('SSO_PRIVATE_KEY_DECRYPTION_FAILED');
      expect(error.statusCode).toBe(500);
      expect(logger.error).toHaveBeenCalledWith(
        '[OIDC] Stored private key decryption failed',
        expect.objectContaining({ code: expect.any(String) })
      );
    });

    test('logs CRYPTO_DECRYPTION_FAILED when the error has no code', () => {
      const error = thrownBy(() => decryptStoredPrivateKey('enc:only-one-part'));

      expect(error.code).toBe('SSO_PRIVATE_KEY_DECRYPTION_FAILED');
      expect(logger.error).toHaveBeenCalledWith(
        '[OIDC] Stored private key decryption failed',
        { code: 'CRYPTO_DECRYPTION_FAILED' }
      );
    });

    test('logs the original error code when there is one', () => {
      // A 1-byte auth tag makes Node throw ERR_CRYPTO_INVALID_AUTH_TAG.
      const error = thrownBy(() => decryptStoredPrivateKey('enc:00:00:00'));

      expect(error.code).toBe('SSO_PRIVATE_KEY_DECRYPTION_FAILED');
      expect(logger.error).toHaveBeenCalledWith(
        '[OIDC] Stored private key decryption failed',
        { code: 'ERR_CRYPTO_INVALID_AUTH_TAG' }
      );
    });
  });
});
