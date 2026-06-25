/**
 * Crypto Utility — AES-256-GCM Encryption
 *
 * Used to encrypt sensitive values (client secrets, private keys)
 * before storing in the database.
 *
 * Format stored in DB:
 *   enc:<iv_hex>:<authTag_hex>:<ciphertext_hex>
 *
 * The "enc:" prefix lets us detect encrypted values and skip
 * double-encryption if a value is already encrypted.
 *
 * Environment variable required:
 *   ENCRYPTION_KEY = 64-char hex string (32 bytes = 256 bits)
 *
 * Generate a key:
 *   node -e "logger.debug(require('crypto').randomBytes(32).toString('hex'))"
 */

const crypto = require('crypto');
const { logger } = require('../config/logger');

const ALGORITHM  = 'aes-256-gcm';
const ENC_PREFIX = 'enc:';

const getKey = () => {
  const hex = process.env.ENCRYPTION_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error(
      '[CRYPTO] ENCRYPTION_KEY must be a 64-character hex string (32 bytes). ' +
      'Generate one with: node -e "logger.debug(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
    );
  }
  return Buffer.from(hex, 'hex');
};

/**
 * Encrypt a plain-text value.
 * Returns a string in the format: enc:<iv>:<authTag>:<ciphertext>
 */
const encrypt = (plainText) => {
  if (!plainText) return null;
  if (isEncrypted(plainText)) return plainText; // already encrypted — skip

  const key    = getKey();
  const iv     = crypto.randomBytes(12); // 96-bit IV — recommended for GCM
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const ciphertext = Buffer.concat([
    cipher.update(String(plainText), 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return `${ENC_PREFIX}${iv.toString('hex')}:${authTag.toString('hex')}:${ciphertext.toString('hex')}`;
};

/**
 * Decrypt a value encrypted by encrypt().
 * Returns the original plain text.
 */
const decrypt = (encryptedValue) => {
  if (!encryptedValue) return null;
  if (!isEncrypted(encryptedValue)) return encryptedValue; // plain text — return as-is

  const parts = encryptedValue.slice(ENC_PREFIX.length).split(':');
  if (parts.length !== 3) {
    throw new Error('[CRYPTO] Invalid encrypted value format');
  }

  const [ivHex, authTagHex, ciphertextHex] = parts;
  const key        = getKey();
  const iv         = Buffer.from(ivHex,         'hex');
  const authTag    = Buffer.from(authTagHex,     'hex');
  const ciphertext = Buffer.from(ciphertextHex,  'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString('utf8');
};

/**
 * Returns true if the value was encrypted by this utility.
 */
const isEncrypted = (value) =>
  typeof value === 'string' && value.startsWith(ENC_PREFIX);

/**
 * Resolves a secret value:
 *   - "env:VAR_NAME"  → reads from process.env
 *   - "enc:..."       → decrypts with AES-256-GCM
 *   - anything else   → returns as-is (plain text fallback)
 */
const resolveSecret = (value) => {
  if (!value) return null;
  if (typeof value === 'string' && value.startsWith('env:')) {
    return process.env[value.slice(4)] || null;
  }
  if (isEncrypted(value)) {
    return decrypt(value);
  }
  return value;
};

module.exports = { encrypt, decrypt, isEncrypted, resolveSecret };
