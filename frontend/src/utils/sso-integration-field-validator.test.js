/**
 * Unit tests for the SSO field validators.
 *
 * These are pure functions with no React/antd dependency, so they run under a
 * plain `testEnvironment: node` jest — no jsdom required. File inputs are faked
 * with plain objects exposing the three members the validators touch:
 * `name`, `size`, and `text()` / `arrayBuffer()`.
 */

const {
  FQDN,
  validateDomains,
  validateUUID,
  validateClientSecret,
  validateHttpsUrl,
  validateSsoUrl,
  validatePemOrDerCertFile,
  validatePkcs12File,
} = require('./sso-integration-field-validator');

// antd validators are called as (rule, value) — the rule argument is unused.
const RULE = {};

const textFile = (name, content) => ({
  name,
  size: content.length,
  text: async () => content,
  arrayBuffer: async () => new TextEncoder().encode(content).buffer,
});

const binaryFile = (name, bytes) => ({
  name,
  size: bytes.length,
  text: async () => String.fromCharCode(...bytes),
  arrayBuffer: async () => new Uint8Array(bytes).buffer,
});

const PEM = [
  '-----BEGIN CERTIFICATE-----',
  'MIIBoTCCAUugAwIBAgIUZmFrZWNlcnRmb3J0ZXN0aW5nMDAwMA0GCSqGSIb3DQEB',
  '-----END CERTIFICATE-----',
].join('\n');

describe('FQDN', () => {
  test.each([
    ['contoso.com', true],
    ['sub.contoso.com', true],
    ['gmail-local.com', true],
    ['contoso', false],          // no TLD
    ['-contoso.com', false],     // leading hyphen
    ['contoso-.com', false],     // trailing hyphen
    ['contoso.c', false],        // TLD too short
  ])('%s → %s', (domain, expected) => {
    expect(FQDN.test(domain)).toBe(expected);
  });
});

describe('validateDomains', () => {
  test('accepts a single domain', async () => {
    await expect(validateDomains(RULE, 'contoso.com')).resolves.toBeUndefined();
  });

  test('accepts a comma-separated list with surrounding whitespace', async () => {
    await expect(validateDomains(RULE, 'contoso.com , sub.contoso.com')).resolves.toBeUndefined();
  });

  test('rejects an empty or whitespace-only value', async () => {
    await expect(validateDomains(RULE, '')).rejects.toThrow('Domain is required');
    await expect(validateDomains(RULE, '   ')).rejects.toThrow('Domain is required');
    await expect(validateDomains(RULE, undefined)).rejects.toThrow('Domain is required');
  });

  test('names the offending domain in the error', async () => {
    await expect(validateDomains(RULE, 'contoso.com, not_a_domain'))
      .rejects.toThrow('Invalid domain: not_a_domain');
  });
});

describe('validateUUID', () => {
  const validate = validateUUID('Tenant ID');

  test('accepts a v4 UUID and tolerates surrounding whitespace', async () => {
    await expect(validate(RULE, '7c9e6679-7425-40de-944b-e07fc1f90ae7')).resolves.toBeUndefined();
    await expect(validate(RULE, '  7c9e6679-7425-40de-944b-e07fc1f90ae7  ')).resolves.toBeUndefined();
  });

  test('rejects a missing value using the supplied label', async () => {
    await expect(validate(RULE, '')).rejects.toThrow('Tenant ID is required');
  });

  test('rejects a non-v4 UUID (version nibble is not 4)', async () => {
    await expect(validate(RULE, '7c9e6679-7425-10de-944b-e07fc1f90ae7'))
      .rejects.toThrow('Tenant ID must be a valid UUID v4 (exactly 36 characters)');
  });

  test('rejects a malformed string', async () => {
    await expect(validate(RULE, 'not-a-uuid')).rejects.toThrow('must be a valid UUID v4');
  });
});

describe('validateClientSecret', () => {
  test('accepts a typical Entra secret', async () => {
    await expect(validateClientSecret(RULE, 'abc~1234DEF-ghi_JKL')).resolves.toBeUndefined();
  });

  test('rejects empty, short, whitespace-bearing, and control-character values', async () => {
    await expect(validateClientSecret(RULE, '')).rejects.toThrow('Client Secret is required');
    await expect(validateClientSecret(RULE, 'short12')).rejects.toThrow('at least 8 characters');
    await expect(validateClientSecret(RULE, 'has space here')).rejects.toThrow('must not contain spaces');
    await expect(validateClientSecret(RULE, 'abcdefgh')).rejects.toThrow('control characters');
  });
});

describe('validateHttpsUrl', () => {
  const validate = validateHttpsUrl('Redirect URI');

  test('accepts https and rejects http', async () => {
    await expect(validate(RULE, 'https://example.com/cb')).resolves.toBeUndefined();
    await expect(validate(RULE, 'http://example.com/cb')).rejects.toThrow('must be a valid HTTPS URL');
  });

  test('rejects a missing value', async () => {
    await expect(validate(RULE, undefined)).rejects.toThrow('Redirect URI is required');
  });
});

describe('validateSsoUrl', () => {
  const TENANT = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
  const APP = '11111111-2222-3333-4444-555555555555';

  test('SAML requires the ?appid= query — per-app Entra certs live only there', async () => {
    const validate = validateSsoUrl('saml');
    await expect(validate(RULE, `https://login.microsoftonline.com/${TENANT}/saml2?appid=${APP}`))
      .resolves.toBeUndefined();
    await expect(validate(RULE, `https://login.microsoftonline.com/${TENANT}/saml2`))
      .rejects.toThrow('SSO URL must match');
  });

  test('OIDC requires the v2.0 authorize endpoint', async () => {
    const validate = validateSsoUrl('oidc');
    await expect(validate(RULE, `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/authorize`))
      .resolves.toBeUndefined();
    await expect(validate(RULE, `https://login.microsoftonline.com/${TENANT}/saml2?appid=${APP}`))
      .rejects.toThrow('SSO URL must match');
  });

  test('the error names the expected shape for the protocol', async () => {
    await expect(validateSsoUrl('saml')(RULE, 'https://example.com'))
      .rejects.toThrow('/saml2?appid={application-id}');
    await expect(validateSsoUrl('oidc')(RULE, 'https://example.com'))
      .rejects.toThrow('/oauth2/v2.0/authorize');
  });

  test('rejects a missing value', async () => {
    await expect(validateSsoUrl('saml')(RULE, '')).rejects.toThrow('SSO URL is required');
  });
});

describe('validatePemOrDerCertFile', () => {
  test('accepts a well-formed PEM certificate', async () => {
    await expect(validatePemOrDerCertFile(textFile('entra.pem', PEM))).resolves.toBeUndefined();
  });

  test('accepts the other permitted extensions', async () => {
    for (const ext of ['crt', 'cert', 'cer']) {
      await expect(validatePemOrDerCertFile(textFile(`entra.${ext}`, PEM))).resolves.toBeUndefined();
    }
  });

  test('rejects a missing file', async () => {
    await expect(validatePemOrDerCertFile(null)).rejects.toThrow('Certificate file is required');
  });

  test('rejects a disallowed extension — .pfx belongs to the PKCS#12 validator', async () => {
    await expect(validatePemOrDerCertFile(textFile('cert.pfx', PEM)))
      .rejects.toThrow('Certificate must be a .crt, .cert, .pem, or .cer file');
  });

  test('rejects content with no BEGIN CERTIFICATE marker', async () => {
    await expect(validatePemOrDerCertFile(textFile('entra.pem', 'just some text')))
      .rejects.toThrow('must be a valid PEM file');
  });

  test('rejects a BEGIN marker with no matching END marker', async () => {
    await expect(validatePemOrDerCertFile(textFile('entra.pem', '-----BEGIN CERTIFICATE-----\nMIIB\n')))
      .rejects.toThrow('Certificate contains invalid Base64 content');
  });

  test('ignores leading preamble before the BEGIN marker', async () => {
    await expect(validatePemOrDerCertFile(textFile('entra.pem', `Bag Attributes\n${PEM}`)))
      .resolves.toBeUndefined();
  });
});

describe('validatePkcs12File', () => {
  test('accepts a .pfx/.p12 starting with the DER SEQUENCE tag (0x30)', async () => {
    await expect(validatePkcs12File(binaryFile('client.pfx', [0x30, 0x82, 0x01]))).resolves.toBeUndefined();
    await expect(validatePkcs12File(binaryFile('client.p12', [0x30, 0x82, 0x01]))).resolves.toBeUndefined();
  });

  test('rejects a missing file', async () => {
    await expect(validatePkcs12File(undefined)).rejects.toThrow('Certificate file is required');
  });

  test('rejects a disallowed extension', async () => {
    await expect(validatePkcs12File(binaryFile('client.pem', [0x30])))
      .rejects.toThrow('Certificate must be .pfx or .p12 format');
  });

  test('rejects a file whose first byte is not 0x30 — e.g. a PEM renamed to .pfx', async () => {
    await expect(validatePkcs12File(binaryFile('client.pfx', [0x2d, 0x2d, 0x2d])))
      .rejects.toThrow('does not appear to be a valid PKCS#12 certificate');
  });
});
