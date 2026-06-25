process.env.NODE_ENV = 'test';

const { validateTokenClaims, validateUserClaims } = require('../src/utils/oidc/tokenValidation.util');

const TENANT = '00000000-0000-0000-0000-000000000000';
const CONSUMER_TENANT_ID = '9188040d-6c67-4c5b-b112-36a304b66dad';
const CLIENT_ID = '11111111-1111-1111-1111-111111111111';
const NONCE = 'nonce-abc-123';

const oidcConfig = { client_id: CLIENT_ID };

// Build a fully-valid claims object; override fields per-test.
const validClaims = (overrides = {}) => {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: `https://login.microsoftonline.com/${TENANT}/v2.0`,
    aud: CLIENT_ID,
    exp: now + 3600,
    nbf: now - 60,
    iat: now - 60,
    nonce: NONCE,
    oid: 'user-object-id',
    email: 'john@zebra.com',
    ...overrides,
  };
};

describe('utils/oidc/tokenValidation — validateTokenClaims', () => {
  test('returns true for fully valid claims', () => {
    expect(validateTokenClaims(validClaims(), oidcConfig, TENANT, NONCE)).toBe(true);
  });

  describe('issuer', () => {
    test('rejects wrong issuer', () => {
      const c = validClaims({ iss: 'https://login.microsoftonline.com/other-tenant/v2.0' });
      expect(() => validateTokenClaims(c, oidcConfig, TENANT, NONCE))
        .toThrow(expect.objectContaining({ code: 'INVALID_ISSUER', statusCode: 401 }));
    });

    test("resolves 'consumers' to the MSA tenant GUID in the issuer", () => {
      const c = validClaims({ iss: `https://login.microsoftonline.com/${CONSUMER_TENANT_ID}/v2.0` });
      expect(validateTokenClaims(c, oidcConfig, 'consumers', NONCE)).toBe(true);
    });

    test("'common' accepts any valid GUID issuer", () => {
      const c = validClaims({ iss: `https://login.microsoftonline.com/${TENANT}/v2.0` });
      expect(validateTokenClaims(c, oidcConfig, 'common', NONCE)).toBe(true);
    });

    test("'common' rejects a non-GUID issuer", () => {
      const c = validClaims({ iss: 'https://login.microsoftonline.com/not-a-guid/v2.0' });
      expect(() => validateTokenClaims(c, oidcConfig, 'common', NONCE))
        .toThrow(expect.objectContaining({ code: 'INVALID_ISSUER' }));
    });
  });

  describe('audience', () => {
    test('rejects when client_id not in aud', () => {
      const c = validClaims({ aud: 'some-other-client' });
      expect(() => validateTokenClaims(c, oidcConfig, TENANT, NONCE))
        .toThrow(expect.objectContaining({ code: 'INVALID_AUDIENCE' }));
    });
    test('accepts aud as an array containing client_id', () => {
      const c = validClaims({ aud: ['x', CLIENT_ID] });
      expect(validateTokenClaims(c, oidcConfig, TENANT, NONCE)).toBe(true);
    });
  });

  describe('temporal claims', () => {
    test('rejects missing exp', () => {
      const c = validClaims({ exp: undefined });
      expect(() => validateTokenClaims(c, oidcConfig, TENANT, NONCE))
        .toThrow(expect.objectContaining({ code: 'MISSING_EXPIRATION' }));
    });
    test('rejects expired token', () => {
      const c = validClaims({ exp: Math.floor(Date.now() / 1000) - 1000 });
      expect(() => validateTokenClaims(c, oidcConfig, TENANT, NONCE))
        .toThrow(expect.objectContaining({ code: 'TOKEN_EXPIRED' }));
    });
    test('rejects not-yet-valid token (nbf in future)', () => {
      const c = validClaims({ nbf: Math.floor(Date.now() / 1000) + 1000 });
      expect(() => validateTokenClaims(c, oidcConfig, TENANT, NONCE))
        .toThrow(expect.objectContaining({ code: 'TOKEN_NOT_YET_VALID' }));
    });
    test('rejects missing iat', () => {
      const c = validClaims({ iat: undefined });
      expect(() => validateTokenClaims(c, oidcConfig, TENANT, NONCE))
        .toThrow(expect.objectContaining({ code: 'MISSING_ISSUED_AT' }));
    });
    test('rejects iat in the future', () => {
      const c = validClaims({ iat: Math.floor(Date.now() / 1000) + 1000 });
      expect(() => validateTokenClaims(c, oidcConfig, TENANT, NONCE))
        .toThrow(expect.objectContaining({ code: 'INVALID_ISSUED_AT' }));
    });
    test('rejects token older than 1 hour', () => {
      const c = validClaims({ iat: Math.floor(Date.now() / 1000) - 4000 });
      expect(() => validateTokenClaims(c, oidcConfig, TENANT, NONCE))
        .toThrow(expect.objectContaining({ code: 'TOKEN_TOO_OLD' }));
    });
  });

  describe('nonce', () => {
    test('rejects missing nonce when one is expected', () => {
      const c = validClaims({ nonce: undefined });
      expect(() => validateTokenClaims(c, oidcConfig, TENANT, NONCE))
        .toThrow(expect.objectContaining({ code: 'MISSING_NONCE' }));
    });
    test('rejects nonce mismatch (replay)', () => {
      const c = validClaims({ nonce: 'different-nonce' });
      expect(() => validateTokenClaims(c, oidcConfig, TENANT, NONCE))
        .toThrow(expect.objectContaining({ code: 'INVALID_NONCE' }));
    });
    test('skips nonce check when no expectedNonce passed', () => {
      const c = validClaims({ nonce: undefined });
      expect(validateTokenClaims(c, oidcConfig, TENANT, undefined)).toBe(true);
    });
  });
});

describe('utils/oidc/tokenValidation — validateUserClaims', () => {
  test('returns oid+email+full claims when valid', () => {
    const out = validateUserClaims({ oid: 'oid-1', email: 'a@b.com', extra: 'kept' }, {});
    expect(out).toMatchObject({ oid: 'oid-1', email: 'a@b.com', extra: 'kept' });
  });

  test('falls back to sub when oid missing', () => {
    const out = validateUserClaims({ sub: 'sub-1', email: 'a@b.com' }, {});
    expect(out.oid).toBe('sub-1');
  });

  test('throws MISSING_OID when neither oid nor sub present', () => {
    expect(() => validateUserClaims({ email: 'a@b.com' }, {}))
      .toThrow(expect.objectContaining({ code: 'MISSING_OID', statusCode: 400 }));
  });

  test('resolves email from preferred_username / upn fallback chain', () => {
    expect(validateUserClaims({ oid: 'o', preferred_username: 'pu@b.com' }, {}).email).toBe('pu@b.com');
    expect(validateUserClaims({ oid: 'o', upn: 'upn@b.com' }, {}).email).toBe('upn@b.com');
    expect(validateUserClaims({ oid: 'o' }, { upn: 'access-upn@b.com' }).email).toBe('access-upn@b.com');
  });

  test('throws MISSING_EMAIL when no email anywhere', () => {
    expect(() => validateUserClaims({ oid: 'o' }, {}))
      .toThrow(expect.objectContaining({ code: 'MISSING_EMAIL', statusCode: 400 }));
  });
});
