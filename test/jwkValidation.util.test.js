jest.mock('../src/config/constants', () => ({
  microsoft: {
    jwksUrl: (tenantId) => `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
  },
}));

const { EventEmitter } = require('node:events');
const https = require('node:https');
const crypto = require('node:crypto');
const { verifyJwtSignature } = require('../src/utils/oidc/jwkValidation.util');

const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');

describe('jwkValidation.util', () => {
  let keyPair;
  let jwk;
  let httpsGetSpy;

  beforeAll(() => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    keyPair = { privateKey, publicKey };
    jwk = publicKey.export({ format: 'jwk' });
  });

  beforeEach(() => {
    jest.clearAllMocks();
    httpsGetSpy = jest.spyOn(https, 'get');
  });

  afterEach(() => {
    httpsGetSpy.mockRestore();
  });

  const mockJwks = (body, statusCode = 200) => {
    httpsGetSpy.mockImplementation((url, options, callback) => {
      const res = new EventEmitter();
      res.statusCode = statusCode;
      callback(res);
      process.nextTick(() => {
        res.emit('data', JSON.stringify(body));
        res.emit('end');
      });
      return { on: jest.fn().mockReturnThis() };
    });
  };

  const makeToken = (header, payload) => {
    const encodedHeader = b64url(header);
    const encodedPayload = b64url(payload);
    const signature = crypto.sign('RSA-SHA256', Buffer.from(`${encodedHeader}.${encodedPayload}`), keyPair.privateKey);
    return `${encodedHeader}.${encodedPayload}.${signature.toString('base64url')}`;
  };

  test('verifies a valid RS256 token against the fetched JWKS', async () => {
    mockJwks({ keys: [{ ...jwk, kid: 'kid-1' }] });
    const token = makeToken({ alg: 'RS256', kid: 'kid-1' }, { sub: 'user-1', tid: 'tenant-1' });

    await expect(verifyJwtSignature(token, 'tenant-1')).resolves.toBe(true);
  });

  test('rejects tokens that use non-RS256 algorithms', async () => {
    const token = `${b64url({ alg: 'HS256', kid: 'kid-1' })}.${b64url({ sub: 'user-1' })}.sig`;

    await expect(verifyJwtSignature(token, 'tenant-1')).rejects.toMatchObject({
      statusCode: 401,
      code: 'JWT_VERIFICATION_FAILED',
    });
  });

  test('rejects tokens when the matching kid is missing from JWKS', async () => {
    mockJwks({ keys: [{ ...jwk, kid: 'other-kid' }] });
    const token = makeToken({ alg: 'RS256', kid: 'kid-missing' }, { sub: 'user-1' });

    await expect(verifyJwtSignature(token, 'tenant-1')).rejects.toThrow(/Signing key/);
  });

  test('rejects malformed JWT strings', async () => {
    await expect(verifyJwtSignature('not-a-jwt', 'tenant-1')).rejects.toMatchObject({
      statusCode: 401,
      code: 'JWT_VERIFICATION_FAILED',
    });
  });

  // ==========================================
  // NEW ADDITIONS FOR >90% CODE COVERAGE
  // ==========================================

  test('rejects when JWKS fetch returns non-200 HTTP status', async () => {
    mockJwks({ error: 'Not Found' }, 404);
    const token = makeToken({ alg: 'RS256', kid: 'kid-1' }, { sub: 'user-1' });

    await expect(verifyJwtSignature(token, 'tenant-1')).rejects.toThrow(/JWKS fetch failed: HTTP 404/);
  });

  test('rejects when JWKS response is invalid JSON', async () => {
    httpsGetSpy.mockImplementation((url, options, callback) => {
      const res = new EventEmitter();
      res.statusCode = 200;
      callback(res);
      process.nextTick(() => {
        res.emit('data', 'invalid-json-response{');
        res.emit('end');
      });
      return { on: jest.fn().mockReturnThis() };
    });

    const token = makeToken({ alg: 'RS256', kid: 'kid-1' }, { sub: 'user-1' });

    await expect(verifyJwtSignature(token, 'tenant-1')).rejects.toThrow(/Failed to parse JWKS response/);
  });

  test('rejects when JWKS request encounters a network error', async () => {
    httpsGetSpy.mockImplementation(() => {
      const req = new EventEmitter();
      process.nextTick(() => req.emit('error', new Error('ECONNRESET')));
      return req;
    });

    const token = makeToken({ alg: 'RS256', kid: 'kid-1' }, { sub: 'user-1' });

    await expect(verifyJwtSignature(token, 'tenant-1')).rejects.toThrow(/JWKS network error: ECONNRESET/);
  });

  test('rejects and destroys request when JWKS request times out', async () => {
    const destroyMock = jest.fn();
    httpsGetSpy.mockImplementation(() => {
      const req = new EventEmitter();
      req.destroy = destroyMock;
      process.nextTick(() => req.emit('timeout'));
      return req;
    });

    const token = makeToken({ alg: 'RS256', kid: 'kid-1' }, { sub: 'user-1' });

    await expect(verifyJwtSignature(token, 'tenant-1')).rejects.toThrow(/JWKS fetch timed out/);
    expect(destroyMock).toHaveBeenCalled();
  });

  test('rejects when JWT signature does not match payload', async () => {
    mockJwks({ keys: [{ ...jwk, kid: 'kid-1' }] });
    const encodedHeader = b64url({ alg: 'RS256', kid: 'kid-1' });
    const encodedPayload1 = b64url({ sub: 'user-1' });
    const encodedPayload2 = b64url({ sub: 'user-tampered' });
    const signature = crypto.sign('RSA-SHA256', Buffer.from(`${encodedHeader}.${encodedPayload1}`), keyPair.privateKey);
    const mismatchedToken = `${encodedHeader}.${encodedPayload2}.${signature.toString('base64url')}`;

    await expect(verifyJwtSignature(mismatchedToken, 'tenant-1')).rejects.toThrow(/JWT signature verification failed/);
  });
});