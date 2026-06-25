jest.mock('../src/config/constants', () => ({
  microsoft: {
    jwksUrl: (tenantId) => `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
  },
}));

const { EventEmitter } = require('events');
const https = require('https');
const crypto = require('crypto');
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
});
