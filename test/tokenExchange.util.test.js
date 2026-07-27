jest.mock('../src/config/logger', () => ({ logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() } }));
jest.mock('../src/config/constants', () => ({
  microsoft: {
    tokenUrl: (tenantId) => `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
  },
}));

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const https = require('node:https');
const { decodeJwt, generateJwtAssertion, exchangeCodeForTokens } = require('../src/utils/oidc/tokenExchange.util');

const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
const makeJwt = (header, payload) => `${b64url(header)}.${b64url(payload)}.${Buffer.from('sig').toString('base64url')}`;

describe('tokenExchange.util — decodeJwt', () => {
  test('decodes header and payload without verifying', () => {
    const token = makeJwt({ alg: 'RS256', kid: 'abc' }, { sub: 'user-1', tid: 'tenant-1' });
    const { header, payload } = decodeJwt(token);
    expect(header).toEqual({ alg: 'RS256', kid: 'abc' });
    expect(payload).toEqual({ sub: 'user-1', tid: 'tenant-1' });
  });

  test('throws JWT_DECODE_FAILED on malformed token (not 3 parts)', () => {
    try { decodeJwt('not.a.valid.jwt.token'); throw new Error('no throw'); }
    catch (e) { expect(e.code).toBe('JWT_DECODE_FAILED'); expect(e.statusCode).toBe(400); }
  });

  test('throws JWT_DECODE_FAILED on non-JSON payload', () => {
    const bad = `${Buffer.from('x').toString('base64url')}.${Buffer.from('not-json').toString('base64url')}.sig`;
    expect(() => decodeJwt(bad)).toThrow(/JWT decode error/);
  });
});

describe('tokenExchange.util — generateJwtAssertion (private_key_jwt)', () => {
  let privateKeyPem, publicKey, privateKeyEnc;
  const clientId = '11111111-1111-1111-1111-111111111111';
  const tenantId = '00000000-0000-0000-0000-000000000000';
  const thumbHex = 'ABCDEF0123456789ABCDEF0123456789ABCDEF01'; // 40 hex chars (SHA-1)

  beforeAll(() => {
    const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
    privateKeyPem = kp.privateKey;
    publicKey     = kp.publicKey;
    privateKeyEnc = Buffer.from(privateKeyPem, 'utf8').toString('base64'); // base64(PEM) as stored
  });

  test('produces a 3-part JWT with correct header (alg RS256, x5t) and claims', () => {
    const jwt = generateJwtAssertion(clientId, tenantId, privateKeyEnc, thumbHex);
    const [h, p] = jwt.split('.');
    expect(jwt.split('.')).toHaveLength(3);

    const header  = JSON.parse(Buffer.from(h, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
    expect(header.alg).toBe('RS256');
    expect(header.typ).toBe('JWT');
    expect(header.x5t).toBe(Buffer.from(thumbHex, 'hex').toString('base64url'));

    expect(payload.iss).toBe(clientId);
    expect(payload.sub).toBe(clientId);
    expect(payload.aud).toContain(tenantId);
    expect(payload.jti).toBeDefined();
    expect(payload.exp - payload.iat).toBe(600);
  });

  test('signature is valid against the matching public key', () => {
    const jwt = generateJwtAssertion(clientId, tenantId, privateKeyEnc, thumbHex);
    const [h, p, sig] = jwt.split('.');
    const ok = crypto.verify('RSA-SHA256', Buffer.from(`${h}.${p}`), publicKey, Buffer.from(sig, 'base64url'));
    expect(ok).toBe(true);
  });

  test('each assertion has a unique jti (replay protection)', () => {
    const a = generateJwtAssertion(clientId, tenantId, privateKeyEnc, thumbHex);
    const b = generateJwtAssertion(clientId, tenantId, privateKeyEnc, thumbHex);
    const jtiOf = (j) => JSON.parse(Buffer.from(j.split('.')[1], 'base64url').toString()).jti;
    expect(jtiOf(a)).not.toBe(jtiOf(b));
  });
});

describe('tokenExchange.util — exchangeCodeForTokens', () => {
  let requestSpy;

  beforeEach(() => {
    jest.clearAllMocks();
    requestSpy = jest.spyOn(https, 'request');
  });

  afterEach(() => {
    requestSpy.mockRestore();
  });

  const mockRequest = (responseFactory) => {
    requestSpy.mockImplementation((options, callback) => {
      const req = new EventEmitter();
      let body = '';
      req.write = jest.fn((chunk) => { body += chunk; });
      req.end = jest.fn(() => {
        const response = responseFactory({ options, body, req });
        if (response.error) {
          process.nextTick(() => req.emit('error', response.error));
          return;
        }
        if (response.timeout) {
          process.nextTick(() => req.emit('timeout'));
          return;
        }
        const res = new EventEmitter();
        res.statusCode = response.statusCode;
        callback(res);
        process.nextTick(() => {
          if (response.body !== undefined) res.emit('data', response.body);
          res.emit('end');
        });
      });
      req.destroy = jest.fn();
      return req;
    });
  };

  test('sends client_secret auth params and parses the token response', async () => {
    mockRequest(({ options, body }) => {
      expect(options).toEqual(expect.objectContaining({
        hostname: 'login.microsoftonline.com',
        path: '/tenant-1/oauth2/v2.0/token',
        method: 'POST',
      }));
      expect(body).toContain('client_secret=secret-1');
      expect(body).toContain('code=code-1');
      return {
        statusCode: 200,
        body: JSON.stringify({ access_token: 'access-token', id_token: 'id-token' }),
      };
    });

    await expect(
      exchangeCodeForTokens(
        'code-1',
        'client-1',
        'client_secret',
        'secret-1',
        'http://localhost/callback',
        'https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token'
      )
    ).resolves.toEqual({ access_token: 'access-token', id_token: 'id-token' });
  });

  test('sends code_verifier for PKCE flows', async () => {
    mockRequest(({ body }) => {
      expect(body).toContain('code_verifier=pkce-verifier');
      expect(body).not.toContain('client_secret=');
      return {
        statusCode: 200,
        body: JSON.stringify({ access_token: 'access-token' }),
      };
    });

    await expect(
      exchangeCodeForTokens(
        'code-2',
        'client-2',
        'none',
        'pkce-verifier',
        'http://localhost/callback',
        'https://login.microsoftonline.com/tenant-2/oauth2/v2.0/token'
      )
    ).resolves.toEqual({ access_token: 'access-token' });
  });

  test('sends client_assertion for private_key_jwt flows', async () => {
    mockRequest(({ body }) => {
      expect(body).toContain('client_assertion=signed-jwt');
      expect(body).toContain('client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer');
      return {
        statusCode: 200,
        body: JSON.stringify({ access_token: 'access-token' }),
      };
    });

    await expect(
      exchangeCodeForTokens(
        'code-3',
        'client-3',
        'private_key_jwt',
        'signed-jwt',
        'http://localhost/callback',
        'https://login.microsoftonline.com/tenant-3/oauth2/v2.0/token'
      )
    ).resolves.toEqual({ access_token: 'access-token' });
  });

  test('rejects non-200 token responses', async () => {
    mockRequest(() => ({
      statusCode: 400,
      body: '{"error":"invalid_grant"}',
    }));

    await expect(
      exchangeCodeForTokens(
        'code-4',
        'client-4',
        'client_secret_post',
        'secret-4',
        'http://localhost/callback',
        'https://login.microsoftonline.com/tenant-4/oauth2/v2.0/token'
      )
    ).rejects.toThrow(/Token exchange failed: HTTP 400/);
  });

  test('rejects network and timeout failures', async () => {
    mockRequest(() => ({ error: new Error('socket hang up') }));
    await expect(
      exchangeCodeForTokens(
        'code-5',
        'client-5',
        'client_secret',
        'secret-5',
        'http://localhost/callback',
        'https://login.microsoftonline.com/tenant-5/oauth2/v2.0/token'
      )
    ).rejects.toThrow('Network error: socket hang up');

    mockRequest(() => ({ timeout: true }));
    await expect(
      exchangeCodeForTokens(
        'code-6',
        'client-6',
        'client_secret',
        'secret-6',
        'http://localhost/callback',
        'https://login.microsoftonline.com/tenant-6/oauth2/v2.0/token'
      )
    ).rejects.toThrow('Token exchange timed out');
  });
});
