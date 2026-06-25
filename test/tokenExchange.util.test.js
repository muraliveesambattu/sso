jest.mock('../src/config/logger', () => ({ logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() } }));

const crypto = require('crypto');
const { decodeJwt, generateJwtAssertion } = require('../src/utils/oidc/tokenExchange.util');

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
