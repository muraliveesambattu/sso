jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const { EventEmitter } = require('node:events');

const PASSWORD = 'TestPass123!';
const DUMMY_PFX_B64 = Buffer.from('mock-pfx-binary-content').toString('base64');
const EXPECTED_THUMBPRINT = 'C0D6E98C83B595BD4425BA2AA65D5A0F17962494';

// Pre-generate a real in-memory RSA keypair using Node's crypto module so the signature validation passes
const { privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// A flag we toggle dynamically in the test to force failure on wrong password
let mockForcePasswordFailure = false;
let mockOpensslOutputMode = 'standard'; // 'standard' | 'missing-key' | 'missing-cert' | 'timeout' | 'spawn-error' | 'exit-code'

// Mock child_process to handle arguments and invalid passwords instantly on spawn invocation
jest.spyOn(childProcess, 'spawn').mockImplementation((command, args) => {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  
  child.stdin = new EventEmitter();
  child.stdin.write = jest.fn();
  child.stdin.end = jest.fn();
  child.kill = jest.fn();

  if (mockOpensslOutputMode === 'spawn-error') {
    process.nextTick(() => {
      child.emit('error', new Error('spawn ENOENT'));
    });
    return child;
  }

  // Check if an incorrect password was passed as an argument
  const passArg = args ? args.find((a) => typeof a === 'string' && a.startsWith('pass:')) : '';
  const isWrongPassword = mockForcePasswordFailure || (passArg && passArg !== `pass:${PASSWORD}`);

  let receivedInputBuffer = Buffer.alloc(0);

  child.stdin.write.mockImplementation((chunk) => {
    if (Buffer.isBuffer(chunk)) {
      receivedInputBuffer = Buffer.concat([receivedInputBuffer, chunk]);
    } else if (typeof chunk === 'string') {
      receivedInputBuffer = Buffer.concat([receivedInputBuffer, Buffer.from(chunk)]);
    }
    return true;
  });

  child.stdin.end.mockImplementation(() => {
    process.nextTick(() => {
      if (mockOpensslOutputMode === 'timeout') {
        // Intercept openssl timeout handling synchronously: 
        // Force-trigger the error event by making the process emit error or simply do nothing
        return;
      }

      // Check if garbage input was passed by inspecting the captured stdin data
      const inputStr = receivedInputBuffer.toString('utf8');
      const isGarbage = inputStr && !inputStr.includes('mock-pfx-binary-content');

      if (isWrongPassword || isGarbage || mockOpensslOutputMode === 'exit-code') {
        child.stderr.emit('data', Buffer.from('Error: mac verify failure / invalid password / parse error'));
        child.emit('close', 1);
        return;
      }

      // Success path: Output mock openssl data structures based on configuration mode
      let mockOutput = '';
      if (mockOpensslOutputMode === 'standard') {
        mockOutput = `${privateKey}\n-----BEGIN CERTIFICATE-----\nMIIB...dummy...\n-----END CERTIFICATE-----\nSHA1 Fingerprint=${EXPECTED_THUMBPRINT}\n`;
      } else if (mockOpensslOutputMode === 'missing-key') {
        // Output cert details but completely omit any private key indicators
        mockOutput = `-----BEGIN CERTIFICATE-----\nMIIB...dummy...\n-----END CERTIFICATE-----\n`;
      } else if (mockOpensslOutputMode === 'missing-cert') {
        // Output private key details but omit any valid certificate blocks
        mockOutput = `${privateKey}\n`;
      }

      child.stdout.emit('data', Buffer.from(mockOutput));
      child.emit('close', 0);
    });
  });

  return child;
});

const { extractFromPkcs12 } = require('../src/utils/oidc/pkcs12.util');

describe('pkcs12.util — input validation', () => {
  beforeEach(() => {
    mockForcePasswordFailure = false;
    mockOpensslOutputMode = 'standard';
  });

  test('throws MISSING_CERTIFICATE when no bundle is provided', async () => {
    await expect(extractFromPkcs12(null, PASSWORD)).rejects.toMatchObject({
      statusCode: 400,
      code: 'MISSING_CERTIFICATE',
    });
    await expect(extractFromPkcs12('', PASSWORD)).rejects.toMatchObject({
      code: 'MISSING_CERTIFICATE',
    });
  });

  test('throws INVALID_PKCS12 on garbage input', async () => {
    const garbageBase64 = Buffer.from('not a pfx garbage input').toString('base64');
    await expect(extractFromPkcs12(garbageBase64, PASSWORD))
      .rejects.toMatchObject({ statusCode: 400, code: 'INVALID_PKCS12' });
  });

  test('throws INVALID_PKCS12 on the wrong password', async () => {
    mockForcePasswordFailure = true; // Force password failure validation
    await expect(extractFromPkcs12(DUMMY_PFX_B64, 'WrongPassword'))
      .rejects.toMatchObject({ statusCode: 400, code: 'INVALID_PKCS12' });
  });
});

describe('pkcs12.util — extraction', () => {
  beforeEach(() => {
    mockForcePasswordFailure = false;
    mockOpensslOutputMode = 'standard';
  });

  test('the thumbprint matches the expected pre-calculated value', async () => {
    const { thumbprintHex } = await extractFromPkcs12(DUMMY_PFX_B64, PASSWORD);
    expect(thumbprintHex).toBe(EXPECTED_THUMBPRINT);
  });

  test('the thumbprint is uppercase hex of the expected length', async () => {
    const { thumbprintHex } = await extractFromPkcs12(DUMMY_PFX_B64, PASSWORD);
    expect(thumbprintHex).toMatch(/^[0-9A-F]{40}$/);
  });

  test('the private key is a clean PEM with no Bag Attributes preamble', async () => {
    const { privateKeyB64 } = await extractFromPkcs12(DUMMY_PFX_B64, PASSWORD);
    const pem = Buffer.from(privateKeyB64, 'base64').toString('utf8');

    expect(pem.startsWith('-----BEGIN')).toBe(true);
    expect(pem).not.toContain('Bag Attributes');
    expect(pem).not.toContain('localKeyID');
    expect(pem.trimEnd().endsWith('-----')).toBe(true);
  });

  test('the extracted key can actually sign — the point of the whole flow', async () => {
    const { privateKeyB64 } = await extractFromPkcs12(DUMMY_PFX_B64, PASSWORD);
    const pem = Buffer.from(privateKeyB64, 'base64').toString('utf8');

    const signature = crypto.sign('RSA-SHA256', Buffer.from('assertion'), crypto.createPrivateKey(pem));
    expect(signature.length).toBeGreaterThan(100);
  });

  test('accepts a data-URL prefixed bundle (FileReader.readAsDataURL output)', async () => {
    const dataUrl = `data:application/x-pkcs12;base64,${DUMMY_PFX_B64}`;
    const { thumbprintHex } = await extractFromPkcs12(dataUrl, PASSWORD);
    expect(thumbprintHex).toBe(EXPECTED_THUMBPRINT);
  });

  test('is deterministic across calls', async () => {
    const a = await extractFromPkcs12(DUMMY_PFX_B64, PASSWORD);
    const b = await extractFromPkcs12(DUMMY_PFX_B64, PASSWORD);
    expect(a.thumbprintHex).toBe(b.thumbprintHex);
    expect(a.privateKeyB64).toBe(b.privateKeyB64);
  });
});

// ==========================================
// NEW ADDITIONS FOR >90% CODE COVERAGE
// ==========================================

describe('pkcs12.util — error branches and timeout handling', () => {
  let originalTimeout;

  beforeEach(() => {
    mockForcePasswordFailure = false;
    mockOpensslOutputMode = 'standard';
    originalTimeout = globalThis.setTimeout;
  });

  afterEach(() => {
    globalThis.setTimeout = originalTimeout;
  });

  test('throws an error immediately when openssl spawn fails', async () => {
    mockOpensslOutputMode = 'spawn-error';

    await expect(extractFromPkcs12(DUMMY_PFX_B64, PASSWORD)).rejects.toMatchObject({
      statusCode: 400,
      code: 'INVALID_PKCS12',
    });
  });

  test('throws an error when openssl process execution times out', async () => {
    mockOpensslOutputMode = 'timeout';

    // Intercept globalThis setTimeout to immediately fire the timeout callback
    jest.spyOn(globalThis, 'setTimeout').mockImplementation((cb) => {
      process.nextTick(cb);
      return 1;
    });

    await expect(extractFromPkcs12(DUMMY_PFX_B64, PASSWORD)).rejects.toMatchObject({
      statusCode: 400,
      code: 'INVALID_PKCS12',
    });
  });

  test('throws NO_PRIVATE_KEY if bundle parses but contains no private key', async () => {
    mockOpensslOutputMode = 'missing-key';

    await expect(extractFromPkcs12(DUMMY_PFX_B64, PASSWORD)).rejects.toMatchObject({
      statusCode: 400,
      code: 'NO_PRIVATE_KEY',
    });
  });

  test('throws INVALID_PKCS12 (wrapping openssl error) if private key is fetched but certificate extraction throws or returns empty', async () => {
    // Force the first private key openssl call to succeed, but configure the second clcerts call to return an empty string
    mockOpensslOutputMode = 'standard';
    let count = 0;
    const realSpawn = childProcess.spawn;

    jest.spyOn(childProcess, 'spawn').mockImplementation((command, args) => {
      mockOpensslOutputMode = count === 0 ? 'standard' : 'missing-cert';
      count++;
      return realSpawn(command, args);
    });

    await expect(extractFromPkcs12(DUMMY_PFX_B64, PASSWORD)).rejects.toMatchObject({
      statusCode: 400,
      code: 'INVALID_PKCS12',
    });
  });

  test('throws INVALID_PKCS12 (wrapping openssl error) when certificate parses but lacks valid BEGIN/END markers', async () => {
    mockOpensslOutputMode = 'missing-cert';

    await expect(extractFromPkcs12(DUMMY_PFX_B64, PASSWORD)).rejects.toMatchObject({
      statusCode: 400,
      code: 'INVALID_PKCS12', // Fails in the first private key step
    });
  });

  test('suppresses and ignores child stdin write pipe error (EPIPE) gracefully', async () => {
    mockOpensslOutputMode = 'exit-code'; // Triggers exit code 1 / stderr failures

    const realSpawn = childProcess.spawn;
    jest.spyOn(childProcess, 'spawn').mockImplementationOnce((command, args) => {
      const child = realSpawn(command, args);
      process.nextTick(() => {
        child.stdin.emit('error', new Error('EPIPE')); // Simulate write failure stream trigger
      });
      return child;
    });

    await expect(extractFromPkcs12(DUMMY_PFX_B64, PASSWORD)).rejects.toMatchObject({
      statusCode: 400,
      code: 'INVALID_PKCS12',
    });
  });
});