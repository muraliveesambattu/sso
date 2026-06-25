process.env.NODE_ENV = 'test';

const tcStore = require('../src/utils/shared/testConnectionStore');

describe('utils/shared/testConnectionStore', () => {
  afterEach(() => {
    ['s1', 's2', 's3', 's4', 'key-new'].forEach((k) => tcStore.remove(k));
  });

  test('set then get returns the stored data WITHOUT the internal timestamp', () => {
    tcStore.set('s1', { client_secret: 'shh', state: 'st', nonce: 'no' });
    const out = tcStore.get('s1');
    expect(out).toEqual({ client_secret: 'shh', state: 'st', nonce: 'no' });
    expect(out.timestamp).toBeUndefined();
  });

  test('get is non-destructive — a second get still returns the data', () => {
    tcStore.set('s1', { client_secret: 'shh' });
    expect(tcStore.get('s1')).toEqual({ client_secret: 'shh' });
    expect(tcStore.get('s1')).toEqual({ client_secret: 'shh' });
  });

  test('get returns null for a missing key', () => {
    expect(tcStore.get('does-not-exist')).toBeNull();
  });

  test('consume is single-use — a second consume returns null (replay protection)', () => {
    tcStore.set('s2', { code_verifier: 'cv' });
    expect(tcStore.consume('s2')).toEqual({ code_verifier: 'cv' });
    expect(tcStore.consume('s2')).toBeNull();
  });

  test('consume also strips the internal timestamp', () => {
    tcStore.set('s2', { code_verifier: 'cv' });
    const out = tcStore.consume('s2');
    expect(out).toEqual({ code_verifier: 'cv' });
    expect(out.timestamp).toBeUndefined();
  });

  test('remove deletes an entry and returns true; false for a missing key', () => {
    tcStore.set('s3', { v: 'x' });
    expect(tcStore.remove('s3')).toBe(true);
    expect(tcStore.get('s3')).toBeNull();
    expect(tcStore.remove('does-not-exist')).toBe(false);
  });

  test('expired entries are not returned (TTL)', () => {
    jest.useFakeTimers();
    try {
      tcStore.set('s3', { v: 'x' });
      // advance 11 minutes (TTL is 10)
      jest.advanceTimersByTime(11 * 60 * 1000);
      expect(tcStore.get('s3')).toBeNull();
      expect(tcStore.consume('s3')).toBeNull();
    } finally {
      jest.useRealTimers();
    }
  });

  test('evicts the oldest entry when MAX_SIZE is exceeded', () => {
    // MAX_SIZE is 500 — insert 501 and confirm the first is gone
    for (let i = 0; i < 501; i++) tcStore.set(`k${i}`, { i });
    expect(tcStore.get('k0')).toBeNull();      // oldest evicted
    expect(tcStore.get('k500')).toEqual({ i: 500 }); // newest present
    // cleanup the flood
    for (let i = 0; i < 501; i++) tcStore.remove(`k${i}`);
  });
});
