const { DOMParser } = require('@xmldom/xmldom');
const {
  validateStatus, validateIssuer, validateInResponseTo, validateConditions, validateAudience,
} = require('../src/utils/saml/samlValidator.util');

const parse = (xml) => new DOMParser().parseFromString(xml, 'text/xml');
const TENANT = '00000000-0000-0000-0000-000000000000';
const iso = (offsetSec) => new Date(Date.now() + offsetSec * 1000).toISOString();

describe('samlValidator.util', () => {
  // ── validateStatus ──
  describe('validateStatus', () => {
    test('passes on Success', () => {
      const doc = parse(`<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol"><Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status></Response>`);
      expect(() => validateStatus(doc)).not.toThrow();
    });
    test('throws AUTHENTICATION_FAILED on non-success', () => {
      const doc = parse(`<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol"><Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></Status></Response>`);
      expect(() => validateStatus(doc)).toThrow(/Authentication failed/);
      try { validateStatus(doc); } catch (e) { expect(e.code).toBe('AUTHENTICATION_FAILED'); }
    });
  });

  // ── validateIssuer ──
  describe('validateIssuer', () => {
    test('passes when issuer matches sts.windows.net/<tenant>/', () => {
      const doc = parse(`<a:Assertion xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion"><a:Issuer>https://sts.windows.net/${TENANT}/</a:Issuer></a:Assertion>`);
      expect(() => validateIssuer(doc, TENANT)).not.toThrow();
    });
    test('throws INVALID_ISSUER on mismatch', () => {
      const doc = parse(`<a:Assertion xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion"><a:Issuer>https://evil.example.com/</a:Issuer></a:Assertion>`);
      try { validateIssuer(doc, TENANT); throw new Error('should have thrown'); }
      catch (e) { expect(e.code).toBe('INVALID_ISSUER'); }
    });
  });

  // ── validateInResponseTo ──
  describe('validateInResponseTo', () => {
    test('passes when InResponseTo matches stored id', () => {
      const doc = parse(`<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="req-123"/>`);
      expect(() => validateInResponseTo(doc, 'req-123')).not.toThrow();
    });
    test('throws MISSING_INRESPONSET when absent', () => {
      const doc = parse(`<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol"/>`);
      try { validateInResponseTo(doc, 'req-123'); throw new Error('no throw'); }
      catch (e) { expect(e.code).toBe('MISSING_INRESPONSET'); }
    });
    test('throws INVALID_INRESPONSETO on mismatch (CSRF)', () => {
      const doc = parse(`<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="other"/>`);
      try { validateInResponseTo(doc, 'req-123'); throw new Error('no throw'); }
      catch (e) { expect(e.code).toBe('INVALID_INRESPONSETO'); }
    });
  });

  // ── validateConditions ──
  describe('validateConditions', () => {
    const assertionWith = (nb, noa) => parse(
      `<a:Assertion xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion"><a:Conditions NotBefore="${nb}" NotOnOrAfter="${noa}"/></a:Assertion>`
    ).documentElement;

    test('passes within the valid window', () => {
      expect(() => validateConditions(assertionWith(iso(-60), iso(300)))).not.toThrow();
    });
    test('throws MISSING_CONDITIONS when no Conditions element', () => {
      const a = parse(`<a:Assertion xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion"/>`).documentElement;
      try { validateConditions(a); throw new Error('no throw'); } catch (e) { expect(e.code).toBe('MISSING_CONDITIONS'); }
    });
    test('throws ASSERTION_NOT_YET_VALID when NotBefore is in the future', () => {
      try { validateConditions(assertionWith(iso(600), iso(1200))); throw new Error('no throw'); }
      catch (e) { expect(e.code).toBe('ASSERTION_NOT_YET_VALID'); }
    });
    test('throws ASSERTION_EXPIRED when NotOnOrAfter is in the past', () => {
      try { validateConditions(assertionWith(iso(-1200), iso(-600))); throw new Error('no throw'); }
      catch (e) { expect(e.code).toBe('ASSERTION_EXPIRED'); }
    });
  });

  // ── validateAudience ──
  describe('validateAudience', () => {
    const assertionAud = (aud) => parse(
      `<a:Assertion xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion"><a:Conditions><a:AudienceRestriction><a:Audience>${aud}</a:Audience></a:AudienceRestriction></a:Conditions></a:Assertion>`
    ).documentElement;

    test('passes when audience matches entityId', () => {
      expect(() => validateAudience(assertionAud('https://sp.example.com/metadata'), 'https://sp.example.com/metadata')).not.toThrow();
    });
    test('throws INVALID_AUDIENCE on mismatch', () => {
      try { validateAudience(assertionAud('https://other.com'), 'https://sp.example.com/metadata'); throw new Error('no throw'); }
      catch (e) { expect(e.code).toBe('INVALID_AUDIENCE'); }
    });
  });
});
