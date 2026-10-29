jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

jest.mock('../src/services/db/ssoDataService', () => ({
  getSamlConfig: jest.fn(),
}));

jest.mock('../src/utils/saml/samlSignature.util', () => ({
  verifyXmlSignature: jest.fn(),
}));

jest.mock('../src/services/Saml/samlAuthRequest.service', () => ({
  samlRequestStore: {
    get: jest.fn(),
    delete: jest.fn(),
  },
}));

jest.mock('../src/services/SSO/userResolution.service', () => ({
  resolveUser: jest.fn(),
}));

jest.mock('../src/utils/firebase/firebaseAdmin.util', () => ({
  generateCustomToken: jest.fn(),
  getTenantFriendlyId: jest.fn().mockResolvedValue(null),
}));

jest.mock('../src/utils/saml/samlValidator.util', () => ({
  validateStatus: jest.fn(),
  validateIssuer: jest.fn(),
  validateInResponseTo: jest.fn(),
  validateConditions: jest.fn(),
  validateAudience: jest.fn(),
}));

const { processSamlCallback } = require('../src/services/Saml/samlCallback.service');
const { getSamlConfig } = require('../src/services/db/ssoDataService');
const { verifyXmlSignature } = require('../src/utils/saml/samlSignature.util');
const { samlRequestStore } = require('../src/services/Saml/samlAuthRequest.service');
const { resolveUser } = require('../src/services/SSO/userResolution.service');
const { generateCustomToken } = require('../src/utils/firebase/firebaseAdmin.util');
const {
  validateStatus,
  validateIssuer,
  validateInResponseTo,
  validateConditions,
  validateAudience,
} = require('../src/utils/saml/samlValidator.util');

const encodeSaml = (xml) => Buffer.from(xml, 'utf8').toString('base64');

const buildResponseXml = ({ inResponseTo = 'req-123', includeOid = true, includeEmail = true, nameIdValue = 'user@example.com', extraResponseContent = '' } = {}) => {
  const oidAttribute = includeOid
    ? `<Attribute Name="http://schemas.microsoft.com/identity/claims/objectidentifier" FriendlyName="objectidentifier"><AttributeValue>oid-123</AttributeValue></Attribute>`
    : '';
  const emailAttribute = includeEmail
    ? `<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" FriendlyName="emailaddress"><AttributeValue>user@example.com</AttributeValue></Attribute>`
    : '';

  return `<?xml version="1.0"?>
  <Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="resp-1" Version="2.0" IssueInstant="2026-06-26T00:00:00Z" InResponseTo="${inResponseTo}" Destination="http://localhost:5000/auth/callback">
    <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://sts.windows.net/tenant-123/</Issuer>
    <Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>
    <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="assert-1" Version="2.0" IssueInstant="2026-06-26T00:00:00Z">
      <Issuer>https://sts.windows.net/tenant-123/</Issuer>
      <Subject>
        <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameIdValue}</NameID>
        <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
          <SubjectConfirmationData Recipient="https://acs.example.com" NotOnOrAfter="2026-06-26T01:00:00Z" InResponseTo="${inResponseTo}"/>
        </SubjectConfirmation>
      </Subject>
      <Conditions NotBefore="2026-06-26T00:00:00Z" NotOnOrAfter="2026-06-26T01:00:00Z">
        <AudienceRestriction><Audience>entity-id-1</Audience></AudienceRestriction>
      </Conditions>
      <AttributeStatement>
        ${emailAttribute}
        ${oidAttribute}
        <Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" FriendlyName="name"><AttributeValue>Test User</AttributeValue></Attribute>
        <Attribute Name="groups" FriendlyName="groups"><AttributeValue>group-a</AttributeValue><AttributeValue>group-b</AttributeValue></Attribute>
      </AttributeStatement>
      <AuthnStatement AuthnInstant="2026-06-26T00:00:00Z" SessionIndex="session-1">
        <AuthnContext><AuthnContextClassRef>urn:test:authn</AuthnContextClassRef></AuthnContext>
      </AuthnStatement>
    </Assertion>
    ${extraResponseContent}
  </Response>`;
};

describe('samlCallback.service', () => {
  const fixedNow = new Date('2026-06-26T00:10:00Z').valueOf();

  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(Date, 'now').mockReturnValue(fixedNow);
    getSamlConfig.mockResolvedValue({
      company_id: 'company-1',
      certificate: 'cert-value',
      sso_url: 'https://login.microsoftonline.com/tenant-123/saml2',
    });
    resolveUser.mockResolvedValue({
      user: { user_id: 'user-1', email: 'user@example.com' },
      roles: [{ role_name: 'Admin' }],
      action: 'created',
    });
    generateCustomToken.mockResolvedValue('firebase-saml-token');
  });

  afterEach(() => {
    Date.now.mockRestore();
  });

  test('rejects SAML responses that do not carry InResponseTo', async () => {
    const xml = buildResponseXml({ inResponseTo: '' });

    await expect(processSamlCallback(encodeSaml(xml), null, {}, '1.2.3.4')).rejects.toMatchObject({
      statusCode: 400,
      code: 'MISSING_IN_RESPONSE_TO',
    });
  });

  test('rejects when no matching authn request session is found', async () => {
    samlRequestStore.get.mockReturnValue(null);

    await expect(processSamlCallback(encodeSaml(buildResponseXml()), null, {}, '1.2.3.4')).rejects.toMatchObject({
      statusCode: 401,
      code: 'SESSION_NOT_FOUND',
    });
  });

  test('rejects when the SAML configuration cannot be found for the company', async () => {
    samlRequestStore.get.mockReturnValue({
      timestamp: fixedNow - 1000,
      ssoContext: { company_id: 'company-1', acs_url: 'https://acs.example.com', entity_id: 'entity-id-1' },
    });
    getSamlConfig.mockResolvedValue(null);

    await expect(processSamlCallback(encodeSaml(buildResponseXml()), null, {}, '1.2.3.4')).rejects.toMatchObject({
      statusCode: 500,
      code: 'CONFIG_NOT_FOUND',
    });
  });

  test('rejects invalid XML structures and responses without assertions', async () => {
    samlRequestStore.get.mockReturnValue({
      timestamp: fixedNow - 1000,
      ssoContext: { company_id: 'company-1', acs_url: 'https://acs.example.com', entity_id: 'entity-id-1' },
    });

    await expect(processSamlCallback(encodeSaml(buildResponseXml({ extraResponseContent: '<parsererror />' })), null, {}, '1.2.3.4')).rejects.toMatchObject({
      statusCode: 400,
      code: 'INVALID_XML',
    });

    const noAssertionXml = `<?xml version="1.0"?><Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="req-123"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://sts.windows.net/tenant-123/</Issuer><Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status></Response>`;
    await expect(processSamlCallback(encodeSaml(noAssertionXml), null, {}, '1.2.3.4')).rejects.toMatchObject({
      statusCode: 400,
      code: 'MISSING_ASSERTION',
    });
  });

  test('rejects expired authn request sessions and deletes them from the store', async () => {
    samlRequestStore.get.mockReturnValue({
      timestamp: fixedNow - 700000,
      ssoContext: { company_id: 'company-1', acs_url: 'https://acs.example.com', entity_id: 'entity-id-1' },
    });

    await expect(processSamlCallback(encodeSaml(buildResponseXml()), null, {}, '1.2.3.4')).rejects.toMatchObject({
      statusCode: 401,
      code: 'SESSION_EXPIRED',
    });
    expect(samlRequestStore.delete).toHaveBeenCalledWith('req-123');
  });

  test('rejects responses that are missing required oid claims', async () => {
    samlRequestStore.get.mockReturnValue({
      timestamp: fixedNow - 1000,
      ssoContext: { company_id: 'company-1', acs_url: 'https://acs.example.com', entity_id: 'entity-id-1' },
    });

    await expect(processSamlCallback(encodeSaml(buildResponseXml({ includeOid: false })), null, {}, '1.2.3.4')).rejects.toMatchObject({
      statusCode: 400,
      code: 'MISSING_OID',
    });
  });

  test('rejects responses that are missing required email claims', async () => {
    samlRequestStore.get.mockReturnValue({
      timestamp: fixedNow - 1000,
      ssoContext: { company_id: 'company-1', acs_url: 'https://acs.example.com', entity_id: 'entity-id-1' },
    });

    await expect(processSamlCallback(encodeSaml(buildResponseXml({ includeEmail: false, nameIdValue: '' })), null, {}, '1.2.3.4')).rejects.toMatchObject({
      statusCode: 400,
      code: 'MISSING_EMAIL',
    });
  });

  test('processes valid SAML responses, resolves the user, and returns a Firebase custom token', async () => {
    samlRequestStore.get.mockReturnValue({
      timestamp: fixedNow - 2000,
      ssoContext: { company_id: 'company-1', acs_url: 'https://acs.example.com', entity_id: 'entity-id-1' },
    });

    const result = await processSamlCallback(encodeSaml(buildResponseXml()), null, {}, '1.2.3.4');

    expect(getSamlConfig).toHaveBeenCalledWith('company-1');
    expect(validateStatus).toHaveBeenCalled();
    expect(validateIssuer).toHaveBeenCalledWith(expect.any(Object), 'tenant-123');
    expect(validateInResponseTo).toHaveBeenCalledWith(expect.any(Object), 'req-123');
    expect(validateConditions).toHaveBeenCalled();
    expect(validateAudience).toHaveBeenCalledWith(expect.any(Object), 'entity-id-1');
    expect(verifyXmlSignature).toHaveBeenCalledTimes(2);
    expect(resolveUser).toHaveBeenCalledWith('company-1', expect.objectContaining({
      emailaddress: 'user@example.com',
      objectidentifier: 'oid-123',
      groups: ['group-a', 'group-b'],
      name: 'Test User',
    }), 'saml');
    expect(generateCustomToken).toHaveBeenCalledWith('user-1', {
      email: 'user@example.com',
      role: 'Admin',
      roles: [{ role_name: 'Admin' }],
      permissions: [],
      companyId: 'company-1',
      friendlyId: null,     // mocked getTenantFriendlyId resolves null
      displayName: 'Test User',
    });
    expect(samlRequestStore.delete).toHaveBeenCalledWith('req-123');
    expect(result).toEqual(expect.objectContaining({
      customToken: 'firebase-saml-token',
      userAction: 'created',
      session: expect.objectContaining({
        protocol: 'saml',
        sessionAge: 2000,
      }),
    }));
  });

  describe('SAML Test Connection callback', () => {
    const ROLE_URI = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role';
    const GROUPS_URI = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups';
    const OVERAGE_URI = 'http://schemas.microsoft.com/claims/groups.link';

    const attr = (name, values) =>
      `<Attribute Name="${name}">${values.map((v) => `<AttributeValue>${v}</AttributeValue>`).join('')}</Attribute>`;

    // Entra sends full claim URIs with no FriendlyName.
    const buildTestXml = (attributes = '') => `<?xml version="1.0"?>
      <Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="req-123">
        <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://sts.windows.net/tenant-xyz/</Issuer>
        <Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>
        <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="assert-1">
          <Subject><NameID>admin@example.com</NameID></Subject>
          <AttributeStatement>
            ${attr('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', ['admin@example.com'])}
            ${attributes}
          </AttributeStatement>
        </Assertion>
      </Response>`;

    let stored;
    beforeEach(() => {
      stored = {
        timestamp: fixedNow - 1000,
        ssoContext: { company_id: undefined, acs_url: 'https://acs.example.com', entity_id: 'test-entity' },
        test: {
          sessionRef: 'ref-1',
          certificate: 'unsaved-cert',
          sso_url: 'https://login.microsoftonline.com/tenant-xyz/saml2',
          entity_id: 'test-entity',
          acs_url: 'https://acs.example.com',
          result: null,
        },
      };
      samlRequestStore.get.mockReturnValue(stored);
    });

    test('validates against the config under test and returns only the testSessionRef', async () => {
      const result = await processSamlCallback(encodeSaml(buildTestXml()), 'req-123', {}, '1.2.3.4');

      expect(result).toEqual({ testSessionRef: 'ref-1' });
      expect(validateStatus).toHaveBeenCalled();
      expect(validateIssuer).toHaveBeenCalledWith(expect.any(Object), 'tenant-xyz');
      expect(validateInResponseTo).toHaveBeenCalledWith(expect.any(Object), 'req-123');
      expect(verifyXmlSignature).toHaveBeenCalledTimes(2);
      expect(verifyXmlSignature).toHaveBeenNthCalledWith(1, expect.any(String), 'unsaved-cert');
      expect(verifyXmlSignature).toHaveBeenNthCalledWith(2, expect.any(String), 'unsaved-cert');
      expect(validateConditions).toHaveBeenCalled();
      expect(validateAudience).toHaveBeenCalledWith(expect.any(Object), 'test-entity');
    });

    test('never touches the saved config, resolves no user, mints no token', async () => {
      await processSamlCallback(encodeSaml(buildTestXml()), 'req-123', {}, '1.2.3.4');

      expect(getSamlConfig).not.toHaveBeenCalled();
      expect(resolveUser).not.toHaveBeenCalled();
      expect(generateCustomToken).not.toHaveBeenCalled();
    });

    test('keeps the store entry so the result endpoint can read it', async () => {
      await processSamlCallback(encodeSaml(buildTestXml()), 'req-123', {}, '1.2.3.4');

      expect(samlRequestStore.delete).not.toHaveBeenCalled();
    });

    test('records a passing result with the email and full-URI role/group claims', async () => {
      const xml = buildTestXml(attr(ROLE_URI, ['Zebra.Admin', 'Zebra.Viewer']) + attr(GROUPS_URI, ['g-1']));

      await processSamlCallback(encodeSaml(xml), 'req-123', {}, '1.2.3.4');

      expect(stored.test.result).toEqual({
        success: true,
        email: 'admin@example.com',
        claims: { roles: ['Zebra.Admin', 'Zebra.Viewer'], groups: ['g-1'], groupsOverage: false },
      });
    });

    test('reports empty claims when the login carries no roles or groups', async () => {
      await processSamlCallback(encodeSaml(buildTestXml()), 'req-123', {}, '1.2.3.4');

      expect(stored.test.result.claims).toEqual({ roles: [], groups: [], groupsOverage: false });
    });

    test('flags group overage when Entra sends groups.link instead of groups', async () => {
      const xml = buildTestXml(attr(OVERAGE_URI, ['https://graph.microsoft.com/v1.0/users/x/getMemberObjects']));

      await processSamlCallback(encodeSaml(xml), 'req-123', {}, '1.2.3.4');

      expect(stored.test.result.claims).toEqual({ roles: [], groups: [], groupsOverage: true });
    });

    test('records a failed result instead of throwing when the signature is invalid', async () => {
      verifyXmlSignature.mockImplementationOnce(() => {
        throw Object.assign(new Error('Invalid signature'), { code: 'INVALID_SIGNATURE' });
      });

      const result = await processSamlCallback(encodeSaml(buildTestXml()), 'req-123', {}, '1.2.3.4');

      expect(result).toEqual({ testSessionRef: 'ref-1' });
      expect(stored.test.result).toEqual({ success: false, code: 'INVALID_SIGNATURE', message: 'Invalid signature' });
    });

    test('fails with INVALID_SSO_URL when the tested SSO URL has no tenant', async () => {
      stored.test.sso_url = 'https://example.com/saml2';

      await processSamlCallback(encodeSaml(buildTestXml()), 'req-123', {}, '1.2.3.4');

      expect(stored.test.result).toEqual(expect.objectContaining({ success: false, code: 'INVALID_SSO_URL' }));
      expect(validateIssuer).not.toHaveBeenCalled();
    });

    test('fails with MISSING_ASSERTION when the response has no assertion', async () => {
      const xml = `<?xml version="1.0"?><Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="req-123"><Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status></Response>`;

      await processSamlCallback(encodeSaml(xml), 'req-123', {}, '1.2.3.4');

      expect(stored.test.result).toEqual(expect.objectContaining({ success: false, code: 'MISSING_ASSERTION' }));
    });

    test('falls back to SAML_TEST_FAILED when a validator error has no code', async () => {
      validateAudience.mockImplementationOnce(() => { throw new Error('Audience mismatch'); });

      await processSamlCallback(encodeSaml(buildTestXml()), 'req-123', {}, '1.2.3.4');

      expect(stored.test.result).toEqual({ success: false, code: 'SAML_TEST_FAILED', message: 'Audience mismatch' });
    });

    test('still enforces the 10-minute TTL before treating it as a test', async () => {
      stored.timestamp = fixedNow - 700000;

      await expect(processSamlCallback(encodeSaml(buildTestXml()), 'req-123', {}, '1.2.3.4')).rejects.toMatchObject({
        statusCode: 401,
        code: 'SESSION_EXPIRED',
      });
      expect(stored.test.result).toBeNull();
    });
  });
});
