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
  describe('Test Connection branch', () => {
    const roleAttr = '<Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/role"><AttributeValue>Zebra.Admin</AttributeValue></Attribute>';
    const buildTestEntry = (overrides = {}) => ({
      timestamp: fixedNow - 2000,
      ssoContext: {},
      test: {
        sessionRef: 'ref-1',
        certificate: 'uploaded-cert',
        sso_url: 'https://login.microsoftonline.com/tenant-123/saml2?appid=app-1',
        entity_id: 'entity-id-1',
        result: null,
        ...overrides,
      },
    });
    const withRole = (xml) => xml.replace('</AttributeStatement>', `${roleAttr}</AttributeStatement>`);

    test('validates with the uploaded cert, returns claims, and resolves no user or token', async () => {
      const entry = buildTestEntry();
      samlRequestStore.get.mockReturnValue(entry);

      const out = await processSamlCallback(encodeSaml(withRole(buildResponseXml({ includeOid: false }))), null, {}, '1.2.3.4');

      expect(out).toEqual({ testSessionRef: 'ref-1' });
      expect(getSamlConfig).not.toHaveBeenCalled();
      expect(resolveUser).not.toHaveBeenCalled();
      expect(generateCustomToken).not.toHaveBeenCalled();
      expect(verifyXmlSignature).toHaveBeenCalledWith(expect.any(String), 'uploaded-cert');
      expect(validateIssuer).toHaveBeenCalledWith(expect.any(Object), 'tenant-123');
      expect(validateAudience).toHaveBeenCalledWith(expect.any(Object), 'entity-id-1');
      expect(entry.test.result).toEqual({
        success: true,
        email: 'user@example.com',
        claims: { roles: ['Zebra.Admin'], groups: ['group-a', 'group-b'], groupsOverage: false },
      });
    });

    test('records a failed result when signature verification fails', async () => {
      const entry = buildTestEntry();
      samlRequestStore.get.mockReturnValue(entry);
      verifyXmlSignature.mockImplementationOnce(() => {
        throw Object.assign(new Error('bad signature'), { code: 'INVALID_SIGNATURE' });
      });

      const out = await processSamlCallback(encodeSaml(buildResponseXml()), null, {}, '1.2.3.4');

      expect(out).toEqual({ testSessionRef: 'ref-1' });
      expect(entry.test.result).toEqual({ success: false, code: 'INVALID_SIGNATURE', message: 'bad signature' });
    });

    test('records a failed result when the audience does not match', async () => {
      const entry = buildTestEntry();
      samlRequestStore.get.mockReturnValue(entry);
      validateAudience.mockImplementationOnce(() => {
        throw Object.assign(new Error('wrong audience'), { code: 'INVALID_AUDIENCE' });
      });

      await processSamlCallback(encodeSaml(buildResponseXml()), null, {}, '1.2.3.4');

      expect(entry.test.result).toMatchObject({ success: false, code: 'INVALID_AUDIENCE' });
    });

    test('records a failed result when the assertion is missing', async () => {
      const entry = buildTestEntry();
      samlRequestStore.get.mockReturnValue(entry);
      const xml = buildResponseXml().replace(/<Assertion[\s\S]*<\/Assertion>/, '');

      await processSamlCallback(encodeSaml(xml), null, {}, '1.2.3.4');

      expect(entry.test.result).toMatchObject({ success: false, code: 'MISSING_ASSERTION' });
    });

    test('flags group overage when Entra sends groups.link instead of the group list', async () => {
      const entry = buildTestEntry();
      samlRequestStore.get.mockReturnValue(entry);
      const overage = '<Attribute Name="http://schemas.microsoft.com/claims/groups.link"><AttributeValue>https://graph.example/groups</AttributeValue></Attribute>';
      const xml = buildResponseXml()
        .replace(/<Attribute Name="groups"[\s\S]*?<\/Attribute>/, overage);

      await processSamlCallback(encodeSaml(xml), null, {}, '1.2.3.4');

      expect(entry.test.result.claims).toEqual({ roles: [], groups: [], groupsOverage: true });
    });
  });
});
