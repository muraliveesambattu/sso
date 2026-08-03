// SSO field format validators
const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const FQDN =
  /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z]{2,})+$/;
const HTTPS =
  /^https:\/\/.+/;
const CLIENT_SECRET_RE = /^[\x21-\x7E]+$/;
const PEM_BODY =
  /^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----$/;

export const validateDomains = async (_, value) => {
  if (!value?.trim()) {
    throw new Error('Domain is required');
  }
  const domains = value.split(',').map((d) => d.trim().toLowerCase());
  const domainRegex = /^(?!-)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
  const invalidDomain = domains.find((domain) => !domainRegex.test(domain));
  if (invalidDomain) {
    throw new Error(`Invalid domain: ${invalidDomain}`);
  }
};

export const validateUUID = (label) =>async (_, value) => {
  if (!value) throw new Error(`${label} is required`);
  if (!UUID_V4.test(value.trim())) throw new Error(`${label} must be a valid UUID v4 (exactly 36 characters)`);
};

export const validateClientSecret = async(_, value) => {
  if (!value?.trim()) throw new Error('Client Secret is required');
  if (value.trim().length < 8) throw new Error('Client Secret must be at least 8 characters');
  if (/\s/.test(value)) throw new Error('Client Secret must not contain spaces or whitespace');
  if (!CLIENT_SECRET_RE.test(value)) throw new Error('Client Secret must not contain control characters');
};

export const validateHttpsUrl = (label) =>async (_, value) => {
  if (!value) throw new Error(`${label} is required`);
  if (!HTTPS.test(value.trim())) throw new Error(`${label} must be a valid HTTPS URL`);
};

export const validateSsoUrl = (protocol) =>async (_, value) => {
  if (!value) throw new Error('SSO URL is required');
  const pattern =
    protocol === 'saml'
      ? /^https:\/\/login\.microsoftonline\.com\/[0-9a-f-]{36}\/saml2\?appid=[0-9a-f-]{36}$/i
      : /^https:\/\/login\.microsoftonline\.com\/[0-9a-f-]{36}\/oauth2\/v2\.0\/authorize$/i;
  if (!pattern.test(value.trim())) {
    const example =
      protocol === 'saml'
        ? 'https://login.microsoftonline.com/{uuid}/saml2?appid={application-id}'
        : 'https://login.microsoftonline.com/{uuid}/oauth2/v2.0/authorize';
    throw new Error(`SSO URL must match: ${example}`);
  }
};

export const validatePemOrDerCertFile = async (file) => {
  if (!file) throw new Error('Certificate file is required');
  const ext = file.name.split('.').pop().toLowerCase();
  if (!['crt', 'cert', 'pem', 'cer'].includes(ext)) {
    throw new Error('Certificate must be a .crt, .cert, .pem, or .cer file');
  }
  if (['pem', 'crt', 'cert', 'cer'].includes(ext)) {
    const content = await file.text();
    if (!content.includes('-----BEGIN CERTIFICATE-----')) {
      throw new Error('Certificate must be a valid PEM file (-----BEGIN CERTIFICATE-----)');
    }
    const beginIdx = content.indexOf('-----BEGIN CERTIFICATE-----');
    const pemContent = content.slice(beginIdx).trim();
    if (!PEM_BODY.test(pemContent)) {
      throw new Error('Certificate contains invalid Base64 content');
    }
  } else {
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    if (bytes[0] !== 0x30) throw new Error('File does not appear to be a valid DER certificate');
  }
};

export const validatePkcs12File = async (file) => {
  if (!file) throw new Error('Certificate file is required');
  const ext = file.name.split('.').pop().toLowerCase();
  if (!['pfx', 'p12'].includes(ext)) throw new Error('Certificate must be .pfx or .p12 format');
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  if (bytes[0] !== 0x30) throw new Error('File does not appear to be a valid PKCS#12 certificate');
};
