jest.mock('../src/services/db/ssoDataService', () => ({
  getSsoConfigDetails: jest.fn(),
  setSsoStatus: jest.fn(),
  deleteSsoConfig: jest.fn(),
  invalidateDomainCache: jest.fn(),
}));

jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

const { handleGetSsoConfig, handleSetSsoStatus, handleDeleteSsoConfig } = require('../src/controllers/ssoAdmin.controller');
const ssoDataService = require('../src/services/db/ssoDataService');

const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  res.set = jest.fn().mockReturnValue(res);
  return res;
};

describe('ssoAdmin.controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('returns 400 when get config has no query filters', async () => {
    const req = { query: {} };
    const res = mockRes();

    await handleGetSsoConfig(req, res, jest.fn());

    expect(res.status).toHaveBeenCalledWith(400);
  });

  test('never lets a CDN/browser cache this personalised config response', async () => {
    // Firebase Hosting applies its own default max-age when the origin sets
    // nothing, which can serve a stale 404/old config for minutes after a fix.
    const res = mockRes();
    ssoDataService.getSsoConfigDetails.mockResolvedValueOnce({ integration: { company_id: 'company-1' } });

    await handleGetSsoConfig({ query: { company_id: 'company-1' } }, res, jest.fn());

    expect(res.set).toHaveBeenCalledWith('Cache-Control', 'no-store');
  });

  test('returns 404 when no config is found and 200 when config exists', async () => {
    const res1 = mockRes();
    ssoDataService.getSsoConfigDetails.mockResolvedValueOnce(null);
    await handleGetSsoConfig({ query: { company_id: 'company-1' } }, res1, jest.fn());
    expect(res1.status).toHaveBeenCalledWith(404);

    const res2 = mockRes();
    ssoDataService.getSsoConfigDetails.mockResolvedValueOnce({ integration: { company_id: 'company-2' } });
    await handleGetSsoConfig({ query: { domain: 'example.com' } }, res2, jest.fn());
    expect(res2.status).toHaveBeenCalledWith(200);
    expect(res2.json).toHaveBeenCalledWith({ success: true, data: { integration: { company_id: 'company-2' } } });
  });

  test('validates status changes, returns 404 for missing integrations, and invalidates cache on success', async () => {
    const invalidRes = mockRes();
    await handleSetSsoStatus({ params: { company_id: 'company-1' }, body: { status: 'paused' } }, invalidRes, jest.fn());
    expect(invalidRes.status).toHaveBeenCalledWith(400);

    const missingRes = mockRes();
    ssoDataService.setSsoStatus.mockResolvedValueOnce(false);
    await handleSetSsoStatus({ params: { company_id: 'company-2' }, body: { status: 'inactive' } }, missingRes, jest.fn());
    expect(missingRes.status).toHaveBeenCalledWith(404);

    const okRes = mockRes();
    ssoDataService.setSsoStatus.mockResolvedValueOnce(true);
    ssoDataService.getSsoConfigDetails.mockResolvedValueOnce({ integration: { domains: 'example.com' } });
    await handleSetSsoStatus({ params: { company_id: 'company-3' }, body: { status: 'active' } }, okRes, jest.fn());
    expect(ssoDataService.invalidateDomainCache).toHaveBeenCalledWith('example.com');
    expect(okRes.status).toHaveBeenCalledWith(200);
  });

  test('returns 404 when delete target is missing and invalidates cache on success', async () => {
    const missingRes = mockRes();
    ssoDataService.getSsoConfigDetails.mockResolvedValueOnce(null);
    await handleDeleteSsoConfig({ params: { company_id: 'company-4' } }, missingRes, jest.fn());
    expect(missingRes.status).toHaveBeenCalledWith(404);

    const okRes = mockRes();
    ssoDataService.getSsoConfigDetails.mockResolvedValueOnce({ integration: { domains: 'example.org' } });
    ssoDataService.deleteSsoConfig.mockResolvedValueOnce(true);
    await handleDeleteSsoConfig({ params: { company_id: 'company-5' } }, okRes, jest.fn());
    expect(ssoDataService.deleteSsoConfig).toHaveBeenCalledWith('company-5');
    expect(ssoDataService.invalidateDomainCache).toHaveBeenCalledWith('example.org');
    expect(okRes.status).toHaveBeenCalledWith(200);
  });
});
