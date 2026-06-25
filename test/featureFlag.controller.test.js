jest.mock('../src/services/featureFlag.service', () => ({
  isEnabled: jest.fn(),
  setFlag: jest.fn(),
  getFlagsForCompany: jest.fn(),
  VALID_FLAGS: ['sso_enabled', 'jit_enabled'],
}));

jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

jest.mock('../src/services/audit/audit.service', () => ({
  writeAuditLog: jest.fn(),
}));

const { getFlags, updateFlag } = require('../src/controllers/featureFlag.controller');
const { getFlagsForCompany, setFlag } = require('../src/services/featureFlag.service');
const { writeAuditLog } = require('../src/services/audit/audit.service');

const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

describe('featureFlag.controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('returns 400 when company_id is missing for getFlags', async () => {
    const res = mockRes();

    await getFlags({ params: {}, ip: '1.2.3.4' }, res, jest.fn());

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json.mock.calls[0][0].error.code).toBe('MISSING_COMPANY_ID');
  });

  test('returns flags and valid flag names on success', async () => {
    const res = mockRes();
    const next = jest.fn();
    getFlagsForCompany.mockResolvedValue({ sso_enabled: { enabled: true, source: 'default' } });

    await getFlags({ params: { company_id: 'company-1' }, ip: '1.2.3.4' }, res, next);

    expect(getFlagsForCompany).toHaveBeenCalledWith('company-1');
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      success: true,
      company_id: 'company-1',
      flags: { sso_enabled: { enabled: true, source: 'default' } },
      valid_flags: ['sso_enabled', 'jit_enabled'],
    });
    expect(next).not.toHaveBeenCalled();
  });

  test('validates missing fields for updateFlag', async () => {
    const res1 = mockRes();
    await updateFlag({ body: {}, ip: '1.2.3.4' }, res1, jest.fn());
    expect(res1.status).toHaveBeenCalledWith(400);

    const res2 = mockRes();
    await updateFlag({ body: { company_id: 'company-1' }, ip: '1.2.3.4' }, res2, jest.fn());
    expect(res2.status).toHaveBeenCalledWith(400);

    const res3 = mockRes();
    await updateFlag({ body: { company_id: 'company-1', flag: 'sso_enabled' }, ip: '1.2.3.4' }, res3, jest.fn());
    expect(res3.status).toHaveBeenCalledWith(400);
  });

  test('updates a flag, writes an audit log, and returns success', async () => {
    const res = mockRes();
    const next = jest.fn();

    await updateFlag({
      body: { company_id: 'company-2', flag: 'sso_enabled', enabled: 0 },
      ip: '1.2.3.4',
    }, res, next);

    expect(setFlag).toHaveBeenCalledWith('company-2', 'sso_enabled', false, '1.2.3.4');
    expect(writeAuditLog).toHaveBeenCalledWith(expect.objectContaining({
      actor: '1.2.3.4',
      action: 'feature_flag_updated',
      detail: { flag: 'sso_enabled', enabled: false },
    }));
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json.mock.calls[0][0]).toEqual(expect.objectContaining({
      success: true,
      company_id: 'company-2',
      flag: 'sso_enabled',
      enabled: false,
    }));
    expect(next).not.toHaveBeenCalled();
  });

  test('passes service errors to next', async () => {
    const res = mockRes();
    const next = jest.fn();
    const err = Object.assign(new Error('bad flag'), { code: 'INVALID_FLAG' });
    setFlag.mockRejectedValue(err);

    await updateFlag({
      body: { company_id: 'company-3', flag: 'bad_flag', enabled: true },
      ip: '1.2.3.4',
    }, res, next);

    expect(next).toHaveBeenCalledWith(err);
  });
});
