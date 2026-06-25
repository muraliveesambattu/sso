jest.mock('../src/config/constants', () => ({
  microsoft: {
    graphMemberOf: 'https://graph.microsoft.com/v1.0/me/memberOf?$select=id,securityEnabled',
  },
}));

const { EventEmitter } = require('events');
const https = require('https');
const { fetchUserGroupsFromGraph } = require('../src/utils/oidc/GraphApi.utils');

describe('GraphApi.utils', () => {
  let requestSpy;

  beforeEach(() => {
    jest.clearAllMocks();
    requestSpy = jest.spyOn(https, 'request');
  });

  afterEach(() => {
    requestSpy.mockRestore();
  });

  const queueResponses = (...responses) => {
    let index = 0;
    requestSpy.mockImplementation((options, callback) => {
      const req = new EventEmitter();
      req.end = jest.fn(() => {
        const response = responses[index++];
        if (response.timeout) {
          process.nextTick(() => req.emit('timeout'));
          return;
        }
        if (response.error) {
          process.nextTick(() => req.emit('error', response.error));
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

  test('paginates through Graph API results and returns only security group ids', async () => {
    queueResponses(
      {
        statusCode: 200,
        body: JSON.stringify({
          value: [
            { id: 'group-1', securityEnabled: true },
            { id: 'dist-list-1', securityEnabled: false },
          ],
          '@odata.nextLink': 'https://graph.microsoft.com/v1.0/me/memberOf?page=2',
        }),
      },
      {
        statusCode: 200,
        body: JSON.stringify({
          value: [
            { id: 'group-2', securityEnabled: true },
          ],
        }),
      }
    );

    const result = await fetchUserGroupsFromGraph('access-token-1');

    expect(result).toEqual(['group-1', 'group-2']);
    expect(requestSpy).toHaveBeenCalledTimes(2);
    expect(requestSpy.mock.calls[0][0]).toEqual(expect.objectContaining({
      method: 'GET',
      headers: expect.objectContaining({
        Authorization: 'Bearer access-token-1',
      }),
    }));
  });

  test('surfaces non-200 Graph API responses as errors', async () => {
    queueResponses({
      statusCode: 500,
      body: '{"error":"server_error"}',
    });

    await expect(fetchUserGroupsFromGraph('access-token-2')).rejects.toThrow(/Graph API failed: HTTP 500/);
  });

  test('rejects when the Graph API request times out', async () => {
    queueResponses({ timeout: true });

    await expect(fetchUserGroupsFromGraph('access-token-3')).rejects.toThrow('Graph API request timed out');
  });
});
