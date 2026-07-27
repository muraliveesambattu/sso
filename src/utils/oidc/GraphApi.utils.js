/**
 * Microsoft Graph API Groups Fallback
 *
 * Called only when Entra omits the groups[] claim due to token size limits
 * (user belongs to more than 200 groups).
 *
 * When overage occurs, Entra sets _claim_names.groups in the token as a signal.
 * We then call Graph API GET /me/memberOf and paginate through all results.
 *
 * Requires GroupMember.Read.All scope on the access_token.
 * This scope must be granted admin consent in the Entra App Registration.
 */

const https     = require('node:https');
const { URL }   = require('node:url');  
const { microsoft } = require('../../config/constants');

// Fetches a single page from Graph API
const fetchGraphPage = (accessToken, url) => {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);

    const options = {
      hostname: parsedUrl.hostname,
      path:     parsedUrl.pathname + parsedUrl.search,
      method:   'GET',
      headers: {
        Authorization:  `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      timeout:            10000,
      rejectUnauthorized: true
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode === 200) {
            const parsed = JSON.parse(data);
            resolve({
              value:    parsed.value || [],
              nextLink: parsed['@odata.nextLink'] || null
            });
          } else {
            reject(new Error(`Graph API failed: HTTP ${res.statusCode} ╬ô├ç├╢ ${data}`));
          }
        } catch (err) {
          reject(new Error(`Failed to parse Graph API response: ${err.message}`));
        }
      });
    });

    req.on('error',   err => reject(new Error(`Graph API network error: ${err.message}`)));
    req.on('timeout', ()  => { req.destroy(); reject(new Error('Graph API request timed out')); });
    req.end();
  });
};

/**
 * Fetches ALL security group memberships for the authenticated user.
 * Follows @odata.nextLink pagination until all pages are retrieved.
 * Returns only Security Group Object IDs (same format as JWT groups[] claim).
 */
const fetchUserGroupsFromGraph = async (accessToken) => {
  const INITIAL_URL = microsoft.graphMemberOf;

  const allGroups = [];
  let nextUrl     = INITIAL_URL;

  while (nextUrl) {
    const { value, nextLink } = await fetchGraphPage(accessToken, nextUrl);

    // Filter to security groups only excludes distribution lists and M365 groups
    const securityGroupIds = value
      .filter(g => g.securityEnabled === true)
      .map(g => g.id);

    allGroups.push(...securityGroupIds);
    nextUrl = nextLink;
  }

  return allGroups;
};

// Raw single-object GET against Graph (fetchGraphPage is page-shaped; /me is not)
const fetchGraphObject = (accessToken, url) => {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const options = {
      hostname: parsedUrl.hostname,
      path:     parsedUrl.pathname + parsedUrl.search,
      method:   'GET',
      headers: {
        Authorization:  `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      timeout:            10000,
      rejectUnauthorized: true
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode === 200) resolve(JSON.parse(data));
          else reject(new Error(`Graph API failed: HTTP ${res.statusCode}`));
        } catch (err) {
          reject(new Error(`Failed to parse Graph API response: ${err.message}`));
        }
      });
    });
    req.on('error',   err => reject(new Error(`Graph API network error: ${err.message}`)));
    req.on('timeout', ()  => { req.destroy(); reject(new Error('Graph API request timed out')); });
    req.end();
  });
};

/**
 * Fetches the signed-in user's department and job title.
 * Feeds the department/jobtitle JIT mapping sources — the id_token does not
 * carry these attributes, so Graph is the only reliable source on OIDC.
 * Requires User.Read (delegated), granted by the default sign-in consent.
 *
 * @returns {Promise<{department: string|null, jobTitle: string|null}>}
 */
const fetchUserProfileFromGraph = async (accessToken) => {
  const me = await fetchGraphObject(accessToken, microsoft.graphMe);
  return { department: me.department ?? null, jobTitle: me.jobTitle ?? null };
};

module.exports = { fetchUserGroupsFromGraph, fetchUserProfileFromGraph };
