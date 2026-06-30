'use strict';

/**
 * Returns true when the OIDC client authentication method requires a
 * client certificate (private_key_jwt or legacy 'certificate' alias).
 * Centralised here so saveSsoConfig.service and testConnection.service
 * stay in sync — a single place to update if new cert-based methods are added.
 *
 * @param {string} authMethod
 * @returns {boolean}
 */
const isCertAuth = (authMethod) =>
  authMethod === 'private_key_jwt' || authMethod === 'certificate';

module.exports = { isCertAuth };
