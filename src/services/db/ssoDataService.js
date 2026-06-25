/**
 * SSO Data Service — Smart Router
 * Picks PostgreSQL or JSON store based on the single `usePostgres` switch
 * in src/config/dataSource.js (controlled by DATA_SOURCE / DB env vars).
 */

const { usePostgres } = require('../../config/dataSource');

module.exports = usePostgres
  ? require('./postgresSSO.service')
  : require('./localSSO.service');
