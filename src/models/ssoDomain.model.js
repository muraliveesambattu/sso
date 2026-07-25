const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');

// One row per verified domain owned by a company. A company may own many
// domains (1:many with sso_integrations); a domain maps to exactly one company
// (globally unique), so domain-check can resolve a login domain to its config.
const SsoDomain = sequelize.define('SsoDomain', {
  id: {
    type:          DataTypes.INTEGER,
    primaryKey:    true,
    autoIncrement: true,
  },
  company_id: {
    type:       DataTypes.STRING(64),
    allowNull:  false,
    references: { model: 'sso_integrations', key: 'company_id' },
  },
  domain: {
    type:      DataTypes.STRING(255),
    allowNull: false,
    unique:    true,
  },
}, {
  tableName:  'sso_domains',
  timestamps: true,
  createdAt:  'created_at',
  updatedAt:  false,
});

module.exports = SsoDomain;
