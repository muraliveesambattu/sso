const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');

const SamlConfiguration = sequelize.define('SamlConfiguration', {
  company_id: {
    type:       DataTypes.STRING(64),
    allowNull:  false,
    unique:     true,
    references: { model: 'sso_integrations', key: 'company_id' },
  },
  entity_id: {
    type:      DataTypes.STRING(255),
    allowNull: false,
  },
  sso_url: {
    type:      DataTypes.STRING(512),
    allowNull: false,
  },
  acs_url: {
    type:      DataTypes.STRING(512),
    allowNull: false,
  },
  certificate: {
    type:      DataTypes.TEXT,
    allowNull: true,
  },
  cert_expiry: {
    type:      DataTypes.DATE,
    allowNull: true,
  },
  sp_private_key_enc: {
    type:      DataTypes.TEXT,
    allowNull: true,
  },
}, {
  tableName:  'saml_configurations',
  timestamps: true,
  createdAt:  'created_at',
  updatedAt:  'updated_at',
});

module.exports = SamlConfiguration;
