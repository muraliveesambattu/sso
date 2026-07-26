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
    type:      DataTypes.STRING(512),
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
  // Whether the SP should sign the AuthnRequest — was previously dropped on
  // save (no column). Signing also requires an SP private key to be present.
  sign_authn_request: {
    type:         DataTypes.BOOLEAN,
    allowNull:    false,
    defaultValue: false,
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
