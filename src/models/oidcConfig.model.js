const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');

const OidcConfiguration = sequelize.define('OidcConfiguration', {
  company_id: {
    type:       DataTypes.STRING(64),
    allowNull:  false,
    unique:     true,
    references: { model: 'sso_integrations', key: 'company_id' },
  },
  client_id: {
    type:      DataTypes.STRING(36),
    allowNull: false,
  },
  client_auth_method: {
    type:      DataTypes.STRING(50),
    allowNull: true,
  },
  // Stored encrypted or as "env:VAR_NAME" reference — never plain text
  client_secret_enc: {
    type:      DataTypes.TEXT,
    allowNull: true,
  },
  client_cert_thumbprint: {
    type:      DataTypes.TEXT,
    allowNull: true,
  },
  private_key_enc: {
    type:      DataTypes.TEXT,
    allowNull: true,
  },
  scope: {
    type:         DataTypes.STRING(200),
    allowNull:    false,
    defaultValue: 'openid profile email offline_access',
  },
  redirect_uri: {
    type:      DataTypes.STRING(512),
    allowNull: true,
  },
}, {
  tableName:  'oidc_configurations',
  timestamps: true,
  createdAt:  'created_at',
  updatedAt:  'updated_at',
});

module.exports = OidcConfiguration;
