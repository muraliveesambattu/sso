const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');

const SsoUser = sequelize.define('SsoUser', {
  user_id: {
    type:         DataTypes.UUID,
    primaryKey:   true,
    defaultValue: DataTypes.UUIDV4,
  },
  company_id: {
    type:       DataTypes.STRING(64),
    allowNull:  false,
    references: { model: 'sso_integrations', key: 'company_id' },
  },
  email: {
    type:      DataTypes.STRING(256),
    allowNull: false,
  },
  oid: {
    type:      DataTypes.STRING(64),
    allowNull: false,
    unique:    true,
  },
  display_name: {
    type:      DataTypes.STRING(256),
    allowNull: true,
  },
  roles: {
    type:         DataTypes.JSON,
    allowNull:    false,
    defaultValue: [],
  },
  jit_provisioned: {
    type:         DataTypes.BOOLEAN,
    allowNull:    false,
    defaultValue: false,
  },
  // How this user authenticates — the non-JIT login path denies SSO to users
  // created via another method (auth-method bypass guard).
  login_method: {
    type:         DataTypes.STRING(20),
    allowNull:    false,
    defaultValue: 'sso',
  },
  last_login: {
    type:      DataTypes.DATE,
    allowNull: true,
  },
}, {
  tableName:   'sso_users',
  timestamps:  true,
  createdAt:   'created_at',
  updatedAt:   'updated_at',
});

module.exports = SsoUser;
