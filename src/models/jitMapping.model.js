const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');

const JitMapping = sequelize.define('JitMapping', {
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
  mapping_source: {
    type:      DataTypes.STRING(30),   // "group" | "default"
    allowNull: false,
  },
  mapping_value: {
    type:      DataTypes.STRING(256),  // Azure AD group name, or null for default
    allowNull: true,
  },
  role_id: {
    type:      DataTypes.STRING(64),
    allowNull: false,
  },
  priority: {
    type:      DataTypes.INTEGER,
    allowNull: false,
  },
  status: {
    type:         DataTypes.STRING(10),
    allowNull:    false,
    defaultValue: 'active',
  },
}, {
  tableName:  'jit_mappings',
  timestamps: true,
  createdAt:  'created_at',
  updatedAt:  'updated_at',
  indexes: [
    { unique: true, fields: ['company_id', 'priority'] },
  ],
});

module.exports = JitMapping;
