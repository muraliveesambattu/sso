const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');

const ZdnaRole = sequelize.define('ZdnaRole', {
  role_id: {
    type:       DataTypes.STRING(64),
    primaryKey: true,
    allowNull:  false,
  },
  role_name: {
    type:      DataTypes.STRING(64),
    allowNull: false,
  },
  permissions: {
    type:         DataTypes.JSON,
    allowNull:    false,
    defaultValue: [],
  },
}, {
  tableName:  'zdna_roles',
  timestamps: false,
});

module.exports = ZdnaRole;
