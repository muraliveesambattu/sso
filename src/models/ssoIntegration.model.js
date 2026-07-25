const {DataTypes} = require('sequelize');
const sequelize = require('../config/db');

const ssoIntegration = sequelize.define('ssoIntegration',
    {
    company_id : {
        type:DataTypes.STRING(255),
        primaryKey:true,
        allowNull:false,
    },
    idp : {
        type :DataTypes.STRING(50),
        allowNull:false,
    },
    entra_tenant_id : {
        type:DataTypes.STRING(60),
        allowNull:false,
    },
    protocol: {
        type: DataTypes.STRING(10),
        allowNull:false,
    },
    sso_status : {
        type: DataTypes.STRING(10),
        allowNull:false,
    },
    jit_enabled : {
        type:DataTypes.BOOLEAN,
        allowNull:false,
        defaultValue:false
    }
},
    {
        tableName:'sso_integrations',
        timestamps: true,
        createdAt:'created_at',
        updatedAt:'updated_at'
    }

);

module.exports = ssoIntegration;