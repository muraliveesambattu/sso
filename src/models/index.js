const sequelize         = require('../config/db');
const SsoIntegration    = require('./ssoIntegration.model');
const SsoDomain         = require('./ssoDomain.model');
const OidcConfiguration = require('./oidcConfig.model');
const SamlConfiguration = require('./samlConfig.model');
const JitMapping        = require('./jitMapping.model');
const SsoUser           = require('./user.model');

// sso_integrations → sso_domains (1:many)
SsoIntegration.hasMany(SsoDomain, { foreignKey: 'company_id', onDelete: 'CASCADE' });
SsoDomain.belongsTo(SsoIntegration, { foreignKey: 'company_id' });

// sso_integrations → oidc_configurations (1:1)
SsoIntegration.hasOne(OidcConfiguration,  { foreignKey: 'company_id', onDelete: 'CASCADE' });
OidcConfiguration.belongsTo(SsoIntegration, { foreignKey: 'company_id' });

// sso_integrations → saml_configurations (1:1)
SsoIntegration.hasOne(SamlConfiguration,  { foreignKey: 'company_id', onDelete: 'CASCADE' });
SamlConfiguration.belongsTo(SsoIntegration, { foreignKey: 'company_id' });

// sso_integrations → jit_mappings (1:many)
SsoIntegration.hasMany(JitMapping, { foreignKey: 'company_id', onDelete: 'CASCADE' });
JitMapping.belongsTo(SsoIntegration, { foreignKey: 'company_id' });

// sso_integrations → sso_users (1:many)
SsoIntegration.hasMany(SsoUser, { foreignKey: 'company_id', onDelete: 'CASCADE' });
SsoUser.belongsTo(SsoIntegration, { foreignKey: 'company_id' });

module.exports = { sequelize, SsoIntegration, SsoDomain, OidcConfiguration, SamlConfiguration, JitMapping, SsoUser };
