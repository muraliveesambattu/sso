'use strict';

/**
 * samlConfig.model has app_id and client_secret_enc, but no migration created
 * them, so every SamlConfiguration query failed with "column does not exist".
 * Guarded so databases that already have the columns are left alone.
 */
module.exports = {
  async up(queryInterface, Sequelize) {
    const table = await queryInterface.describeTable('saml_configurations');
    if (!table.app_id) {
      await queryInterface.addColumn('saml_configurations', 'app_id', {
        type: Sequelize.STRING(128),
        allowNull: true,
      });
    }
    if (!table.client_secret_enc) {
      await queryInterface.addColumn('saml_configurations', 'client_secret_enc', {
        type: Sequelize.TEXT,
        allowNull: true,
      });
    }
  },

  async down(queryInterface) {
    await queryInterface.removeColumn('saml_configurations', 'client_secret_enc');
    await queryInterface.removeColumn('saml_configurations', 'app_id');
  },
};
