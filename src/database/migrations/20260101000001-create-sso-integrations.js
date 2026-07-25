'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('sso_integrations', {
      company_id: {
        type:       Sequelize.STRING(64),
        primaryKey: true,
        allowNull:  false,
      },
      idp: {
        type:      Sequelize.STRING(50),
        allowNull: false,
      },
      entra_tenant_id: {
        type:      Sequelize.STRING(60),
        allowNull: false,
      },
      protocol: {
        type:      Sequelize.STRING(10),
        allowNull: false,
      },
      sso_status: {
        type:         Sequelize.STRING(10),
        allowNull:    false,
        defaultValue: 'active',
      },
      jit_enabled: {
        type:         Sequelize.BOOLEAN,
        allowNull:    false,
        defaultValue: false,
      },
      created_at: {
        type:      Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.literal('NOW()'),
      },
      updated_at: {
        type:      Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.literal('NOW()'),
      },
    });

    await queryInterface.addIndex('sso_integrations', ['sso_status'], {
      name: 'idx_sso_integrations_status',
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('sso_integrations');
  },
};
