'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('saml_configurations', {
      id: {
        type:          Sequelize.INTEGER,
        primaryKey:    true,
        autoIncrement: true,
      },
      company_id: {
        type:       Sequelize.STRING(64),
        allowNull:  false,
        unique:     true,
        references: { model: 'sso_integrations', key: 'company_id' },
        onDelete:   'CASCADE',
      },
      entity_id: {
        type:      Sequelize.STRING(255),
        allowNull: false,
      },
      sso_url: {
        type:      Sequelize.STRING(512),
        allowNull: false,
      },
      acs_url: {
        type:      Sequelize.STRING(512),
        allowNull: false,
      },
      certificate: {
        type:      Sequelize.TEXT,
        allowNull: true,
      },
      cert_expiry: {
        type:      Sequelize.DATE,
        allowNull: true,
      },
      sp_private_key_enc: {
        type:      Sequelize.TEXT,
        allowNull: true,
      },
      created_at: {
        type:         Sequelize.DATE,
        allowNull:    false,
        defaultValue: Sequelize.literal('NOW()'),
      },
      updated_at: {
        type:         Sequelize.DATE,
        allowNull:    false,
        defaultValue: Sequelize.literal('NOW()'),
      },
    });

    await queryInterface.addIndex('saml_configurations', ['company_id'], {
      name: 'idx_saml_configurations_company_id',
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('saml_configurations');
  },
};
