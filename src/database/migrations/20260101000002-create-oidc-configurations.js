'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('oidc_configurations', {
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
      client_id: {
        type:      Sequelize.STRING(36),
        allowNull: false,
      },
      client_auth_method: {
        type:      Sequelize.STRING(50),
        allowNull: true,
      },
      // Stored as AES-256-GCM encrypted string: enc:<iv>:<authTag>:<ciphertext>
      client_secret_enc: {
        type:      Sequelize.TEXT,
        allowNull: true,
      },
      client_cert_thumbprint: {
        type:      Sequelize.TEXT,
        allowNull: true,
      },
      private_key_enc: {
        type:      Sequelize.TEXT,
        allowNull: true,
      },
      scope: {
        type:         Sequelize.STRING(200),
        allowNull:    false,
        defaultValue: 'openid profile email offline_access',
      },
      redirect_uri: {
        type:      Sequelize.STRING(512),
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

    await queryInterface.addIndex('oidc_configurations', ['company_id'], {
      name: 'idx_oidc_configurations_company_id',
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('oidc_configurations');
  },
};
