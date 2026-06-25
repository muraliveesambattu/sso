'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('sso_users', {
      user_id: {
        type:         Sequelize.UUID,
        primaryKey:   true,
        defaultValue: Sequelize.literal('gen_random_uuid()'),
      },
      company_id: {
        type:       Sequelize.STRING(64),
        allowNull:  false,
        references: { model: 'sso_integrations', key: 'company_id' },
        onDelete:   'CASCADE',
      },
      email: {
        type:      Sequelize.STRING(256),
        allowNull: false,
      },
      oid: {
        type:      Sequelize.STRING(64),
        allowNull: false,
        comment:   'Microsoft Entra Object ID — unique per user per tenant',
      },
      display_name: {
        type:      Sequelize.STRING(256),
        allowNull: true,
      },
      roles: {
        type:         Sequelize.JSON,
        allowNull:    false,
        defaultValue: [],
      },
      jit_provisioned: {
        type:         Sequelize.BOOLEAN,
        allowNull:    false,
        defaultValue: false,
      },
      last_login: {
        type:      Sequelize.DATE,
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

    // FIXED: unique per company+oid (not globally unique)
    // Same Microsoft user can belong to multiple companies
    await queryInterface.addIndex('sso_users', ['company_id', 'oid'], {
      name:   'idx_sso_users_company_oid',
      unique: true,
    });

    await queryInterface.addIndex('sso_users', ['company_id', 'email'], {
      name: 'idx_sso_users_company_email',
    });

    await queryInterface.addIndex('sso_users', ['company_id'], {
      name: 'idx_sso_users_company_id',
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('sso_users');
  },
};
