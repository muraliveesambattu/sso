'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('jit_mappings', {
      id: {
        type:          Sequelize.INTEGER,
        primaryKey:    true,
        autoIncrement: true,
      },
      company_id: {
        type:       Sequelize.STRING(64),
        allowNull:  false,
        references: { model: 'sso_integrations', key: 'company_id' },
        onDelete:   'CASCADE',
      },
      mapping_source: {
        type:      Sequelize.STRING(30),   // "group" | "default"
        allowNull: false,
      },
      mapping_value: {
        type:      Sequelize.STRING(256),  // Azure AD group name or null for default
        allowNull: true,
      },
      role_id: {
        type:      Sequelize.STRING(64),
        allowNull: false,
      },
      role_name: {
        type:      Sequelize.STRING(64),
        allowNull: false,
      },
      priority: {
        type:      Sequelize.INTEGER,
        allowNull: false,
      },
      status: {
        type:         Sequelize.STRING(10),
        allowNull:    false,
        defaultValue: 'active',
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

    // Index for fast JIT lookup by company
    await queryInterface.addIndex('jit_mappings', ['company_id'], {
      name: 'idx_jit_mappings_company_id',
    });

    // Unique priority per company — prevents duplicate priorities
    await queryInterface.addIndex('jit_mappings', ['company_id', 'priority'], {
      name:   'idx_jit_mappings_company_priority',
      unique: true,
    });

    await queryInterface.addIndex('jit_mappings', ['status'], {
      name: 'idx_jit_mappings_status',
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('jit_mappings');
  },
};
