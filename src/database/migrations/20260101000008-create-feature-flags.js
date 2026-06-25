'use strict';

/**
 * Feature Flags Table
 *
 * Stores per-company feature flags.
 * Two flags implemented:
 *   sso_enabled  — master switch, disables entire SSO flow
 *   jit_enabled  — controls auto user provisioning on first login
 *
 * Priority (highest wins):
 *   1. Env var FEATURE_<FLAG>_DISABLED=true  → global kill switch
 *   2. DB row per company                    → per-company control
 *   3. Default (true)                        → if no row found
 */

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('feature_flags', {
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
      flag_name: {
        type:      Sequelize.STRING(64),
        allowNull: false,
        comment:   'sso_enabled | jit_enabled',
      },
      enabled: {
        type:         Sequelize.BOOLEAN,
        allowNull:    false,
        defaultValue: true,
      },
      // Who changed it and when — full audit trail
      updated_by: {
        type:      Sequelize.STRING(256),
        allowNull: true,
        comment:   'IP or admin identifier of who last changed this flag',
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

    // One flag per company — no duplicate flag names
    await queryInterface.addIndex('feature_flags', ['company_id', 'flag_name'], {
      name:   'idx_feature_flags_company_flag',
      unique: true,
    });

    await queryInterface.addIndex('feature_flags', ['company_id'], {
      name: 'idx_feature_flags_company_id',
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('feature_flags');
  },
};
