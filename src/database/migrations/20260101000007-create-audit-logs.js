'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('audit_logs', {
      id: {
        type:          Sequelize.BIGINT,
        primaryKey:    true,
        autoIncrement: true,
      },
      // Who
      actor:       { type: Sequelize.STRING(256), allowNull: true  }, // email or 'system'
      actor_ip:    { type: Sequelize.STRING(64),  allowNull: true  },
      // What
      action:      { type: Sequelize.STRING(64),  allowNull: false }, // e.g. sso_config_saved, user_login
      resource:    { type: Sequelize.STRING(64),  allowNull: true  }, // e.g. sso_integrations, sso_users
      resource_id: { type: Sequelize.STRING(128), allowNull: true  }, // company_id or user_id
      // Detail
      status:      { type: Sequelize.STRING(20),  allowNull: false, defaultValue: 'success' }, // success | failure
      detail:      { type: Sequelize.JSONB,        allowNull: true  }, // extra context
      // When
      created_at: {
        type:         Sequelize.DATE,
        allowNull:    false,
        defaultValue: Sequelize.literal('NOW()'),
      },
    });

    // Fast queries: by actor, by resource, by time range
    await queryInterface.addIndex('audit_logs', ['action'],      { name: 'idx_audit_action' });
    await queryInterface.addIndex('audit_logs', ['actor'],       { name: 'idx_audit_actor' });
    await queryInterface.addIndex('audit_logs', ['resource_id'], { name: 'idx_audit_resource_id' });
    await queryInterface.addIndex('audit_logs', ['created_at'],  { name: 'idx_audit_created_at' });
    await queryInterface.addIndex('audit_logs', ['status'],      { name: 'idx_audit_status' });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('audit_logs');
  },
};
