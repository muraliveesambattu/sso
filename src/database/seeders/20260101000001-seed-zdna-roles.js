'use strict';

module.exports = {
  async up(queryInterface) {
    // Use INSERT ... ON CONFLICT DO NOTHING — safe to re-run
    await queryInterface.sequelize.query(`
      INSERT INTO zdna_roles (role_id, role_name, permissions)
      VALUES
        ('role-admin',   'Administrator', '["read","write","delete","manage_users"]'),
        ('role-analyst', 'Analyst',       '["read","write"]'),
        ('role-viewer',  'Viewer',        '["read"]')
      ON CONFLICT (role_id) DO NOTHING;
    `);
  },

  async down(queryInterface) {
    await queryInterface.bulkDelete('zdna_roles', null, {});
  },
};
