'use strict';

/**
 * Role catalog mirroring the zDNA Cloud console (Roles page, 2026-07-14).
 * Permission strings are 'feature:level' — levels: editable | view_only |
 * view_with_remote_control; "No Access" = feature absent from the array.
 * Manager and Temporary currently share the same matrix in the console;
 * they stay separate rows because tenants manage them independently.
 */

const EDITABLE_FEATURES = [
  'new_device_setup', 'my_devices', 'device_users', 'device_settings',
  'my_apps', 'design_studio', 'android_updates', 'licensing', 'remote_rxlogger',
];

const editable = (features) => JSON.stringify(features.map((f) => `${f}:editable`));

const ROLES = [
  { role_id: 'role-admin',     role_name: 'Admin',     permissions: editable([...EDITABLE_FEATURES, 'my_services', 'users']) },
  { role_id: 'role-manager',   role_name: 'Manager',   permissions: editable(EDITABLE_FEATURES) },
  { role_id: 'role-temporary', role_name: 'Temporary', permissions: editable(EDITABLE_FEATURES) },
];

module.exports = {
  async up(queryInterface) {
    // Upsert — safe to re-run, and existing rows converge on the console matrix
    const values = ROLES
      .map((r) => `('${r.role_id}', '${r.role_name}', '${r.permissions}')`)
      .join(',\n        ');
    await queryInterface.sequelize.query(`
      INSERT INTO zdna_roles (role_id, role_name, permissions)
      VALUES
        ${values}
      ON CONFLICT (role_id) DO UPDATE
        SET role_name = EXCLUDED.role_name, permissions = EXCLUDED.permissions;
    `);
  },

  async down(queryInterface) {
    await queryInterface.bulkDelete('zdna_roles', null, {});
  },
};
