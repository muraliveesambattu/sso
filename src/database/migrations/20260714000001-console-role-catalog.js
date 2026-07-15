'use strict';

/**
 * Replace the placeholder role catalog (Administrator/Analyst/Viewer with flat
 * read/write permissions) with the real zDNA Cloud console roles
 * (Admin/Manager/Temporary with 'feature:level' permission strings).
 *
 * Existing references are remapped before the old rows are deleted —
 * jit_mappings.role_id carries an FK (RESTRICT) and sso_users.roles is a JSON
 * array of role_ids with no FK, so both must move:
 *   role-analyst → role-manager, role-viewer → role-temporary
 */

const EDITABLE_FEATURES = [
  'new_device_setup', 'my_devices', 'device_users', 'device_settings',
  'my_apps', 'design_studio', 'android_updates', 'licensing', 'remote_rxlogger',
];

const editable = (features) => JSON.stringify(features.map((f) => `${f}:editable`));

const NEW_ROLES = [
  { role_id: 'role-admin',     role_name: 'Admin',     permissions: editable([...EDITABLE_FEATURES, 'my_services', 'users']) },
  { role_id: 'role-manager',   role_name: 'Manager',   permissions: editable(EDITABLE_FEATURES) },
  { role_id: 'role-temporary', role_name: 'Temporary', permissions: editable(EDITABLE_FEATURES) },
];

const OLD_ROLES = [
  { role_id: 'role-admin',   role_name: 'Administrator', permissions: '["read","write","delete","manage_users"]' },
  { role_id: 'role-analyst', role_name: 'Analyst',       permissions: '["read","write"]' },
  { role_id: 'role-viewer',  role_name: 'Viewer',        permissions: '["read"]' },
];

const upsertRoles = async (queryInterface, roles) => {
  const values = roles
    .map((r) => `('${r.role_id}', '${r.role_name}', '${r.permissions}')`)
    .join(',\n      ');
  await queryInterface.sequelize.query(`
    INSERT INTO zdna_roles (role_id, role_name, permissions)
    VALUES
      ${values}
    ON CONFLICT (role_id) DO UPDATE
      SET role_name = EXCLUDED.role_name, permissions = EXCLUDED.permissions;
  `);
};

const remapRole = async (queryInterface, from, to) => {
  await queryInterface.sequelize.query(`
    UPDATE jit_mappings SET role_id = '${to}' WHERE role_id = '${from}';
  `);
  // sso_users.roles is a JSON array of role_id strings
  await queryInterface.sequelize.query(`
    UPDATE sso_users
    SET    roles = replace(roles::text, '"${from}"', '"${to}"')::json
    WHERE  roles::text LIKE '%"${from}"%';
  `);
};

module.exports = {
  async up(queryInterface) {
    await upsertRoles(queryInterface, NEW_ROLES);
    await remapRole(queryInterface, 'role-analyst', 'role-manager');
    await remapRole(queryInterface, 'role-viewer', 'role-temporary');
    await queryInterface.sequelize.query(`
      DELETE FROM zdna_roles WHERE role_id IN ('role-analyst', 'role-viewer');
    `);
  },

  // Best-effort reverse: restores the old catalog and remaps references back.
  // Lossy — pre-migration Manager/Temporary assignments (if any) become
  // Analyst/Viewer too, since the forward remap is not distinguishable.
  async down(queryInterface) {
    await upsertRoles(queryInterface, OLD_ROLES);
    await remapRole(queryInterface, 'role-manager', 'role-analyst');
    await remapRole(queryInterface, 'role-temporary', 'role-viewer');
    await queryInterface.sequelize.query(`
      DELETE FROM zdna_roles WHERE role_id IN ('role-manager', 'role-temporary');
    `);
  },
};
