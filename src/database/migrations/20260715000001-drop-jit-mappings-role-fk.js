'use strict';

/**
 * Reverts 20260707000001: jit_mappings.role_id can no longer be a foreign key
 * to zdna_roles. RMS roles are defined per-tenant — each company manages its
 * own custom role names via the console's Roles page — so the set of valid
 * values is not enumerable from this backend and cannot be constrained to a
 * fixed local catalog. Login-time resolution now passes through any role_id
 * it doesn't recognise locally (see resolveRoles in userResolution.service.js).
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.removeConstraint('jit_mappings', 'fk_jit_mappings_role_id');
  },

  // Best-effort reverse: restores the FK, first dropping any rows that would
  // now violate it (arbitrary tenant role names saved while the FK was gone).
  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DELETE FROM jit_mappings
      WHERE  role_id NOT IN (SELECT role_id FROM zdna_roles);
    `);

    await queryInterface.addConstraint('jit_mappings', {
      fields: ['role_id'],
      type:   'foreign key',
      name:   'fk_jit_mappings_role_id',
      references: { table: 'zdna_roles', field: 'role_id' },
      onDelete: 'RESTRICT',
      onUpdate: 'CASCADE',
    });
  },
};
