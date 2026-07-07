'use strict';

/**
 * jit_mappings.role_id had no FK — a typo'd role saved fine and JIT then
 * silently provisioned users with zero roles. Orphaned rows (role_id not in
 * zdna_roles) are removed first so the constraint can be applied; they were
 * never resolvable to a role, so nothing functional is lost.
 */
module.exports = {
  async up(queryInterface) {
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

  async down(queryInterface) {
    await queryInterface.removeConstraint('jit_mappings', 'fk_jit_mappings_role_id');
  },
};
