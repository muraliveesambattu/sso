'use strict';

/**
 * userResolution has always written login_method ('sso') and the non-JIT path
 * checks it to block auth-method bypass — but the column never existed in
 * Postgres, so Sequelize silently dropped the value and the check never fired.
 */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('sso_users', 'login_method', {
      type:         Sequelize.STRING(20),
      allowNull:    false,
      defaultValue: 'sso',
    });
  },

  async down(queryInterface) {
    await queryInterface.removeColumn('sso_users', 'login_method');
  },
};
