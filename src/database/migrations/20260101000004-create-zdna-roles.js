'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('zdna_roles', {
      role_id: {
        type:       Sequelize.STRING(64),
        primaryKey: true,
        allowNull:  false,
      },
      role_name: {
        type:      Sequelize.STRING(64),
        allowNull: false,
      },
      permissions: {
        type:         Sequelize.JSON,
        allowNull:    false,
        defaultValue: [],
      },
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('zdna_roles');
  },
};
