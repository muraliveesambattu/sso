'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('sso_domains', {
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
        onUpdate:   'CASCADE',
      },
      domain: {
        type:      Sequelize.STRING(255),
        allowNull: false,
      },
      created_at: {
        type:         Sequelize.DATE,
        allowNull:    false,
        defaultValue: Sequelize.literal('NOW()'),
      },
    });

    // A domain belongs to exactly one company — global unique for domain-check.
    await queryInterface.addIndex('sso_domains', ['domain'], {
      name:   'idx_sso_domains_domain',
      unique: true,
    });

    // Fast lookup of all domains for a company (config view, delete cascade).
    await queryInterface.addIndex('sso_domains', ['company_id'], {
      name: 'idx_sso_domains_company_id',
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('sso_domains');
  },
};
