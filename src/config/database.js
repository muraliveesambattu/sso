require('dotenv').config();

/**
 * Sequelize CLI configuration
 * Used by: sequelize-cli db:migrate, db:seed, db:migrate:undo
 */

const base = {
  dialect:  'postgres',
  logging:  false,
  migrationStorageTableName: 'sequelize_meta',
};

// Support DATABASE_URL (Cloud Run) or individual DB_* vars (local dev)
const fromUrl = process.env.DATABASE_URL
  ? { url: process.env.DATABASE_URL, ...base }
  : {
      username: process.env.DB_USER     || 'sso_user',
      password: process.env.DB_PASSWORD || 'sso_secret',
      database: process.env.DB_NAME     || 'sso_db',
      host:     process.env.DB_HOST     || 'localhost',
      port:     Number(process.env.DB_PORT) || 5432,
      ...base,
    };

module.exports = {
  development: fromUrl,
  test:        fromUrl,
  production:  fromUrl,
};
