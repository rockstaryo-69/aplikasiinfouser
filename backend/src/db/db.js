/**
 * Database Connection Pool (PostgreSQL via pg)
 */
const { Pool } = require('pg');
const { logger } = require('../middleware/logger');

const pool = new Pool({
  host:     process.env.PG_HOST     || 'localhost',
  port:     parseInt(process.env.PG_PORT) || 5432,
  database: process.env.PG_DATABASE || 'cyberscope',
  user:     process.env.PG_USER     || 'postgres',
  password: process.env.PG_PASSWORD,
  max: 20,                    // Max pool size
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.on('error', (err) => {
  logger.error(`Unexpected DB pool error: ${err.message}`);
});

/**
 * Execute a parameterized query
 * @param {string} text  - SQL query with $1, $2... placeholders
 * @param {any[]}  params - Query parameters
 */
async function query(text, params = []) {
  const start = Date.now();
  const client = await pool.connect();
  try {
    const res = await client.query(text, params);
    const duration = Date.now() - start;
    if (duration > 1000) logger.warn(`Slow query (${duration}ms): ${text.slice(0, 100)}`);
    return res;
  } finally {
    client.release();
  }
}

/**
 * Execute a transaction
 * @param {Function} callback - async (client) => { ... }
 */
async function transaction(callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function checkConnection() {
  try {
    const res = await query('SELECT NOW() AS time, current_database() AS db');
    logger.info(`DB connected: ${res.rows[0].db} @ ${res.rows[0].time}`);
    return true;
  } catch (err) {
    logger.error(`DB connection failed: ${err.message}`);
    return false;
  }
}

module.exports = { query, transaction, checkConnection, pool };
