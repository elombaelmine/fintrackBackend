import pg from 'pg';
import dotenv from 'dotenv';
dotenv.config();

const { Pool } = pg;

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 5,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
    })
  : null;

// Prevent unhandled 'error' events from terminated idle clients crashing Node
pool?.on('error', (err) => {
  console.error('Unexpected pool client error:', err.message);
});

export default pool;
