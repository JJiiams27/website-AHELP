const sqlite3 = require('sqlite3').verbose();
const DB_FILE = process.env.DB_FILE || 'users.db';
const db = new sqlite3.Database(DB_FILE);

const createTable = `CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  name TEXT,
  password TEXT,
  is_admin INTEGER DEFAULT 0
)`;
db.run(createTable);
db.run(`ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0`, err => {
  if (err && !/duplicate column/.test(err.message)) {
    console.error('Failed adding is_admin column', err);
  }
});

const createAssessments = `CREATE TABLE IF NOT EXISTS assessments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  data TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
)`;
db.run(createAssessments);

const createProgress = `CREATE TABLE IF NOT EXISTS progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER UNIQUE,
  weekly TEXT,
  monthly TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
)`;
db.run(createProgress);

const createChallenges = `CREATE TABLE IF NOT EXISTS challenges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  title TEXT,
  description TEXT,
  progress INTEGER,
  goal INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
)`;
db.run(createChallenges);

const createRewards = `CREATE TABLE IF NOT EXISTS rewards (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  title TEXT,
  points INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
)`;
db.run(createRewards);

const createInventory = `CREATE TABLE IF NOT EXISTS reward_inventory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  points INTEGER,
  quantity INTEGER
)`;
db.run(createInventory);

module.exports = db;
