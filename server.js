const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const db = new sqlite3.Database('users.db');
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

app.use(express.json());

// Ensure Users table exists
const createTable = `CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  name TEXT,
  password TEXT
)`;
db.run(createTable);

// Additional tables for assessments, progress, challenges and rewards
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

// Register endpoint
app.post('/api/auth/register', (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  const hashed = bcrypt.hashSync(password, 10);
  const stmt = `INSERT INTO users (email, name, password) VALUES (?, ?, ?)`;
  db.run(stmt, [email, name || '' , hashed], function(err) {
    if (err) {
      if (err.code === 'SQLITE_CONSTRAINT') {
        return res.status(400).json({ error: 'User already exists' });
      }
      return res.status(500).json({ error: 'Database error' });
    }
    const user = { id: this.lastID, email, name: name || '' };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user });
  });
});

// Login endpoint
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  const query = `SELECT * FROM users WHERE email = ?`;
  db.get(query, [email], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!row) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const match = bcrypt.compareSync(password, row.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = { id: row.id, email: row.email, name: row.name };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user });
  });
});

// --- Assessments ---
app.post('/api/assessments', (req, res) => {
  const { user_id, data } = req.body;
  if (!user_id || !data) {
    return res.status(400).json({ error: 'user_id and data required' });
  }
  const stmt = `INSERT INTO assessments (user_id, data) VALUES (?, ?)`;
  db.run(stmt, [user_id, JSON.stringify(data)], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ id: this.lastID });
  });
});

app.get('/api/assessments', (req, res) => {
  const userId = req.query.user_id;
  const query = userId
    ? `SELECT * FROM assessments WHERE user_id = ?`
    : `SELECT * FROM assessments`;
  const params = userId ? [userId] : [];
  db.all(query, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows.map(r => ({ ...r, data: JSON.parse(r.data) })));
  });
});

// --- Progress ---
app.post('/api/progress', (req, res) => {
  const { user_id, weekly, monthly } = req.body;
  if (!user_id) {
    return res.status(400).json({ error: 'user_id required' });
  }
  const stmt = `INSERT INTO progress (user_id, weekly, monthly)
               VALUES (?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET
                 weekly = excluded.weekly,
                 monthly = excluded.monthly`;
  db.run(stmt, [user_id, JSON.stringify(weekly || []), JSON.stringify(monthly || [])], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ id: this.lastID });
  });
});

app.get('/api/progress', (req, res) => {
  const userId = req.query.user_id;
  if (!userId) {
    return res.status(400).json({ error: 'user_id required' });
  }
  const query = `SELECT weekly, monthly FROM progress WHERE user_id = ?`;
  db.get(query, [userId], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!row) {
      return res.json({ weekly: [], monthly: [] });
    }
    res.json({
      weekly: JSON.parse(row.weekly || '[]'),
      monthly: JSON.parse(row.monthly || '[]')
    });
  });
});

// --- Challenges ---
app.post('/api/challenges', (req, res) => {
  const { user_id, title, description, progress, goal } = req.body;
  if (!user_id || !title) {
    return res.status(400).json({ error: 'user_id and title required' });
  }
  const stmt = `INSERT INTO challenges (user_id, title, description, progress, goal) VALUES (?, ?, ?, ?, ?)`;
  db.run(stmt, [user_id, title, description || '', progress || 0, goal || 0], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ id: this.lastID });
  });
});

app.get('/api/challenges', (req, res) => {
  const userId = req.query.user_id;
  const query = userId
    ? `SELECT * FROM challenges WHERE user_id = ?`
    : `SELECT * FROM challenges`;
  const params = userId ? [userId] : [];
  db.all(query, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// --- Rewards ---
app.post('/api/rewards', (req, res) => {
  const { user_id, title, points } = req.body;
  if (!user_id || !title || typeof points !== 'number') {
    return res.status(400).json({ error: 'user_id, title and points required' });
  }
  const stmt = `INSERT INTO rewards (user_id, title, points) VALUES (?, ?, ?)`;
  db.run(stmt, [user_id, title, points], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ id: this.lastID });
  });
});

app.get('/api/rewards', (req, res) => {
  const userId = req.query.user_id;
  if (!userId) {
    return res.status(400).json({ error: 'user_id required' });
  }
  const query = `SELECT * FROM rewards WHERE user_id = ?`;
  db.all(query, [userId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    const points = rows.reduce((sum, r) => sum + (r.points || 0), 0);
    res.json({ points, rewards: rows });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});

module.exports = app;
