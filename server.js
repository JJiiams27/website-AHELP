const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const https = require('https');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const Joi = require('joi');
const xss = require('xss');

const app = express();
const db = new sqlite3.Database('users.db');
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'improved-website-v14')));
app.use(csrf({ cookie: true }));
app.use((req, res, next) => {
  res.cookie('XSRF-TOKEN', req.csrfToken(), {
    httpOnly: false,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production'
  });
  next();
});

function sanitizeInput(input) {
  if (typeof input === 'string') {
    return xss(input);
  }
  if (typeof input === 'object' && input !== null) {
    const sanitized = {};
    for (const key in input) {
      sanitized[key] = sanitizeInput(input[key]);
    }
    return sanitized;
  }
  return input;
}

function validate(schema) {
  return (req, res, next) => {
    const sanitized = sanitizeInput(req.body);
    const { error, value } = schema.validate(sanitized);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }
    req.body = value;
    next();
  };
}

const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  name: Joi.string().allow('')
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

const assessmentSchema = Joi.object({
  user_id: Joi.number().integer().required(),
  data: Joi.object().required()
});

const progressSchema = Joi.object({
  user_id: Joi.number().integer().required(),
  weekly: Joi.array().items(Joi.number()).optional(),
  monthly: Joi.array().items(Joi.number()).optional()
});

const challengeSchema = Joi.object({
  user_id: Joi.number().integer().required(),
  title: Joi.string().required(),
  description: Joi.string().allow('').optional(),
  progress: Joi.number().integer().min(0).optional(),
  goal: Joi.number().integer().min(0).optional()
});

const rewardSchema = Joi.object({
  user_id: Joi.number().integer().required(),
  title: Joi.string().required(),
  points: Joi.number().integer().required()
});

const updateUserSchema = Joi.object({
  name: Joi.string().allow('', null),
  is_admin: Joi.number().integer().valid(0, 1).optional()
});

const challengeUpdateSchema = Joi.object({
  title: Joi.string().optional(),
  description: Joi.string().allow('').optional(),
  progress: Joi.number().integer().min(0).optional(),
  goal: Joi.number().integer().min(0).optional(),
  user_id: Joi.number().integer().optional()
});

const rewardInventorySchema = Joi.object({
  title: Joi.string().required(),
  points: Joi.number().integer().required(),
  quantity: Joi.number().integer().optional()
});

const rewardInventoryUpdateSchema = Joi.object({
  title: Joi.string().optional(),
  points: Joi.number().integer().optional(),
  quantity: Joi.number().integer().optional()
});

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/login', (req, res) => {
  res.render('login');
});

// Ensure Users table exists and contains admin flag
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

const createInventory = `CREATE TABLE IF NOT EXISTS reward_inventory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  points INTEGER,
  quantity INTEGER
)`;
db.run(createInventory);

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = req.cookies.token || (authHeader && authHeader.split(' ')[1]);
  if (!token) {
    return res.status(401).json({ error: 'Missing token' });
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  authenticateToken(req, res, () => {
    if (!req.user.is_admin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  });
}

// Register endpoint
app.post('/api/auth/register', validate(registerSchema), (req, res) => {
  const { email, password, name } = req.body;
  const hashed = bcrypt.hashSync(password, 10);
  const stmt = `INSERT INTO users (email, name, password, is_admin) VALUES (?, ?, ?, 0)`;
  db.run(stmt, [email, name || '', hashed], function (err) {
    if (err) {
      if (err.code === 'SQLITE_CONSTRAINT') {
        return res.status(400).json({ error: 'User already exists' });
      }
      return res.status(500).json({ error: 'Database error' });
    }
    const user = { id: this.lastID, email, name: name || '', is_admin: 0 };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000
    });
    res.json({ token, user });
  });
});

// Login endpoint
app.post('/api/auth/login', validate(loginSchema), (req, res) => {
  const { email, password } = req.body;
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
    const user = {
      id: row.id,
      email: row.email,
      name: row.name,
      is_admin: row.is_admin || 0,
    };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000
    });
    res.json({ token, user });
  });
});

// --- Assessments ---
app.post('/api/assessments', validate(assessmentSchema), (req, res) => {
  const { user_id, data } = req.body;
  const stmt = `INSERT INTO assessments (user_id, data) VALUES (?, ?)`;
  db.run(stmt, [user_id, JSON.stringify(data)], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ id: this.lastID });
  });
});

app.get('/api/assessments', (req, res) => {
  const userId = sanitizeInput(req.query.user_id);
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
app.post('/api/progress', validate(progressSchema), (req, res) => {
  const { user_id, weekly, monthly } = req.body;
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
  const userId = sanitizeInput(req.query.user_id);
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
app.post('/api/challenges', validate(challengeSchema), (req, res) => {
  const { user_id, title, description, progress, goal } = req.body;
  const stmt = `INSERT INTO challenges (user_id, title, description, progress, goal) VALUES (?, ?, ?, ?, ?)`;
  db.run(stmt, [user_id, title, description || '', progress || 0, goal || 0], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ id: this.lastID });
  });
});

app.get('/api/challenges', (req, res) => {
  const userId = sanitizeInput(req.query.user_id);
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
app.post('/api/rewards', validate(rewardSchema), (req, res) => {
  const { user_id, title, points } = req.body;
  const stmt = `INSERT INTO rewards (user_id, title, points) VALUES (?, ?, ?)`;
  db.run(stmt, [user_id, title, points], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ id: this.lastID });
  });
});

app.get('/api/rewards', (req, res) => {
  const userId = sanitizeInput(req.query.user_id);
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

// --- Admin: Users ---
app.get('/api/admin/users', requireAdmin, (req, res) => {
  db.all(`SELECT id, email, name, is_admin FROM users`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.put('/api/admin/users/:id', requireAdmin, validate(updateUserSchema), (req, res) => {
  const { name, is_admin } = req.body;
  const stmt = `UPDATE users SET name = COALESCE(?, name), is_admin = COALESCE(?, is_admin) WHERE id = ?`;
  db.run(
    stmt,
    [name, typeof is_admin === 'number' ? is_admin : null, req.params.id],
    function (err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({ updated: this.changes });
    }
  );
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  db.run(`DELETE FROM users WHERE id = ?`, [req.params.id], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ deleted: this.changes });
  });
});

// --- Admin: Challenges ---
app.get('/api/admin/challenges', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM challenges`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.post('/api/admin/challenges', requireAdmin, validate(challengeSchema), (req, res) => {
  const { user_id, title, description, progress, goal } = req.body;
  const stmt =
    `INSERT INTO challenges (user_id, title, description, progress, goal) VALUES (?, ?, ?, ?, ?)`;
  db.run(
    stmt,
    [user_id, title, description || '', progress || 0, goal || 0],
    function (err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({ id: this.lastID });
    }
  );
});

app.put('/api/admin/challenges/:id', requireAdmin, validate(challengeUpdateSchema), (req, res) => {
  const { title, description, progress, goal } = req.body;
  const stmt =
    `UPDATE challenges SET title = COALESCE(?, title), description = COALESCE(?, description), progress = COALESCE(?, progress), goal = COALESCE(?, goal) WHERE id = ?`;
  db.run(
    stmt,
    [title, description, progress, goal, req.params.id],
    function (err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({ updated: this.changes });
    }
  );
});

app.delete('/api/admin/challenges/:id', requireAdmin, (req, res) => {
  db.run(`DELETE FROM challenges WHERE id = ?`, [req.params.id], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ deleted: this.changes });
  });
});

// --- Admin: Reward inventory ---
app.get('/api/admin/reward-inventory', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM reward_inventory`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.post('/api/admin/reward-inventory', requireAdmin, validate(rewardInventorySchema), (req, res) => {
  const { title, points, quantity } = req.body;
  const stmt =
    `INSERT INTO reward_inventory (title, points, quantity) VALUES (?, ?, ?)`;
  db.run(stmt, [title, points, quantity || 0], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ id: this.lastID });
  });
});

app.put('/api/admin/reward-inventory/:id', requireAdmin, validate(rewardInventoryUpdateSchema), (req, res) => {
  const { title, points, quantity } = req.body;
  const stmt =
    `UPDATE reward_inventory SET title = COALESCE(?, title), points = COALESCE(?, points), quantity = COALESCE(?, quantity) WHERE id = ?`;
  db.run(stmt, [title, points, quantity, req.params.id], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ updated: this.changes });
  });
});

app.delete('/api/admin/reward-inventory/:id', requireAdmin, (req, res) => {
  db.run(
    `DELETE FROM reward_inventory WHERE id = ?`,
    [req.params.id],
    function (err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({ deleted: this.changes });
    }
  );
});

const PORT = process.env.PORT || 3000;
if (process.env.SSL_KEY && process.env.SSL_CERT) {
  const httpsOptions = {
    key: fs.readFileSync(process.env.SSL_KEY),
    cert: fs.readFileSync(process.env.SSL_CERT)
  };
  https.createServer(httpsOptions, app).listen(PORT, () => {
    console.log(`HTTPS server listening on port ${PORT}`);
  });
} else {
  app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });
}

module.exports = app;
