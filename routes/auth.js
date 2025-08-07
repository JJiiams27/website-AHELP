const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const db = require('../db');
const { validate } = require('../middleware/validation');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  name: Joi.string().allow('')
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

router.post('/register', validate(registerSchema), (req, res) => {
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

router.post('/login', validate(loginSchema), (req, res) => {
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

module.exports = router;
