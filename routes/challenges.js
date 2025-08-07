const express = require('express');
const Joi = require('joi');
const db = require('../db');
const { validate, sanitizeInput } = require('../middleware/validation');

const router = express.Router();

const challengeSchema = Joi.object({
  user_id: Joi.number().integer().required(),
  title: Joi.string().required(),
  description: Joi.string().allow('').optional(),
  progress: Joi.number().integer().min(0).optional(),
  goal: Joi.number().integer().min(0).optional()
});

router.post('/', validate(challengeSchema), (req, res) => {
  const { user_id, title, description, progress, goal } = req.body;
  const stmt = `INSERT INTO challenges (user_id, title, description, progress, goal) VALUES (?, ?, ?, ?, ?)`;
  db.run(stmt, [user_id, title, description || '', progress || 0, goal || 0], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ id: this.lastID });
  });
});

router.get('/', (req, res) => {
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

module.exports = router;
