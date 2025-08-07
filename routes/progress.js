const express = require('express');
const Joi = require('joi');
const db = require('../db');
const { validate, sanitizeInput } = require('../middleware/validation');

const router = express.Router();

const progressSchema = Joi.object({
  user_id: Joi.number().integer().required(),
  weekly: Joi.array().items(Joi.number()).optional(),
  monthly: Joi.array().items(Joi.number()).optional()
});

router.post('/', validate(progressSchema), (req, res) => {
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

router.get('/', (req, res) => {
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

module.exports = router;
