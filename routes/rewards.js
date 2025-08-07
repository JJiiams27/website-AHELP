const express = require('express');
const Joi = require('joi');
const db = require('../db');
const { validate, sanitizeInput } = require('../middleware/validation');

const router = express.Router();

const rewardSchema = Joi.object({
  user_id: Joi.number().integer().required(),
  title: Joi.string().required(),
  points: Joi.number().integer().required()
});

router.post('/', validate(rewardSchema), (req, res) => {
  const { user_id, title, points } = req.body;
  const stmt = `INSERT INTO rewards (user_id, title, points) VALUES (?, ?, ?)`;
  db.run(stmt, [user_id, title, points], function (err) {
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
  const query = `SELECT * FROM rewards WHERE user_id = ?`;
  db.all(query, [userId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    const points = rows.reduce((sum, r) => sum + (r.points || 0), 0);
    res.json({ points, rewards: rows });
  });
});

module.exports = router;
