const express = require('express');
const Joi = require('joi');
const db = require('../db');
const { validate, sanitizeInput } = require('../middleware/validation');

const router = express.Router();

const assessmentSchema = Joi.object({
  user_id: Joi.number().integer().required(),
  data: Joi.object().required()
});

router.post('/', validate(assessmentSchema), (req, res) => {
  const { user_id, data } = req.body;
  const stmt = `INSERT INTO assessments (user_id, data) VALUES (?, ?)`;
  db.run(stmt, [user_id, JSON.stringify(data)], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ id: this.lastID });
  });
});

router.get('/', (req, res) => {
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

module.exports = router;
