const express = require('express');
const Joi = require('joi');
const db = require('../db');
const { validate } = require('../middleware/validation');
const { requireAdmin } = require('../middleware/auth');

const router = express.Router();

const updateUserSchema = Joi.object({
  name: Joi.string().allow('', null),
  is_admin: Joi.number().integer().valid(0, 1).optional()
});

const challengeSchema = Joi.object({
  user_id: Joi.number().integer().required(),
  title: Joi.string().required(),
  description: Joi.string().allow('').optional(),
  progress: Joi.number().integer().min(0).optional(),
  goal: Joi.number().integer().min(0).optional()
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

router.get('/users', requireAdmin, (req, res) => {
  db.all(`SELECT id, email, name, is_admin FROM users`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

router.put('/users/:id', requireAdmin, validate(updateUserSchema), (req, res) => {
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

router.delete('/users/:id', requireAdmin, (req, res) => {
  db.run(`DELETE FROM users WHERE id = ?`, [req.params.id], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ deleted: this.changes });
  });
});

router.get('/challenges', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM challenges`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

router.post('/challenges', requireAdmin, validate(challengeSchema), (req, res) => {
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

router.put('/challenges/:id', requireAdmin, validate(challengeUpdateSchema), (req, res) => {
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

router.delete('/challenges/:id', requireAdmin, (req, res) => {
  db.run(`DELETE FROM challenges WHERE id = ?`, [req.params.id], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ deleted: this.changes });
  });
});

router.get('/reward-inventory', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM reward_inventory`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

router.post('/reward-inventory', requireAdmin, validate(rewardInventorySchema), (req, res) => {
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

router.put('/reward-inventory/:id', requireAdmin, validate(rewardInventoryUpdateSchema), (req, res) => {
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

router.delete('/reward-inventory/:id', requireAdmin, (req, res) => {
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

module.exports = router;
