const xss = require('xss');

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

module.exports = { sanitizeInput, validate };
