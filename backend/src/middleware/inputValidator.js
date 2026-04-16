/**
 * Input Validation & Sanitization Middleware
 */
const { body, query, param, validationResult } = require('express-validator');

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array().map(e => ({ field: e.path, message: e.msg })),
    });
  }
  next();
}

// ─── Validation Chains ────────────────────────────────────────
const validators = {
  domain: [
    query('name')
      .trim()
      .notEmpty().withMessage('Domain name is required')
      .matches(/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/)
      .withMessage('Invalid domain format')
      .isLength({ max: 253 }).withMessage('Domain too long'),
    validate,
  ],

  ip: [
    query('address')
      .trim()
      .notEmpty().withMessage('IP address is required')
      .isIP().withMessage('Invalid IP address format'),
    validate,
  ],

  social: [
    query('username')
      .trim()
      .notEmpty().withMessage('Username is required')
      .matches(/^[a-zA-Z0-9_.\-@]{1,64}$/).withMessage('Invalid username format')
      .isLength({ min: 1, max: 64 }).withMessage('Username must be 1-64 characters'),
    validate,
  ],

  scan: [
    body('target')
      .trim()
      .notEmpty().withMessage('Scan target is required')
      .isLength({ max: 253 }).withMessage('Target too long'),
    body('type')
      .isIn(['domain', 'ip', 'url']).withMessage('Invalid scan type'),
    validate,
  ],

  threat: [
    query('target')
      .trim()
      .notEmpty().withMessage('Target is required')
      .isLength({ max: 500 }).withMessage('Target too long'),
    validate,
  ],

  riskScore: [
    body('domainAge').optional().isInt({ min: 0 }),
    body('subdomainCount').optional().isInt({ min: 0 }),
    body('vtMalicious').optional().isInt({ min: 0 }),
    body('asnRisk').optional().isFloat({ min: 0, max: 100 }),
    body('usernameAnomaly').optional().isBoolean(),
    body('linkSpam').optional().isBoolean(),
    validate,
  ],

  register: [
    body('email').isEmail().withMessage('Valid email required').normalizeEmail(),
    body('password')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/[A-Z]/).withMessage('Password must contain uppercase letter')
      .matches(/[0-9]/).withMessage('Password must contain number'),
    body('name').trim().isLength({ min: 2, max: 80 }).withMessage('Name must be 2-80 characters'),
    body('role').optional().isIn(['Admin', 'Analyst', 'Viewer']).withMessage('Invalid role'),
    validate,
  ],

  login: [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty().withMessage('Password required'),
    validate,
  ],
};

module.exports = { validators, validate };
