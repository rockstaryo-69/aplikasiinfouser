/**
 * Social Media OSINT Routes
 * GET /osint/social?username=target_user
 */
const router = require('express').Router();
const rateLimit = require('express-rate-limit');
const { validators } = require('../middleware/inputValidator');
const { requireMinRole } = require('../middleware/auth');
const { activityLogger } = require('../middleware/logger');
const socialService = require('../services/socialService');

const scanLimiter = rateLimit({ windowMs: 60000, max: 10 });

// GET /osint/social?username=
router.get('/social',
  requireMinRole('Analyst'),
  scanLimiter,
  validators.social,
  activityLogger('SOCIAL_OSINT'),
  async (req, res, next) => {
    try {
      const { username } = req.query;
      const data = await socialService.analyzeUsername(username);
      res.json({ success: true, target: username, data, timestamp: new Date().toISOString() });
    } catch (err) { next(err); }
  }
);

module.exports = router;
