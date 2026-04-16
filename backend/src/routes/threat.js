/**
 * Threat Intelligence Routes
 * GET /threat-check?target=domain.com
 */
const router = require('express').Router();
const rateLimit = require('express-rate-limit');
const { validators } = require('../middleware/inputValidator');
const { activityLogger } = require('../middleware/logger');
const threatService = require('../services/threatService');

const scanLimiter = rateLimit({ windowMs: 60000, max: 20 });

// GET /threat-check?target=
router.get('/',
  scanLimiter,
  validators.threat,
  activityLogger('THREAT_CHECK'),
  async (req, res, next) => {
    try {
      const { target } = req.query;
      const data = await threatService.check(target);
      res.json({ success: true, target, data, timestamp: new Date().toISOString() });
    } catch (err) { next(err); }
  }
);

module.exports = router;
