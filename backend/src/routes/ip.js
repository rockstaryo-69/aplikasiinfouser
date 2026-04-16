/**
 * IP Intelligence Routes
 * GET /ip?address=8.8.8.8
 */
const router = require('express').Router();
const rateLimit = require('express-rate-limit');
const { validators } = require('../middleware/inputValidator');
const { requireMinRole } = require('../middleware/auth');
const { activityLogger } = require('../middleware/logger');
const ipService = require('../services/ipService');

const scanLimiter = rateLimit({ windowMs: 60000, max: 15 });

// GET /ip?address=
router.get('/',
  requireMinRole('Analyst'),
  scanLimiter,
  validators.ip,
  activityLogger('IP_SCAN'),
  async (req, res, next) => {
    try {
      const { address } = req.query;
      // Block private/loopback IPs
      if (/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1)/.test(address)) {
        return res.status(400).json({ error: 'Private/loopback IP addresses are not allowed' });
      }
      const data = await ipService.fullAnalysis(address);
      res.json({ success: true, target: address, data, timestamp: new Date().toISOString() });
    } catch (err) { next(err); }
  }
);

module.exports = router;
