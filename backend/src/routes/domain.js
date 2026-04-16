/**
 * Domain Intelligence Routes
 * GET  /domain?name=example.com          — Full domain analysis
 * GET  /domain/whois?name=example.com    — WHOIS only
 * GET  /domain/dns?name=example.com      — DNS records
 * GET  /domain/subdomains?name=example.com — Subdomain enumeration
 * GET  /domain/availability?name=...     — Availability check
 */
const router = require('express').Router();
const rateLimit = require('express-rate-limit');
const { validators } = require('../middleware/inputValidator');
const { requireMinRole } = require('../middleware/auth');
const { activityLogger } = require('../middleware/logger');
const domainService = require('../services/domainService');

// Stricter rate limit for domain scans
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: parseInt(process.env.SCAN_RATE_LIMIT_PER_MINUTE) || 10,
  message: { error: 'Scan rate limit exceeded. Max 10 domain scans per minute.' },
});

// GET /domain?name=
router.get('/',
  requireMinRole('Analyst'),
  scanLimiter,
  validators.domain,
  activityLogger('DOMAIN_SCAN'),
  async (req, res, next) => {
    try {
      const { name } = req.query;
      const result = await domainService.fullAnalysis(name);
      res.json({ success: true, target: name, data: result, timestamp: new Date().toISOString() });
    } catch (err) { next(err); }
  }
);

// GET /domain/whois?name=
router.get('/whois', requireMinRole('Analyst'), validators.domain, async (req, res, next) => {
  try {
    const data = await domainService.whoisLookup(req.query.name);
    res.json({ success: true, data });
  } catch (err) { next(err); }
});

// GET /domain/dns?name=
router.get('/dns', requireMinRole('Analyst'), validators.domain, async (req, res, next) => {
  try {
    const data = await domainService.dnsLookup(req.query.name);
    res.json({ success: true, data });
  } catch (err) { next(err); }
});

// GET /domain/subdomains?name=
router.get('/subdomains', requireMinRole('Analyst'), validators.domain, async (req, res, next) => {
  try {
    const data = await domainService.enumerateSubdomains(req.query.name);
    res.json({ success: true, data });
  } catch (err) { next(err); }
});

// GET /domain/availability?name=
router.get('/availability', requireMinRole('Analyst'), validators.domain, async (req, res, next) => {
  try {
    const data = await domainService.checkAvailability(req.query.name);
    res.json({ success: true, data });
  } catch (err) { next(err); }
});

module.exports = router;
