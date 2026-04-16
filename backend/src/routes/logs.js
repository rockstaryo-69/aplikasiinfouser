/**
 * Activity & Audit Logs Routes
 * GET /logs/activity  — API activity logs
 * GET /logs/audit     — Immutable audit trail
 */
const router = require('express').Router();
const { requireMinRole, requireRole } = require('../middleware/auth');

// Mock log store (replace with DB query in production)
const activityLogs = [
  { id: 1, time: '2026-04-16T15:47:02Z', level: 'info',    action: 'DOMAIN_SCAN', user: 'analyst@cyberscope.io', ip: '10.0.0.5', resource: 'example.com' },
  { id: 2, time: '2026-04-16T15:45:18Z', level: 'warn',    action: 'RATE_LIMIT',  user: 'system',               ip: '0.0.0.0',  resource: 'API Gateway' },
  { id: 3, time: '2026-04-16T15:43:55Z', level: 'success', action: 'LOGIN',       user: 'admin@cyberscope.io',  ip: '10.0.0.1', resource: 'Auth' },
  { id: 4, time: '2026-04-16T15:41:30Z', level: 'error',   action: 'API_TIMEOUT', user: 'system',               ip: '0.0.0.0',  resource: 'VirusTotal' },
  { id: 5, time: '2026-04-16T15:38:10Z', level: 'info',    action: 'IP_SCAN',     user: 'analyst@cyberscope.io', ip: '10.0.0.5', resource: '45.33.32.156' },
];

const auditLogs = [
  { id: 1, time: '2026-04-16T15:47:22Z', actor: 'admin@cyberscope.io',   action: 'USER_CREATED',   resource: 'viewer@cyberscope.io', ip: '10.0.0.1', status: 'success' },
  { id: 2, time: '2026-04-16T15:43:55Z', actor: 'admin@cyberscope.io',   action: 'LOGIN',           resource: 'Auth',                 ip: '10.0.0.1', status: 'success' },
  { id: 3, time: '2026-04-16T15:40:00Z', actor: 'analyst@cyberscope.io', action: 'SCAN_EXECUTED',   resource: 'malware-c2.xyz',       ip: '10.0.0.5', status: 'success' },
  { id: 4, time: '2026-04-16T15:30:10Z', actor: 'unknown',               action: 'LOGIN_FAILED',    resource: 'Auth',                 ip: '203.0.113.5', status: 'failure' },
];

// GET /logs/activity
router.get('/activity', requireMinRole('Analyst'), (req, res) => {
  const { level, limit = 50 } = req.query;
  let logs = activityLogs;
  if (level) logs = logs.filter(l => l.level === level);
  res.json({ success: true, logs: logs.slice(0, parseInt(limit)), total: activityLogs.length });
});

// GET /logs/audit
router.get('/audit', requireMinRole('Analyst'), (req, res) => {
  const { limit = 50 } = req.query;
  res.json({ success: true, logs: auditLogs.slice(0, parseInt(limit)), total: auditLogs.length });
});

// GET /logs/stats
router.get('/stats', requireMinRole('Analyst'), (req, res) => {
  const counts = activityLogs.reduce((acc, l) => {
    acc[l.level] = (acc[l.level] || 0) + 1;
    return acc;
  }, {});
  res.json({ success: true, counts, total: activityLogs.length });
});

module.exports = router;
