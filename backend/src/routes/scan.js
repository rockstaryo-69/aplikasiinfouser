/**
 * Controlled Scan Routes (Legal Use Only)
 * POST /scan  — Queue async scan job
 * GET  /scan/:jobId — Check job status
 *
 * IMPORTANT: Scan targets must be explicitly authorized by the user.
 * All scans are queued, rate-limited, and sandboxed.
 */
const router = require('express').Router();
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const { requireMinRole } = require('../middleware/auth');
const { activityLogger, logger } = require('../middleware/logger');

// Very strict rate limit for scans
const scanLimiter = rateLimit({
  windowMs: 60000,
  max: parseInt(process.env.SCAN_RATE_LIMIT_PER_MINUTE) || 5,
  message: { error: 'Scan rate limit exceeded. Max 5 scans per minute.' },
});

// In-memory job store (replace with BullMQ + Redis in production)
const jobs = new Map();
let jobCounter = 1;

const scanValidator = [
  body('target').trim().notEmpty().isLength({ max: 253 }),
  body('type').isIn(['domain', 'ip', 'url']),
  body('authorized').equals('true').withMessage('You must confirm you are authorized to scan this target'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    next();
  }
];

// Block private/internal IP ranges
function isPrivateTarget(target) {
  return /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|localhost)/i.test(target);
}

// POST /scan
router.post('/',
  requireMinRole('Analyst'),
  scanLimiter,
  scanValidator,
  activityLogger('SCAN_QUEUED'),
  async (req, res, next) => {
    try {
      const { target, type, ports = 'top-100', timeout = 10000 } = req.body;

      if (isPrivateTarget(target)) {
        return res.status(400).json({ error: 'Cannot scan private/internal network targets' });
      }

      const jobId = `job_${Date.now()}_${jobCounter++}`;
      const job = {
        id: jobId,
        target, type,
        status: 'queued',
        createdAt: new Date().toISOString(),
        user: req.user.email,
        result: null,
        error: null,
      };
      jobs.set(jobId, job);

      logger.info(`Scan queued: ${type}://${target} by ${req.user.email} [${jobId}]`);

      // Simulate async execution (replace with BullMQ worker in production)
      setTimeout(async () => {
        try {
          job.status = 'running';
          await new Promise(r => setTimeout(r, 2000 + Math.random() * 3000));
          job.status = 'done';
          job.result = {
            target, type,
            openPorts: [22, 80, 443].filter(() => Math.random() > 0.3),
            services: { 22: 'SSH/OpenSSH 8.2', 80: 'HTTP/nginx', 443: 'HTTPS/nginx' },
            os: type === 'ip' ? 'Linux 5.x (Ubuntu 22)' : null,
            completedAt: new Date().toISOString(),
          };
        } catch (e) {
          job.status = 'failed';
          job.error = e.message;
        }
      }, 100);

      res.status(202).json({ jobId, status: 'queued', message: 'Scan job queued successfully', target, type });
    } catch (err) { next(err); }
  }
);

// GET /scan/:jobId
router.get('/:jobId', requireMinRole('Analyst'), (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  // Users can only see their own jobs (unless admin)
  if (req.user.role !== 'Admin' && job.user !== req.user.email) {
    return res.status(403).json({ error: 'Access denied to this job' });
  }
  res.json({ success: true, job });
});

// GET /scan (list recent jobs for current user)
router.get('/', requireMinRole('Analyst'), (req, res) => {
  const userJobs = [...jobs.values()]
    .filter(j => req.user.role === 'Admin' || j.user === req.user.email)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 20);
  res.json({ success: true, jobs: userJobs });
});

module.exports = router;
