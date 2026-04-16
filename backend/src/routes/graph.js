/**
 * Network Graph Route
 * GET /network-graph?domain=example.com
 */
const router = require('express').Router();
const { query, validationResult } = require('express-validator');

router.get('/',
  query('domain').trim().notEmpty().isLength({ max: 253 }),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Validation failed' });
    next();
  },
  async (req, res, next) => {
    try {
      const { domain } = req.query;
      // Build graph nodes and edges (real impl would pull from scan DB)
      const nodes = [
        { id: 'root',    label: domain,             type: 'domain',    risk: 25 },
        { id: 'www',     label: `www.${domain}`,    type: 'subdomain', risk: 10 },
        { id: 'api',     label: `api.${domain}`,    type: 'subdomain', risk: 15 },
        { id: 'mail',    label: `mail.${domain}`,   type: 'subdomain', risk: 20 },
        { id: 'ip1',     label: '93.184.216.34',    type: 'ip',        risk: 15 },
        { id: 'asn1',    label: 'AS15133 EdgeCast', type: 'asn',       risk: 5  },
      ];
      const edges = [
        { source: 'root', target: 'www'  },
        { source: 'root', target: 'api'  },
        { source: 'root', target: 'mail' },
        { source: 'root', target: 'ip1'  },
        { source: 'ip1',  target: 'asn1' },
      ];
      res.json({ success: true, domain, nodes, edges, timestamp: new Date().toISOString() });
    } catch (err) { next(err); }
  }
);

module.exports = router;
