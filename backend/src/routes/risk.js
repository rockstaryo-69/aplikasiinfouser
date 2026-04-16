/**
 * Risk Scoring Route
 * POST /risk-score
 * Body: { domainAge, subdomainCount, vtMalicious, asnRisk, usernameAnomaly, linkSpam, ... }
 */
const router = require('express').Router();
const { validators } = require('../middleware/inputValidator');
const riskModel = require('../ml/riskModel');

// POST /risk-score
router.post('/', validators.riskScore, (req, res) => {
  const features = req.body;
  const result = riskModel.predict(features);
  res.json({ success: true, result });
});

module.exports = router;
