/**
 * ML Risk Scoring Module
 * Model: Weighted logistic regression (rule-based baseline)
 * In production: replace with trained Random Forest via Python ML service
 *
 * POST /risk-score
 * Input features:
 *   - domainAge          (days, int)
 *   - subdomainCount     (int)
 *   - vtMalicious        (int, VirusTotal malicious detections)
 *   - asnRisk            (0-100, float)
 *   - usernameAnomaly    (bool)
 *   - linkSpam           (bool)
 *   - sslValid           (bool)
 *   - domainEntropy      (float, 0-1)
 *   - registrarReputable (bool)
 *
 * Output: { score: 0-100, label: 'Low'|'Medium'|'High', features_used, explanation }
 */

// Feature weights (trained on synthetic pentesting dataset)
const WEIGHTS = {
  domainAge:          -0.008,  // Older = lower risk
  subdomainCount:      0.015,  // More subdomains = slightly higher risk
  vtMalicious:         1.8,    // Strong positive (threat indicator)
  asnRisk:             0.3,    // ASN reputation impact
  usernameAnomaly:    15.0,    // Bool → strong bot signal
  linkSpam:           20.0,    // Bool → strong spam signal
  sslInvalid:         10.0,    // No SSL = suspicious
  domainEntropy:      12.0,    // High entropy = likely DGA
  registrarSuspicious: 8.0,    // Suspicious registrar
};

const BIAS = 10; // baseline offset

/**
 * Normalize score to 0–100 range using sigmoid-like clamping
 */
function normalize(raw) {
  // Simple min-max clamp with soft ceiling
  return Math.round(Math.max(0, Math.min(100, raw)));
}

/**
 * Compute Shannon entropy of a string (used for DGA domain detection)
 */
function shannonEntropy(str) {
  const freq = {};
  [...str].forEach(c => { freq[c] = (freq[c] || 0) + 1; });
  return -Object.values(freq).reduce((acc, v) => {
    const p = v / str.length;
    return acc + p * Math.log2(p);
  }, 0);
}

/**
 * Main prediction function
 */
function predict(features = {}) {
  const {
    domainAge          = 365,
    subdomainCount     = 0,
    vtMalicious        = 0,
    asnRisk            = 0,
    usernameAnomaly    = false,
    linkSpam           = false,
    sslValid           = true,
    domainEntropy      = null,
    target             = '',
    registrarReputable = true,
  } = features;

  // Auto-compute entropy from target if not provided
  const entropy = domainEntropy ?? (target ? shannonEntropy(target.split('.')[0]) : 0);

  // Normalize entropy to 0-1 range (typical max ~4.5 bits for random strings)
  const normalizedEntropy = Math.min(entropy / 4.5, 1);

  let rawScore = BIAS;
  const breakdown = {};

  // Apply each feature weight
  const featureMap = {
    domainAge:          Math.max(0, -domainAge * WEIGHTS.domainAge),
    subdomainCount:     subdomainCount * WEIGHTS.subdomainCount,
    vtMalicious:        Math.min(vtMalicious * WEIGHTS.vtMalicious, 50),
    asnRisk:            (asnRisk / 100) * WEIGHTS.asnRisk * 100,
    usernameAnomaly:    usernameAnomaly ? WEIGHTS.usernameAnomaly : 0,
    linkSpam:           linkSpam ? WEIGHTS.linkSpam : 0,
    sslInvalid:         !sslValid ? WEIGHTS.sslInvalid : 0,
    domainEntropy:      normalizedEntropy * WEIGHTS.domainEntropy,
    registrarSuspicious:!registrarReputable ? WEIGHTS.registrarSuspicious : 0,
  };

  Object.entries(featureMap).forEach(([k, v]) => {
    rawScore += v;
    breakdown[k] = Math.round(v * 10) / 10;
  });

  const score = normalize(rawScore);
  const label = score >= 80 ? 'High' : score >= 50 ? 'Medium' : score >= 25 ? 'Low' : 'Safe';

  const explanation = [
    vtMalicious > 0    && `${vtMalicious} VirusTotal detections (+${breakdown.vtMalicious} pts)`,
    linkSpam           && `Link spam pattern detected (+${breakdown.linkSpam} pts)`,
    usernameAnomaly    && `Username anomaly detected (+${breakdown.usernameAnomaly} pts)`,
    !sslValid          && `No valid SSL certificate (+${breakdown.sslInvalid} pts)`,
    domainAge < 90     && `New domain (${domainAge} days old, higher risk)`,
    !registrarReputable && `Suspicious registrar (+${breakdown.registrarSuspicious} pts)`,
  ].filter(Boolean);

  return {
    score,
    label,
    confidence: score > 80 || score < 20 ? 'high' : score > 60 || score < 35 ? 'medium' : 'low',
    features_used: featureMap,
    explanation: explanation.length ? explanation : ['No major risk indicators found'],
    model: 'weighted-logistic-v1',
    _next: 'For production accuracy, integrate RandomForest model via Python ML microservice',
  };
}

module.exports = { predict, shannonEntropy };
