/**
 * Social Media OSINT Service (Public Data Only)
 * Checks username existence using public profile pages
 * NO login, NO scraping private data, NO authentication bypass
 */
const https = require('https');

// Known public platforms to probe
const PLATFORMS = [
  { name: 'GitHub',     url: 'https://github.com/{username}',           method: 'HEAD' },
  { name: 'Twitter/X',  url: 'https://x.com/{username}',                method: 'HEAD' },
  { name: 'Instagram',  url: 'https://www.instagram.com/{username}/',   method: 'HEAD' },
  { name: 'LinkedIn',   url: 'https://www.linkedin.com/in/{username}/', method: 'HEAD' },
  { name: 'Reddit',     url: 'https://www.reddit.com/user/{username}/', method: 'HEAD' },
  { name: 'TikTok',     url: 'https://www.tiktok.com/@{username}',      method: 'HEAD' },
];

function headRequest(url) {
  return new Promise((resolve) => {
    const parsed = new URL(url);
    const opts = { hostname: parsed.hostname, path: parsed.pathname + parsed.search, method: 'HEAD',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CyberScope-OSINT/1.0; +https://cyberscope.io/bot)' },
      timeout: 8000 };
    const req = https.request(opts, resp => resolve({ status: resp.statusCode }));
    req.on('error', () => resolve({ status: 0 }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0 }); });
    req.end();
  });
}

// Rule-based bot pattern detection
function detectBotPatterns(username) {
  const patterns = {
    randomUsername:     /^[a-z]{2,4}\d{4,}$/.test(username),
    numericHeavy:       /\d{5,}/.test(username),
    repeatingChars:     /(.)\1{3,}/.test(username),
    suspiciousKeywords: /bot|spam|click|free|win|crypto|giveaway/i.test(username),
    tooShort:           username.length < 3,
    tooLong:            username.length > 30,
  };
  const botScore = Object.values(patterns).filter(Boolean).length;
  return { patterns, botScore, isLikelyBot: botScore >= 2 };
}

function extractDomains(links) {
  const domainRegex = /https?:\/\/([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})/g;
  const domains = new Set();
  links.forEach(link => {
    let m;
    while ((m = domainRegex.exec(link)) !== null) {
      const d = m[1].toLowerCase();
      if (!['twitter.com','x.com','github.com','instagram.com','linkedin.com'].includes(d)) {
        domains.add(d);
      }
    }
  });
  return [...domains];
}

async function analyzeUsername(username) {
  // Check platforms in parallel with timeout
  const checks = await Promise.all(
    PLATFORMS.map(async (platform) => {
      const url = platform.url.replace('{username}', encodeURIComponent(username));
      const { status } = await headRequest(url);
      return { platform: platform.name, url, found: [200, 301, 302].includes(status), status };
    })
  );

  const botAnalysis = detectBotPatterns(username);

  // Calculate risk
  let risk = 0;
  if (botAnalysis.isLikelyBot) risk += 50;
  if (botAnalysis.patterns.suspiciousKeywords) risk += 20;
  if (botAnalysis.patterns.randomUsername) risk += 15;
  if (checks.filter(c => c.found).length === 0) risk += 10;
  risk = Math.min(100, risk);

  return {
    username,
    platformResults: checks,
    foundOn: checks.filter(c => c.found).map(c => c.platform),
    botAnalysis,
    extractedDomains: extractDomains([]),  // Would extract from actual bio
    riskScore: risk,
    _note: 'Only public profile endpoints are probed. No private data accessed.'
  };
}

module.exports = { analyzeUsername, detectBotPatterns, extractDomains };
