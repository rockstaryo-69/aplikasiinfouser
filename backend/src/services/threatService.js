/**
 * Threat Intelligence Service
 * Integrates: VirusTotal v3 API + AbuseIPDB
 * Requires: VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY in .env
 */
const https = require('https');

function httpsGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers }, (resp) => {
      let data = '';
      resp.on('data', chunk => data += chunk);
      resp.on('end', () => {
        try { resolve({ status: resp.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: resp.statusCode, body: data }); }
      });
    }).on('error', reject);
  });
}

async function virusTotalCheck(target) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey || apiKey === 'your_virustotal_api_key_here') {
    return { _mock: true, message: 'Configure VIRUSTOTAL_API_KEY in .env', malicious: 0, suspicious: 0, harmless: 80, undetected: 10 };
  }
  // Determine resource type
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(target);
  const endpoint = isIP
    ? `https://www.virustotal.com/api/v3/ip_addresses/${target}`
    : `https://www.virustotal.com/api/v3/domains/${target}`;

  const { status, body } = await httpsGet(endpoint, { 'x-apikey': apiKey });
  if (status !== 200) throw new Error(`VirusTotal API error: ${status}`);
  const stats = body?.data?.attributes?.last_analysis_stats || {};
  return {
    malicious:  stats.malicious  || 0,
    suspicious: stats.suspicious || 0,
    harmless:   stats.harmless   || 0,
    undetected: stats.undetected || 0,
    categories: body?.data?.attributes?.categories || {},
    lastAnalysis: body?.data?.attributes?.last_analysis_date,
  };
}

async function abuseIPDBCheck(target) {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey || apiKey === 'your_abuseipdb_api_key_here') {
    return { _mock: true, message: 'Configure ABUSEIPDB_API_KEY in .env', abuseScore: 0, totalReports: 0, lastReported: 'Never' };
  }
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(target);
  if (!isIP) return { abuseScore: null, note: 'AbuseIPDB only supports IP addresses' };

  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(target)}&maxAgeInDays=90`;
  const { status, body } = await httpsGet(url, { 'Key': apiKey, 'Accept': 'application/json' });
  if (status !== 200) throw new Error(`AbuseIPDB API error: ${status}`);
  const d = body?.data || {};
  return {
    abuseScore:   d.abuseConfidenceScore || 0,
    totalReports: d.totalReports || 0,
    lastReported: d.lastReportedAt || 'Never',
    isp:          d.isp,
    countryCode:  d.countryCode,
    categories:   d.reports?.map(r => r.categories).flat() || [],
  };
}

async function check(target) {
  const timeout = parseInt(process.env.SCAN_TIMEOUT_MS) || 30000;
  const withTimeout = (promise) => Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), timeout)),
  ]);

  const [vt, abuse] = await Promise.allSettled([
    withTimeout(virusTotalCheck(target)),
    withTimeout(abuseIPDBCheck(target)),
  ]);

  return {
    target,
    virusTotal: vt.status === 'fulfilled' ? vt.value : { error: vt.reason?.message },
    abuseIPDB:  abuse.status === 'fulfilled' ? abuse.value : { error: abuse.reason?.message },
  };
}

module.exports = { check, virusTotalCheck, abuseIPDBCheck };
