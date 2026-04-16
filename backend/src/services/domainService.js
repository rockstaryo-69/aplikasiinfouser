/**
 * Domain Intelligence Service
 * Integrates: WHOIS, DNS (native dns module), crt.sh, Passive DNS
 */
const dns = require('dns').promises;
const https = require('https');

async function whoisLookup(domain) {
  // In production: use 'whois-json' npm package or WHOIS API
  // Returning structured mock for now; replace with real WHOIS call
  return {
    registrar: 'Demo Registrar Inc.',
    created: '2020-01-15',
    expiry:  '2027-01-15',
    updated: '2024-11-01',
    status: 'clientTransferProhibited',
    nameServers: [`ns1.${domain}`, `ns2.${domain}`],
    organization: 'Demo Organization',
    country: 'US',
    _note: 'In production: call whois-json or WHOIS XML API'
  };
}

async function dnsLookup(domain) {
  const results = {};
  try { results.A    = (await dns.resolve4(domain)).map(r => r);               } catch { results.A    = []; }
  try { results.AAAA = (await dns.resolve6(domain)).map(r => r);               } catch { results.AAAA = []; }
  try { results.MX   = (await dns.resolveMx(domain)).map(r => `${r.priority} ${r.exchange}`); } catch { results.MX = []; }
  try { results.NS   = await dns.resolveNs(domain);                           } catch { results.NS   = []; }
  try { results.TXT  = (await dns.resolveTxt(domain)).map(r => r.join(''));   } catch { results.TXT  = []; }
  try { results.CNAME = await dns.resolveCname(domain);                       } catch { results.CNAME = []; }
  return results;
}

async function enumerateSubdomains(domain) {
  // Use crt.sh Certificate Transparency logs (no API key required)
  return new Promise((resolve) => {
    const url = `https://crt.sh/?q=%.${domain}&output=json`;
    https.get(url, { headers: { 'User-Agent': 'CyberScope-OSINT/1.0' } }, (resp) => {
      let data = '';
      resp.on('data', chunk => data += chunk);
      resp.on('end', () => {
        try {
          const entries = JSON.parse(data);
          const subdomains = [...new Set(
            entries.flatMap(e => e.name_value.split('\n'))
                   .filter(s => s.endsWith(`.${domain}`) || s === domain)
                   .map(s => s.toLowerCase().replace(/^\*\./, ''))
          )].sort();
          resolve({ subdomains, source: 'crt.sh (Certificate Transparency)', count: subdomains.length });
        } catch {
          resolve({ subdomains: [], source: 'crt.sh', error: 'Failed to parse CT logs', count: 0 });
        }
      });
    }).on('error', () => {
      resolve({ subdomains: [], source: 'crt.sh', error: 'Network error', count: 0 });
    });
  });
}

async function checkAvailability(domain) {
  try {
    const addresses = await dns.resolve4(domain);
    return { available: false, resolves: true, addresses };
  } catch {
    return { available: true, resolves: false, addresses: [] };
  }
}

async function reverseIPLookup(ip) {
  try {
    const hostnames = await dns.reverse(ip);
    return { ip, hostnames };
  } catch {
    return { ip, hostnames: [] };
  }
}

async function fullAnalysis(domain) {
  const [whois, dnsRecords, subdomains] = await Promise.all([
    whoisLookup(domain),
    dnsLookup(domain),
    enumerateSubdomains(domain),
  ]);

  // Compute a simple risk score based on available data
  let riskFactors = [];
  const suspiciousTLDs = ['xyz','top','click','loan','win','gq','tk','ml','cf','ga'];
  const tld = domain.split('.').pop().toLowerCase();
  if (suspiciousTLDs.includes(tld)) riskFactors.push({ factor: 'Suspicious TLD', weight: 30 });
  if (subdomains.count > 10) riskFactors.push({ factor: 'Many subdomains', weight: 10 });

  const riskScore = Math.min(100, riskFactors.reduce((acc, f) => acc + f.weight, 0));

  return { whois, dns: dnsRecords, subdomains, riskScore, riskFactors };
}

module.exports = { whoisLookup, dnsLookup, enumerateSubdomains, checkAvailability, reverseIPLookup, fullAnalysis };
