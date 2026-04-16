/**
 * IP Intelligence Service
 * Integrates: ip-api.com (free, no key), Reverse DNS
 */
const http  = require('http');
const dns   = require('dns').promises;

async function geolocate(ip) {
  return new Promise((resolve, reject) => {
    const url = `http://ip-api.com/json/${ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,as,query`;
    http.get(url, { headers: { 'User-Agent': 'CyberScope-OSINT/1.0' } }, (resp) => {
      let data = '';
      resp.on('data', c => data += c);
      resp.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('Geo parse error')); }
      });
    }).on('error', reject);
  });
}

async function reverseDNS(ip) {
  try {
    const hostnames = await dns.reverse(ip);
    return { hostnames, found: true };
  } catch {
    return { hostnames: [], found: false };
  }
}

function detectHostingType(isp = '', org = '') {
  const combined = (isp + ' ' + org).toLowerCase();
  if (/amazon|aws/.test(combined)) return 'Amazon Web Services';
  if (/google|gcp/.test(combined)) return 'Google Cloud';
  if (/microsoft|azure/.test(combined)) return 'Microsoft Azure';
  if (/cloudflare/.test(combined)) return 'Cloudflare';
  if (/digitalocean/.test(combined)) return 'DigitalOcean';
  if (/vultr/.test(combined)) return 'Vultr';
  if (/linode|akamai/.test(combined)) return 'Linode/Akamai';
  if (/tor|exit|anonymi|bulletproof/.test(combined)) return 'Tor / Bulletproof Hosting';
  if (/ovh/.test(combined)) return 'OVH';
  return 'Unknown / Generic ISP';
}

async function fullAnalysis(ip) {
  const [geo, rdns] = await Promise.all([geolocate(ip), reverseDNS(ip)]);
  return {
    ip,
    geo: {
      country:    geo.country,
      countryCode: geo.countryCode,
      region:     geo.regionName,
      city:       geo.city,
      lat:        geo.lat,
      lon:        geo.lon,
    },
    asn:        geo.as,
    isp:        geo.isp,
    org:        geo.org,
    reverseDns: rdns.hostnames,
    hosting:    detectHostingType(geo.isp, geo.org),
    // Port scan would be performed by BullMQ worker in production
    _note: 'Port data requires authorized scan job. POST /scan with target & type=ip',
  };
}

module.exports = { geolocate, reverseDNS, fullAnalysis };
