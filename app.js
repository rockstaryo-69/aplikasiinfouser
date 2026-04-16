/* ============================================================
   CyberScope — OSINT Intelligence Platform
   Main Application (React CDN, no bundler)
   ============================================================ */
'use strict';

const { useState, useEffect, useRef, useCallback, createContext, useContext } = React;
const { createRoot } = ReactDOM;

// ─── Contexts ────────────────────────────────────────────────
const AppContext = createContext(null);

// ─── Mock Data ───────────────────────────────────────────────
const DEMO_USERS = [
  { id: 1, email: 'admin@cyberscope.io',   password: 'admin123',   name: 'Admin User',     role: 'Admin',   avatar: 'A' },
  { id: 2, email: 'analyst@cyberscope.io', password: 'analyst123', name: 'Sarah Chen',     role: 'Analyst', avatar: 'S' },
  { id: 3, email: 'viewer@cyberscope.io',  password: 'viewer123',  name: 'John Viewer',    role: 'Viewer',  avatar: 'J' },
];

const MOCK_SCAN_HISTORY = [
  { id: 1, type: 'domain', target: 'example.com',       risk: 22,  label: 'Low',      time: '2 min ago',   status: 'done' },
  { id: 2, type: 'ip',     target: '192.168.1.100',      risk: 67,  label: 'Medium',   time: '15 min ago',  status: 'done' },
  { id: 3, type: 'social', target: '@suspicious_user99', risk: 88,  label: 'High',     time: '1 hr ago',    status: 'done' },
  { id: 4, type: 'threat', target: 'malware-c2.xyz',     risk: 95,  label: 'Critical', time: '2 hr ago',    status: 'done' },
  { id: 5, type: 'domain', target: 'google.com',         risk: 5,   label: 'Low',      time: '3 hr ago',    status: 'done' },
];

const MOCK_LOGS = [
  { id: 1, time: '15:47:02', level: 'info',    msg: 'Domain lookup completed: example.com',           user: 'analyst@cyberscope.io', ip: '10.0.0.5' },
  { id: 2, time: '15:45:18', level: 'warn',    msg: 'Rate limit threshold reached for IP 203.0.113.5', user: 'system',               ip: '0.0.0.0' },
  { id: 3, time: '15:43:55', level: 'success', msg: 'User login: admin@cyberscope.io',                user: 'admin@cyberscope.io',   ip: '10.0.0.1' },
  { id: 4, time: '15:41:30', level: 'error',   msg: 'Threat API timeout: VirusTotal unreachable',     user: 'system',               ip: '0.0.0.0' },
  { id: 5, time: '15:38:10', level: 'info',    msg: 'IP intelligence scan: 45.33.32.156',             user: 'analyst@cyberscope.io', ip: '10.0.0.5' },
  { id: 6, time: '15:35:44', level: 'warn',    msg: 'Suspicious username pattern detected: bot_xyz9',  user: 'system',               ip: '0.0.0.0' },
  { id: 7, time: '15:30:12', level: 'info',    msg: 'Social OSINT completed: @cryptoking99',           user: 'analyst@cyberscope.io', ip: '10.0.0.5' },
  { id: 8, time: '15:28:01', level: 'error',   msg: 'Scan queue overflow: 50 jobs pending',           user: 'system',               ip: '0.0.0.0' },
  { id: 9, time: '15:25:33', level: 'success', msg: 'PDF report exported: scan_2847.pdf',             user: 'admin@cyberscope.io',   ip: '10.0.0.1' },
  { id:10, time: '15:20:05', level: 'info',    msg: 'New user registered: viewer@cyberscope.io',      user: 'admin@cyberscope.io',   ip: '10.0.0.1' },
];

const MOCK_ALERTS = [
  { id: 1, title: 'High Risk Domain Detected',   desc: 'malware-c2.xyz flagged by 47 AV engines', severity: 'critical', time: '2m ago' },
  { id: 2, title: 'Suspicious Bot Activity',      desc: 'Username pattern matches bot fingerprint',  severity: 'high',     time: '18m ago' },
  { id: 3, title: 'Rate Limit Exceeded',          desc: 'API rate limit 90% consumed',               severity: 'medium',   time: '45m ago' },
  { id: 4, title: 'New Subdomain Discovered',     desc: 'admin.target.com — previously unknown',    severity: 'info',     time: '1h ago' },
];

const MOCK_USERS_TABLE = [
  { id: 1, name: 'Admin User',  email: 'admin@cyberscope.io',   role: 'Admin',   status: 'Active', scans: 142, lastSeen: 'Just now' },
  { id: 2, name: 'Sarah Chen',  email: 'analyst@cyberscope.io', role: 'Analyst', status: 'Active', scans: 89,  lastSeen: '5 min ago' },
  { id: 3, name: 'John Viewer', email: 'viewer@cyberscope.io',  role: 'Viewer',  status: 'Active', scans: 12,  lastSeen: '2 hr ago' },
  { id: 4, name: 'Marcus Lee',  email: 'mlee@cyberscope.io',    role: 'Analyst', status: 'Inactive', scans: 34, lastSeen: '3 days ago' },
];

// ─── Helpers ─────────────────────────────────────────────────
function riskColor(score) {
  if (score >= 80) return '#ef4444';
  if (score >= 50) return '#f59e0b';
  if (score >= 25) return '#06b6d4';
  return '#10b981';
}
function riskLabel(score) {
  if (score >= 80) return 'High';
  if (score >= 50) return 'Medium';
  if (score >= 25) return 'Low';
  return 'Safe';
}
function riskClass(score) {
  if (score >= 80) return 'risk-high';
  if (score >= 50) return 'risk-medium';
  return 'risk-low';
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function randomBetween(a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; }

// Simulated scan engine (deterministic for demo)
function simulateDomainScan(domain) {
  const suspicious = ['xyz','top','click','loan','win'].some(tld => domain.endsWith('.'+tld));
  const score = suspicious ? randomBetween(55, 85) : randomBetween(5, 35);
  const age = suspicious ? randomBetween(30, 180) : randomBetween(500, 3000);
  return {
    whois: {
      registrar: suspicious ? 'NameCheap, Inc.' : 'GoDaddy, LLC',
      created: new Date(Date.now() - age*24*3600*1000).toISOString().slice(0,10),
      expiry: new Date(Date.now() + 365*24*3600*1000).toISOString().slice(0,10),
      updated: new Date(Date.now() - 30*24*3600*1000).toISOString().slice(0,10),
      country: suspicious ? 'Panama' : 'United States',
      organization: suspicious ? 'Privacy Protection' : domain.split('.')[0].toUpperCase() + ' Inc.',
      status: 'clientTransferProhibited',
    },
    dns: {
      A: [suspicious ? '185.220.101.'+randomBetween(1,50) : '93.184.216.34'],
      AAAA: suspicious ? [] : ['2600:1f18:2148:bc01::1'],
      MX: ['10 mail.'+domain, '20 mail2.'+domain],
      NS: ['ns1.example-dns.com', 'ns2.example-dns.com'],
      TXT: suspicious ? [] : ['v=spf1 include:_spf.'+domain+' ~all', 'google-site-verification=abc123'],
    },
    subdomains: suspicious
      ? ['mail.'+domain, 'login.'+domain, 'secure.'+domain]
      : ['www.'+domain, 'mail.'+domain, 'api.'+domain, 'docs.'+domain, 'cdn.'+domain],
    availability: false,
    risk: score,
    domainAge: age,
    ipInfo: {
      ip: suspicious ? '185.220.101.'+randomBetween(1,50) : '93.184.216.34',
      asn: suspicious ? 'AS206264 Amarutu Technology Ltd' : 'AS15133 EdgeCast Networks',
      isp: suspicious ? 'Tor Exit Node' : 'Verizon Media CDN',
      country: suspicious ? 'Germany' : 'United States',
      city: suspicious ? 'Frankfurt' : 'Los Angeles',
      lat: suspicious ? 50.11 : 34.05,
      lon: suspicious ? 8.68 : -118.24,
    }
  };
}

function simulateKeywordSearch(keyword) {
  const tlds = ['.com', '.net', '.site', '.xyz', '.online', '.info', '.biz'];
  const realDomain = keyword.toLowerCase() + '.com';
  
  const fakes = [
    keyword + '-login.com',
    keyword + '-support.net',
    keyword.replace('o', '0') + '.com',
    keyword.replace('i', '1') + '.site',
    keyword.replace('l', 'I') + '.xyz',
    'secure-' + keyword + '.com',
    'www-' + keyword + '.com',
    keyword + 'official.net'
  ].filter(d => d && d !== realDomain && d !== keyword+'.com');

  const discovered = [];
  
  // Real Legitimate Domain
  discovered.push({
    domain: realDomain,
    status: 'Active',
    ip: `104.21.${randomBetween(10, 200)}.${randomBetween(1, 250)}`,
    risk: randomBetween(2, 10),
    type: 'Legitimate',
    indicators: ['Official SSL', 'Old Domain (10+ yrs)', 'Reputable ASN']
  });

  // Fake Domains
  const numFakes = randomBetween(2, 5);
  for(let i=0; i<numFakes; i++) {
    const fake = fakes[i % fakes.length];
    const isHighRisk = i % 2 === 0;
    
    discovered.push({
      domain: fake,
      status: 'Active',
      ip: `185.220.${randomBetween(10,100)}.${randomBetween(1,250)}`,
      risk: isHighRisk ? randomBetween(80, 95) : randomBetween(40, 65),
      type: isHighRisk ? 'Phishing / Fake' : 'Suspicious',
      indicators: ['Typosquatting', 'New Registration (< 30d)', 'No Extended Validation SSL']
    });
  }

  return {
    keyword,
    domains: discovered.sort((a,b) => b.risk - a.risk)
  };
}

function simulateIPScan(ip) {
  const isTor = ip.startsWith('185.220') || ip.startsWith('199.87');
  const score = isTor ? randomBetween(70,90) : randomBetween(5,30);
  return {
    ip,
    geo: { country: isTor ? 'Germany' : 'United States', city: isTor ? 'Frankfurt' : 'Chicago', region: isTor ? 'Hesse' : 'Illinois', lat: isTor ? 50.11 : 41.85, lon: isTor ? 8.68 : -87.65 },
    asn: isTor ? 'AS206264 Amarutu Technology Ltd' : 'AS8100 QuadraNet Enterprises',
    isp: isTor ? 'Tor Exit Node / VPN Provider' : 'QuadraNet LLC',
    reverseDns: isTor ? 'exit-node-'+randomBetween(1,99)+'.tor-exit.example' : 'server-'+randomBetween(10,99)+'.us-east.example.com',
    hosting: isTor ? 'Anonymous Hosting / Bulletproof' : 'Legitimate Cloud Provider',
    ports: [
      { port: 22,  service: 'SSH',   status: 'open',   version: 'OpenSSH 8.2p1' },
      { port: 80,  service: 'HTTP',  status: 'open',   version: 'nginx/1.18.0'  },
      { port: 443, service: 'HTTPS', status: 'open',   version: 'nginx/1.18.0'  },
      { port: 21,  service: 'FTP',   status: isTor ? 'open' : 'closed',  version: isTor ? 'vsftpd 3.0.3' : '' },
      { port: 3389,service: 'RDP',   status: 'filtered', version: ''           },
    ],
    flags: isTor ? ['Tor Exit Node', 'Known VPN', 'Data Center - Suspicious'] : ['Cloud Hosting'],
    risk: score,
  };
}

function simulateSocialScan(username) {
  const botPatterns = [/bot/i, /\d{4,}$/, /^[a-z]{1,5}\d{3,}$/, /spam/i, /click/i];
  const isBot = botPatterns.some(p => p.test(username));
  const score = isBot ? randomBetween(65, 90) : randomBetween(5, 35);
  return {
    username,
    platforms: ['Twitter/X', 'Instagram', 'GitHub'].map(p => ({
      platform: p,
      found: Math.random() > 0.3,
      url: `https://${p.toLowerCase().split('/')[0]}.com/${username}`,
      followers: randomBetween(10, 50000),
      following: randomBetween(10, 5000),
      posts: randomBetween(1, 5000),
      created: new Date(Date.now() - randomBetween(100, 2000)*24*3600*1000).toISOString().slice(0,10),
      bio: isBot ? 'Click here for free crypto! 🚀💰 DM us now!' : 'Security researcher | CTF player | OSINT enthusiast',
    })),
    links: isBot
      ? ['http://free-crypto-giveaway.xyz', 'http://t.me/cryptoscam', 'http://bitly.com/xxYYzz']
      : ['https://github.com/'+username, 'https://linkedin.com/in/'+username],
    extractedDomains: isBot ? ['free-crypto-giveaway.xyz', 'cryptoscam.top'] : ['github.com'],
    patterns: {
      usernameRandom: isBot,
      linkSpam: isBot,
      botIndicator: isBot,
      accountAge: isBot ? 'Very New (< 30 days)' : 'Established (> 1 year)',
    },
    risk: score,
  };
}

function simulateThreatScan(target) {
  const malicious = ['malware','phish','c2','ransomware','bad'].some(kw => target.includes(kw));
  const score = malicious ? randomBetween(75, 98) : randomBetween(0, 15);
  return {
    target,
    virusTotal: {
      malicious: malicious ? randomBetween(20, 47) : 0,
      suspicious: malicious ? randomBetween(2, 8) : 0,
      harmless: malicious ? randomBetween(5, 15) : randomBetween(60, 75),
      undetected: randomBetween(5, 20),
      lastAnalysis: new Date().toISOString().slice(0,10),
      categories: malicious ? ['malware', 'phishing', 'command-and-control'] : ['safe', 'legitimate'],
    },
    abuseIPDB: {
      abuseScore: malicious ? randomBetween(80, 100) : randomBetween(0, 5),
      totalReports: malicious ? randomBetween(50, 500) : randomBetween(0, 2),
      lastReported: malicious ? new Date(Date.now() - randomBetween(1,7)*24*3600*1000).toISOString().slice(0,10) : 'Never',
      categories: malicious ? ['Web Attack', 'Port Scan', 'Brute Force', 'Phishing'] : [],
    },
    flags: malicious
      ? [
          { type: 'Phishing', desc: 'Matches known phishing kit fingerprint', severity: 'critical' },
          { type: 'Malware Distribution', desc: 'Serving malicious payloads', severity: 'high' },
          { type: 'C2 Communication', desc: 'Communicates with known botnet C2', severity: 'critical' },
        ]
      : [],
    risk: score,
  };
}

// ─── Risk Circle ─────────────────────────────────────────────
function RiskCircle({ score }) {
  const r = 40; const circ = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score));
  const offset = circ - (pct / 100) * circ;
  const col = riskColor(score);
  return React.createElement('div', { className: 'risk-circle' },
    React.createElement('svg', { width: 100, height: 100, viewBox: '0 0 100 100' },
      React.createElement('circle', { cx: 50, cy: 50, r, fill: 'none', stroke: 'rgba(255,255,255,0.05)', strokeWidth: 8 }),
      React.createElement('circle', { cx: 50, cy: 50, r, fill: 'none', stroke: col, strokeWidth: 8, strokeDasharray: circ, strokeDashoffset: offset, strokeLinecap: 'round', style: { transition: 'stroke-dashoffset 1s ease, stroke 0.5s' } }),
    ),
    React.createElement('div', { className: 'score-value', style: { color: col } }, pct),
    React.createElement('div', { className: 'score-label' }, 'RISK')
  );
}

// ─── Risk Badge ───────────────────────────────────────────────
function RiskBadge({ score }) {
  return React.createElement('span', { className: `risk-badge ${riskClass(score)}` }, riskLabel(score));
}

// ─── Toast System ────────────────────────────────────────────
let _setToasts = null;
function showToast(msg, type = 'info') {
  if (_setToasts) {
    const id = Date.now();
    _setToasts(prev => [...prev, { id, msg, type }]);
    setTimeout(() => _setToasts(prev => prev.filter(t => t.id !== id)), 4000);
  }
}

function ToastContainer() {
  const [toasts, setToasts] = useState([]);
  useEffect(() => { _setToasts = setToasts; }, []);
  const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
  return React.createElement('div', { className: 'toast-container' },
    toasts.map(t =>
      React.createElement('div', { key: t.id, className: `toast toast-${t.type}` },
        React.createElement('span', null, icons[t.type] || 'ℹ️'),
        React.createElement('span', null, t.msg)
      )
    )
  );
}

// ─── Spinner ─────────────────────────────────────────────────
function Spinner({ large }) {
  return React.createElement('div', { className: large ? 'spinner spinner-lg' : 'spinner' });
}

// ─── Empty State ──────────────────────────────────────────────
function EmptyState({ icon, title, desc }) {
  return React.createElement('div', { className: 'empty-state' },
    React.createElement('div', { className: 'empty-icon' }, icon),
    React.createElement('h3', null, title),
    React.createElement('p', null, desc)
  );
}

// ─── Login Page ───────────────────────────────────────────────
function LoginPage({ onLogin }) {
  const [email, setEmail] = useState('');
  const [pass, setPass] = useState('');
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState('');

  async function handleLogin(e) {
    e.preventDefault();
    setLoading(true); setErr('');
    await sleep(900);
    const user = DEMO_USERS.find(u => u.email === email && u.password === pass);
    setLoading(false);
    if (user) { onLogin(user); showToast(`Welcome back, ${user.name}!`, 'success'); }
    else setErr('Invalid credentials. Try a demo account below.');
  }

  function fillDemo(u) { setEmail(u.email); setPass(u.password); }

  return React.createElement('div', { className: 'login-page' },
    React.createElement('div', { className: 'login-bg-grid' }),
    React.createElement('div', { className: 'login-bg-glow' }),
    React.createElement('div', { className: 'login-card fade-in' },
      React.createElement('div', { className: 'login-logo' },
        React.createElement('div', { className: 'login-logo-icon' }, '🔭'),
        React.createElement('h1', null, 'CyberScope'),
        React.createElement('p', null, 'OSINT Intelligence Platform'),
      ),
      React.createElement('form', { className: 'login-form', onSubmit: handleLogin },
        React.createElement('div', { className: 'input-group' },
          React.createElement('label', { className: 'input-label' }, 'EMAIL ADDRESS'),
          React.createElement('input', { className: 'input-field', type: 'email', placeholder: 'analyst@cyberscope.io', value: email, onChange: e => setEmail(e.target.value), required: true })
        ),
        React.createElement('div', { className: 'input-group' },
          React.createElement('label', { className: 'input-label' }, 'PASSWORD'),
          React.createElement('input', { className: 'input-field', type: 'password', placeholder: '••••••••', value: pass, onChange: e => setPass(e.target.value), required: true })
        ),
        err && React.createElement('div', { className: 'alert alert-danger' }, '⚠️ ', err),
        React.createElement('button', { className: 'btn btn-primary', type: 'submit', disabled: loading, style: { width: '100%', justifyContent: 'center' } },
          loading ? React.createElement(Spinner) : null, loading ? 'Authenticating...' : '🔐 Sign In'
        )
      ),
      React.createElement('div', { className: 'disclaimer-box' },
        '⚖️ Legal Use Only — This platform is for authorized penetration testing, educational, and defensive security purposes ONLY.'
      ),
      React.createElement('div', { className: 'demo-accounts' },
        React.createElement('h4', null, '🔑 Demo Accounts'),
        DEMO_USERS.map(u =>
          React.createElement('div', { key: u.id, className: 'demo-account-item', onClick: () => fillDemo(u) },
            React.createElement('div', null,
              React.createElement('span', null, u.name, ' '),
              React.createElement('span', { className: `role-pill role-${u.role.toLowerCase()}` }, u.role)
            ),
            React.createElement('span', { className: 'creds' }, u.password)
          )
        )
      )
    )
  );
}

// ─── Sidebar ──────────────────────────────────────────────────
const NAV_ITEMS = [
  { id: 'dashboard',    icon: '📊', label: 'Dashboard',       section: 'OVERVIEW' },
  { id: 'social',       icon: '👤', label: 'Social OSINT',    section: 'INTELLIGENCE' },
  { id: 'domain',       icon: '🌐', label: 'Domain Intel',    section: null },
  { id: 'ip',           icon: '🖥️', label: 'IP Intelligence', section: null },
  { id: 'threat',       icon: '🦠', label: 'Threat Intel',    section: null },
  { id: 'network',      icon: '🕸️', label: 'Network Graph',   section: null },
  { id: 'siem',         icon: '📡', label: 'SIEM Monitor',    section: 'SECURITY', badge: '3' },
  { id: 'users',        icon: '👥', label: 'User Management', section: null },
  { id: 'auditlog',     icon: '📋', label: 'Audit Log',       section: null },
];

function Sidebar({ activePage, setPage, user, onLogout }) {
  const sections = [];
  let currentSection = null;
  NAV_ITEMS.forEach(item => {
    if (item.section) { currentSection = item.section; sections.push({ type: 'section', label: item.section }); }
    sections.push({ type: 'item', ...item });
  });

  const canAccess = (id) => {
    if (user.role === 'Admin') return true;
    if (user.role === 'Analyst') return ['dashboard','social','domain','ip','threat','network','siem','auditlog'].includes(id);
    return ['dashboard','threat','network','auditlog'].includes(id);
  };

  return React.createElement('div', { className: 'sidebar' },
    React.createElement('div', { className: 'sidebar-logo' },
      React.createElement('div', { className: 'logo-icon' }, '🔭'),
      React.createElement('div', null,
        React.createElement('div', { className: 'logo-text' }, 'CyberScope'),
        React.createElement('div', { className: 'logo-sub' }, 'OSINT PLATFORM v1.0')
      )
    ),
    React.createElement('nav', { className: 'sidebar-nav' },
      sections.map((s, i) => {
        if (s.type === 'section') return React.createElement('div', { key: 'sec-'+i, className: 'nav-section-label' }, s.label);
        const disabled = !canAccess(s.id);
        return React.createElement('div', {
          key: s.id,
          className: `nav-item ${activePage === s.id ? 'active' : ''} ${disabled ? '' : ''}`,
          onClick: disabled ? () => showToast('Access denied for your role', 'error') : () => setPage(s.id),
          style: disabled ? { opacity: 0.4 } : {},
          'data-tooltip': disabled ? `Requires ${s.id === 'users' ? 'Admin' : 'Analyst'} role` : null
        },
          React.createElement('span', { className: 'nav-icon' }, s.icon),
          React.createElement('span', null, s.label),
          s.badge && React.createElement('span', { className: 'nav-badge' }, s.badge)
        );
      })
    ),
    React.createElement('div', { className: 'sidebar-footer' },
      React.createElement('div', { className: 'user-card', onClick: onLogout },
        React.createElement('div', { className: 'user-avatar' }, user.avatar),
        React.createElement('div', { className: 'user-info' },
          React.createElement('div', { className: 'user-name' }, user.name),
          React.createElement('div', { className: 'user-role' }, user.role.toUpperCase())
        ),
        React.createElement('span', { style: { marginLeft: 'auto', color: 'var(--text-muted)', fontSize: 14 } }, '↗')
      )
    )
  );
}

// ─── Topbar ───────────────────────────────────────────────────
const PAGE_TITLES = {
  dashboard: ['📊 Dashboard', 'Overview & Live Stats'],
  social:    ['👤 Social OSINT', 'Public Profile Analysis'],
  domain:    ['🌐 Domain Intelligence', 'WHOIS, DNS & Subdomain Analysis'],
  ip:        ['🖥️ IP Intelligence', 'Geolocation, ASN & Port Mapping'],
  threat:    ['🦠 Threat Intel', 'VirusTotal & AbuseIPDB Reputation'],
  network:   ['🕸️ Network Graph', 'Interactive Attack Surface Visualization'],
  siem:      ['📡 SIEM Dashboard', 'Log Monitoring & Alert System'],
  users:     ['👥 User Management', 'RBAC & Team Collaboration'],
  auditlog:  ['📋 Audit Log', 'Activity Trail & Compliance'],
};

function Topbar({ page, user, scanCount }) {
  const [t, sub] = PAGE_TITLES[page] || ['CyberScope', ''];
  return React.createElement('div', { className: 'topbar' },
    React.createElement('div', { className: 'topbar-left' },
      React.createElement('div', null,
        React.createElement('div', { className: 'topbar-title' }, t),
        React.createElement('div', { className: 'topbar-breadcrumb' }, sub)
      )
    ),
    React.createElement('div', { className: 'topbar-right' },
      React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-muted)' } },
        React.createElement('div', { className: 'status-dot' }),
        React.createElement('span', null, 'Systems Operational')
      ),
      React.createElement('div', { style: { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: '6px 12px', fontSize: 12, color: 'var(--text-secondary)' } },
        '🔍 ', scanCount, ' scans today'
      ),
      React.createElement('div', { style: { background: 'rgba(37,99,235,0.1)', border: '1px solid rgba(37,99,235,0.3)', borderRadius: 8, padding: '6px 12px', fontSize: 12, color: '#93c5fd' } },
        user.role
      )
    )
  );
}

// ─── Dashboard Page ───────────────────────────────────────────
function DashboardPage() {
  const stats = [
    { label: 'Total Scans', value: '1,247', change: '+23% this week', up: true, icon: '🔍', color: 'blue' },
    { label: 'Threats Found', value: '38',  change: '+5 today',        up: false,icon: '🦠', color: 'cyan' },
    { label: 'High Risk Targets', value: '12', change: '3 unresolved',up: false,icon: '⚠️', color: 'purple' },
    { label: 'Active Users', value: '4',    change: '2 online now',    up: true, icon: '👥', color: 'green' },
  ];

  const chartData = [42, 65, 38, 72, 55, 88, 61, 44, 79, 53, 66, 91, 74, 48];
  const maxVal = Math.max(...chartData);

  return React.createElement('div', { className: 'page-content fade-in' },
    React.createElement('div', { className: 'grid-4', style: { marginBottom: 20 } },
      stats.map(s => React.createElement('div', { key: s.label, className: `stat-card ${s.color}` },
        React.createElement('div', { className: `stat-icon ${s.color}` }, s.icon),
        React.createElement('div', { className: 'stat-value' }, s.value),
        React.createElement('div', { className: 'stat-label' }, s.label),
        React.createElement('div', { className: `stat-change ${s.up ? 'up' : 'down'}` }, s.up ? '↑' : '↓', ' ', s.change)
      ))
    ),

    React.createElement('div', { className: 'dashboard-grid' },
      React.createElement('div', { className: 'card' },
        React.createElement('div', { className: 'card-header' },
          React.createElement('div', { className: 'card-title' }, '📈 Scan Activity (Last 14 Days)'),
          React.createElement('div', { style: { fontSize: 12, color: 'var(--text-muted)' } }, 'Daily scan volume')
        ),
        React.createElement('div', { className: 'mini-chart', style: { height: 80, alignItems: 'flex-end', gap: 4 } },
          chartData.map((v, i) =>
            React.createElement('div', {
              key: i,
              className: 'mini-bar',
              style: { height: `${(v / maxVal) * 100}%`, flex: 1 },
              title: `${v} scans`
            })
          )
        ),
        React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-muted)', marginTop: 8 } },
          React.createElement('span', null, '14 days ago'),
          React.createElement('span', null, 'Today')
        )
      ),

      React.createElement('div', { className: 'card' },
        React.createElement('div', { className: 'card-header' },
          React.createElement('div', { className: 'card-title' }, '🚨 Recent Alerts')
        ),
        MOCK_ALERTS.map(a =>
          React.createElement('div', { key: a.id, style: { display: 'flex', gap: 10, padding: '8px 0', borderBottom: '1px solid var(--border)', alignItems: 'flex-start' } },
            React.createElement('span', { style: { fontSize: 16, paddingTop: 2 } },
              a.severity === 'critical' ? '🔴' : a.severity === 'high' ? '🟠' : a.severity === 'medium' ? '🟡' : 'ℹ️'
            ),
            React.createElement('div', { style: { flex: 1 } },
              React.createElement('div', { style: { fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' } }, a.title),
              React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)', marginTop: 2 } }, a.desc),
            ),
            React.createElement('span', { style: { fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' } }, a.time)
          )
        )
      )
    ),

    React.createElement('div', { style: { marginTop: 20 } },
      React.createElement('div', { className: 'card' },
        React.createElement('div', { className: 'card-header' },
          React.createElement('div', { className: 'card-title' }, '🕐 Recent Scans')
        ),
        React.createElement('div', { className: 'table-wrap' },
          React.createElement('table', null,
            React.createElement('thead', null,
              React.createElement('tr', null,
                ['Type', 'Target', 'Risk Score', 'Status', 'Time'].map(h =>
                  React.createElement('th', { key: h }, h)
                )
              )
            ),
            React.createElement('tbody', null,
              MOCK_SCAN_HISTORY.map(s =>
                React.createElement('tr', { key: s.id },
                  React.createElement('td', null, React.createElement('span', { className: 'tag' }, s.type.toUpperCase())),
                  React.createElement('td', null, React.createElement('span', { className: 'mono' }, s.target)),
                  React.createElement('td', null,
                    React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 8 } },
                      React.createElement('div', { className: 'progress-bar-wrap', style: { width: 60 } },
                        React.createElement('div', { className: 'progress-bar', style: { width: s.risk+'%', background: riskColor(s.risk) } })
                      ),
                      React.createElement('span', { style: { fontSize: 12, color: riskColor(s.risk) } }, s.risk)
                    )
                  ),
                  React.createElement('td', null, React.createElement(RiskBadge, { score: s.risk })),
                  React.createElement('td', null, s.time)
                )
              )
            )
          )
        )
      )
    )
  );
}

// ─── Social OSINT Page ────────────────────────────────────────
function SocialOSINTPage() {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [steps, setSteps] = useState([]);
  const STEPS = ['Searching username across platforms', 'Extracting public profile data', 'Analyzing link patterns', 'Scanning for bot indicators', 'Computing risk score'];

  async function runScan() {
    if (!input.trim()) return;
    setLoading(true); setResult(null); setSteps([]);
    for (let i = 0; i < STEPS.length; i++) {
      setSteps(prev => [...prev, { label: STEPS[i], done: false, active: true }]);
      await sleep(600);
      setSteps(prev => prev.map((s, si) => si === i ? { ...s, done: true, active: false } : s));
    }
    const r = simulateSocialScan(input.trim());
    setResult(r);
    setLoading(false);
    showToast(`Social OSINT complete — Risk: ${r.risk}/100`, r.risk > 60 ? 'warning' : 'success');
  }

  const platforms = result?.platforms?.filter(p => p.found) || [];

  return React.createElement('div', { className: 'page-content fade-in' },
    React.createElement('div', { className: 'card', style: { marginBottom: 16 } },
      React.createElement('div', { className: 'card-title', style: { marginBottom: 14 } }, '👤 Social Media OSINT Analysis'),
      React.createElement('div', { className: 'alert alert-info' }, 'ℹ️ Only analyzes publicly accessible social media data. No login or private data access.'),
      React.createElement('div', { className: 'input-with-btn', style: { marginTop: 12 } },
        React.createElement('input', { className: 'input-field', placeholder: 'Enter username (e.g., cryptoking99, bot_abc123, john_doe)', value: input, onChange: e => setInput(e.target.value), onKeyDown: e => e.key === 'Enter' && runScan() }),
        React.createElement('button', { className: 'btn btn-cyan', onClick: runScan, disabled: loading || !input.trim() },
          loading ? React.createElement(Spinner) : '🔍', loading ? ' Scanning...' : ' Analyze'
        )
      ),
      loading && React.createElement('div', { className: 'scan-progress', style: { marginTop: 14 } },
        steps.map((s, i) =>
          React.createElement('div', { key: i, className: 'scan-step' },
            React.createElement('span', { className: 'scan-step-icon' }, s.done ? '✅' : s.active ? '⏳' : '⬜'),
            React.createElement('span', { className: s.done ? 'step-done' : s.active ? 'step-active' : 'step-pending' }, STEPS[i])
          )
        )
      )
    ),

    result && React.createElement('div', { className: 'result-section' },
      React.createElement('div', { className: 'grid-2', style: { marginBottom: 16 } },
        React.createElement('div', { className: 'card glow-cyan' },
          React.createElement('div', { className: 'card-title', style: { marginBottom: 14 } }, '📊 Risk Assessment'),
          React.createElement('div', { className: 'risk-circle-container' },
            React.createElement(RiskCircle, { score: result.risk }),
            React.createElement('div', null,
              React.createElement('div', { style: { fontSize: 22, fontWeight: 800, color: riskColor(result.risk), marginBottom: 6 } }, riskLabel(result.risk), ' Risk'),
              React.createElement('div', { style: { fontSize: 13, color: 'var(--text-secondary)', marginBottom: 10 } }, 'Based on pattern analysis across platforms'),
              React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 4 } },
                result.patterns.botIndicator && React.createElement('span', { className: 'tag tag-red' }, '🤖 Bot Pattern'),
                result.patterns.linkSpam && React.createElement('span', { className: 'tag tag-red' }, '🔗 Link Spam'),
                result.patterns.usernameRandom && React.createElement('span', { className: 'tag tag-yellow' }, '⚠️ Random Username'),
                !result.patterns.botIndicator && React.createElement('span', { className: 'tag tag-green' }, '✅ Organic User'),
              )
            )
          )
        ),
        React.createElement('div', { className: 'card' },
          React.createElement('div', { className: 'card-title', style: { marginBottom: 12 } }, '🔍 Pattern Analysis'),
          React.createElement('div', { className: 'info-list' },
            [
              ['Username Pattern', result.patterns.usernameRandom ? '⚠️ Anomalous / Random' : '✅ Normal'],
              ['Bot Indicator', result.patterns.botIndicator ? '🤖 High Confidence Bot' : '✅ Unlikely Bot'],
              ['Link Behavior', result.patterns.linkSpam ? '🔗 Spammy / Repeated' : '✅ Organic'],
              ['Account Age', result.patterns.accountAge],
            ].map(([k,v]) =>
              React.createElement('div', { key: k, className: 'info-row' },
                React.createElement('span', { className: 'info-key' }, k),
                React.createElement('span', { className: 'info-val' }, v)
              )
            )
          )
        )
      ),

      platforms.length > 0 && React.createElement('div', { className: 'card', style: { marginBottom: 16 } },
        React.createElement('div', { className: 'card-title', style: { marginBottom: 12 } }, '📱 Platform Presence'),
        React.createElement('div', { className: 'table-wrap' },
          React.createElement('table', null,
            React.createElement('thead', null,
              React.createElement('tr', null,
                ['Platform', 'URL', 'Followers', 'Following', 'Posts', 'Created'].map(h => React.createElement('th', { key: h }, h))
              )
            ),
            React.createElement('tbody', null,
              result.platforms.map(p =>
                React.createElement('tr', { key: p.platform },
                  React.createElement('td', null, p.found ? React.createElement('span', { className: 'tag tag-green' }, '✅ '+p.platform) : React.createElement('span', { className: 'tag' }, '❌ '+p.platform)),
                  React.createElement('td', null, p.found ? React.createElement('a', { href: p.url, target: '_blank', style: { color: 'var(--accent-cyan)', fontSize: 12 } }, p.url) : '—'),
                  React.createElement('td', null, p.found ? p.followers.toLocaleString() : '—'),
                  React.createElement('td', null, p.found ? p.following.toLocaleString() : '—'),
                  React.createElement('td', null, p.found ? p.posts.toLocaleString() : '—'),
                  React.createElement('td', null, p.found ? p.created : '—')
                )
              )
            )
          )
        )
      ),

      result.links.length > 0 && React.createElement('div', { className: 'card', style: { marginBottom: 16 } },
        React.createElement('div', { className: 'card-title', style: { marginBottom: 12 } }, '🔗 Extracted Links & Domains'),
        result.links.map((link, i) =>
          React.createElement('div', { key: i, style: { display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', borderBottom: '1px solid var(--border)' } },
            React.createElement('span', { className: 'mono', style: { flex: 1, fontSize: 13 } }, link),
            result.patterns.linkSpam
              ? React.createElement('span', { className: 'tag tag-red' }, '⚠️ Suspicious')
              : React.createElement('span', { className: 'tag tag-green' }, '✅ Clean')
          )
        ),
        result.extractedDomains.length > 0 && React.createElement('div', { style: { marginTop: 12 } },
          React.createElement('div', { className: 'section-title' }, 'Extracted Domains'),
          React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 6 } },
            result.extractedDomains.map((d,i) =>
              React.createElement('span', { key: i, className: result.patterns.linkSpam ? 'tag tag-red' : 'tag tag-green' }, d)
            )
          )
        )
      )
    ),

    !result && !loading && React.createElement(EmptyState, { icon: '👤', title: 'No Analysis Yet', desc: 'Enter a username above to begin social media OSINT analysis' })
  );
}

// ─── Domain Intel Page ────────────────────────────────────────
function DomainIntelPage() {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [keywordResults, setKeywordResults] = useState(null);
  const [tab, setTab] = useState('whois');

  async function runScan() {
    if (!input.trim()) return;
    setLoading(true); setResult(null); setKeywordResults(null);
    await sleep(1800);
    
    // Auto-detect if it's a domain or keyword
    const val = input.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (val.includes('.')) {
      // Regular domain scan
      const r = simulateDomainScan(val);
      setResult(r);
      showToast(`Domain analysis complete — Risk: ${r.risk}/100`, r.risk > 60 ? 'warning' : 'success');
    } else {
      // Keyword phishing/typosquatting search
      const r = simulateKeywordSearch(val);
      setKeywordResults(r);
      const fakeCount = r.domains.filter(d => d.risk > 60).length;
      showToast(`Keyword search complete. Found ${fakeCount} potential fake websites.`, fakeCount > 0 ? 'error' : 'success');
    }
    setLoading(false);
  }

  return React.createElement('div', { className: 'page-content fade-in' },
    React.createElement('div', { className: 'card', style: { marginBottom: 16 } },
      React.createElement('div', { className: 'card-title', style: { marginBottom: 14 } }, '🌐 Domain & Website Intelligence'),
      React.createElement('div', { className: 'alert alert-info' }, 'ℹ️ Advanced mode: Enter a brand keyword (e.g. "paypal") to hunt for typosquatting & fake websites, or enter a full domain for detailed intel.'),
      React.createElement('div', { className: 'input-with-btn', style: { marginTop: 12 } },
        React.createElement('input', { className: 'input-field', placeholder: 'Enter domain (example.com) or brand keyword (paypal)', value: input, onChange: e => setInput(e.target.value), onKeyDown: e => e.key === 'Enter' && runScan() }),
        React.createElement('button', { className: 'btn btn-primary', onClick: runScan, disabled: loading || !input.trim() },
          loading ? React.createElement(Spinner) : '🌐', loading ? ' Analyzing...' : ' Analyze'
        )
      ),
      loading && React.createElement('div', { style: { textAlign: 'center', padding: 24, color: 'var(--text-muted)' } },
        React.createElement(Spinner, { large: true }),
        React.createElement('div', { style: { marginTop: 12 } }, input.includes('.') ? 'Performing WHOIS, DNS, and subdomain enumeration...' : 'Discovering typosquatting and fake domains...')
      )
    ),

    keywordResults && React.createElement('div', { className: 'result-section' },
      React.createElement('div', { className: 'card glow-cyan', style: { marginBottom: 16 } },
         React.createElement('div', { className: 'card-title', style: { marginBottom: 14 } }, `🕵️ Fake Website Detection for: "${keywordResults.keyword}"`),
         React.createElement('p', { style: { fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 } }, 'Found multiple registered domains that mimic your keyword. These may be used for phishing attacks.'),
         React.createElement('div', { className: 'table-wrap' },
           React.createElement('table', null,
             React.createElement('thead', null,
                React.createElement('tr', null,
                  React.createElement('th', null, 'Domain'),
                  React.createElement('th', null, 'Target IP'),
                  React.createElement('th', null, 'Risk Score'),
                  React.createElement('th', null, 'Indicators')
                )
             ),
             React.createElement('tbody', null,
               keywordResults.domains.map((d, i) =>
                 React.createElement('tr', { key: i },
                   React.createElement('td', null, 
                     React.createElement('div', { className: 'mono', style: { fontWeight: d.risk > 70 ? 'bold' : 'normal', color: d.risk > 70 ? 'var(--text-primary)' : 'var(--text-secondary)' } }, d.domain),
                     React.createElement('span', { className: d.risk > 70 ? 'tag tag-red' : d.risk > 40 ? 'tag tag-yellow' : 'tag tag-green', style: { marginTop: 4, display: 'inline-block' } }, d.type)
                   ),
                   React.createElement('td', { className: 'mono', style: { fontSize: 12 } }, d.ip),
                   React.createElement('td', null,
                     React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 6 } },
                       React.createElement('div', { className: 'progress-bar-wrap', style: { width: 50 } },
                         React.createElement('div', { className: 'progress-bar', style: { width: d.risk+'%', background: riskColor(d.risk) } })
                       ),
                       React.createElement('span', { style: { fontSize: 12, color: riskColor(d.risk) } }, d.risk)
                     )
                   ),
                   React.createElement('td', null,
                     React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: '4px' } },
                       d.indicators.map(ind => React.createElement('span', { key: ind, className: 'tag' }, ind))
                     )
                   )
                 )
               )
             )
           )
         )
      )
    ),

    result && React.createElement('div', { className: 'result-section' },
      React.createElement('div', { className: 'grid-3', style: { marginBottom: 16 } },
        React.createElement('div', { className: 'card glow-blue' },
          React.createElement('div', { className: 'card-title', style: { marginBottom: 12 } }, '🔴 Risk Score'),
          React.createElement(RiskCircle, { score: result.risk }),
          React.createElement('div', { style: { marginTop: 10, display: 'flex', flexWrap: 'wrap', gap: 4 } },
            result.risk > 60 && React.createElement('span', { className: 'tag tag-red' }, '⚠️ Suspicious Domain'),
            React.createElement('span', { className: `risk-badge ${riskClass(result.risk)}` }, riskLabel(result.risk)+' Risk')
          )
        ),
        React.createElement('div', { className: 'card' },
          React.createElement('div', { className: 'card-title', style: { marginBottom: 10 } }, '📋 Quick Info'),
          React.createElement('div', { className: 'info-list', style: { fontSize: 12 } },
            [
              ['Domain Age', result.domainAge + ' days'],
              ['Registrar', result.whois.registrar],
              ['Registrant Country', result.whois.country],
              ['Availability', 'Registered ✗'],
              ['Subdomains Found', result.subdomains.length],
              ['Primary IP', result.ipInfo.ip],
            ].map(([k,v]) =>
              React.createElement('div', { key: k, className: 'info-row' },
                React.createElement('span', { className: 'info-key' }, k),
                React.createElement('span', { className: 'info-val' }, v)
              )
            )
          )
        ),
        React.createElement('div', { className: 'card' },
          React.createElement('div', { className: 'card-title', style: { marginBottom: 10 } }, '🌍 IP / Hosting'),
          React.createElement('div', { className: 'info-list', style: { fontSize: 12 } },
            [
              ['IP Address', result.ipInfo.ip],
              ['ASN', result.ipInfo.asn],
              ['ISP', result.ipInfo.isp],
              ['Country', result.ipInfo.country],
              ['City', result.ipInfo.city],
            ].map(([k,v]) =>
              React.createElement('div', { key: k, className: 'info-row' },
                React.createElement('span', { className: 'info-key' }, k),
                React.createElement('span', { className: 'info-val mono', style: { fontSize: 12 } }, v)
              )
            )
          )
        )
      ),

      React.createElement('div', { className: 'card' },
        React.createElement('div', { className: 'tabs' },
          ['whois','dns','subdomains'].map(t =>
            React.createElement('button', { key: t, className: `tab-btn ${tab === t ? 'active' : ''}`, onClick: () => setTab(t) },
              t === 'whois' ? '📝 WHOIS' : t === 'dns' ? '🔄 DNS Records' : '🔍 Subdomains'
            )
          )
        ),

        tab === 'whois' && React.createElement('div', { className: 'info-list' },
          Object.entries(result.whois).map(([k, v]) =>
            React.createElement('div', { key: k, className: 'info-row' },
              React.createElement('span', { className: 'info-key', style: { textTransform: 'capitalize' } }, k),
              React.createElement('span', { className: 'info-val mono' }, String(v))
            )
          )
        ),

        tab === 'dns' && React.createElement('div', null,
          Object.entries(result.dns).map(([rtype, vals]) =>
            React.createElement('div', { key: rtype, style: { marginBottom: 14 } },
              React.createElement('div', { className: 'section-title' }, rtype, ' Records'),
              vals.length > 0
                ? vals.map((v, i) => React.createElement('div', { key: i, style: { padding: '6px 0', fontSize: 13, color: 'var(--text-secondary)' } }, React.createElement('span', { className: 'mono' }, v)))
                : React.createElement('span', { style: { fontSize: 12, color: 'var(--text-muted)' } }, 'No records')
            )
          )
        ),

        tab === 'subdomains' && React.createElement('div', null,
          React.createElement('div', { className: 'alert alert-info', style: { marginBottom: 14 } }, '🔍 Discovered via Certificate Transparency logs (crt.sh)'),
          result.subdomains.map((s, i) =>
            React.createElement('div', { key: i, className: 'threat-row' },
              React.createElement('span', { className: 'mono' }, s),
              React.createElement('span', { className: 'tag' }, 'CT Log')
            )
          )
        )
      )
    ),

    !result && !keywordResults && !loading && React.createElement(EmptyState, { icon: '🌐', title: 'No Scan Active', desc: 'Enter a domain or a brand keyword above to begin intelligence gathering.' })
  );
}

// ─── IP Intel Page ────────────────────────────────────────────
function IPIntelPage() {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function runScan() {
    if (!input.trim()) return;
    setLoading(true); setResult(null);
    await sleep(1500);
    const r = simulateIPScan(input.trim());
    setResult(r);
    setLoading(false);
    showToast(`IP intelligence complete — Risk: ${r.risk}/100`, r.risk > 60 ? 'warning' : 'success');
  }

  return React.createElement('div', { className: 'page-content fade-in' },
    React.createElement('div', { className: 'card', style: { marginBottom: 16 } },
      React.createElement('div', { className: 'card-title', style: { marginBottom: 14 } }, '🖥️ IP Address Intelligence'),
      React.createElement('div', { className: 'input-with-btn' },
        React.createElement('input', { className: 'input-field', placeholder: 'Enter IP address (e.g., 8.8.8.8, 185.220.101.22)', value: input, onChange: e => setInput(e.target.value), onKeyDown: e => e.key === 'Enter' && runScan() }),
        React.createElement('button', { className: 'btn btn-purple', onClick: runScan, disabled: loading || !input.trim() },
          loading ? React.createElement(Spinner) : '🖥️', loading ? ' Scanning...' : ' Analyze'
        )
      ),
      loading && React.createElement('div', { style: { textAlign: 'center', padding: 24, color: 'var(--text-muted)' } },
        React.createElement(Spinner, { large: true }),
        React.createElement('div', { style: { marginTop: 12 } }, 'Running geolocation, ASN lookup, reverse DNS, and port scanning...')
      )
    ),

    result && React.createElement('div', { className: 'result-section' },
      React.createElement('div', { className: 'grid-3', style: { marginBottom: 16 } },
        React.createElement('div', { className: 'card glow-blue' },
          React.createElement('div', { className: 'card-title', style: { marginBottom: 10 } }, '📊 Risk Score'),
          React.createElement(RiskCircle, { score: result.risk }),
          React.createElement('div', { style: { marginTop: 10 } },
            result.flags.map((f, i) =>
              React.createElement('span', { key: i, className: 'tag tag-red', style: { display: 'block', marginBottom: 4 } }, '⚠️ ', f)
            )
          )
        ),

        React.createElement('div', { className: 'card' },
          React.createElement('div', { className: 'card-title', style: { marginBottom: 10 } }, '🌍 Geolocation'),
          React.createElement('div', { className: 'geo-map-placeholder', style: { marginBottom: 12 } },
            React.createElement('div', { style: { textAlign: 'center' } },
              React.createElement('div', { style: { fontSize: 32, marginBottom: 8 } }, '📍'),
              React.createElement('div', { style: { fontSize: 14, fontWeight: 600 } }, result.geo.city, ', ', result.geo.country),
              React.createElement('div', { style: { fontSize: 12, color: 'var(--text-muted)', marginTop: 4 } }, 'Lat: ', result.geo.lat, ' Lon: ', result.geo.lon)
            )
          ),
          React.createElement('div', { className: 'info-list' },
            [
              ['Region', result.geo.region],
              ['ASN', result.asn],
              ['ISP', result.isp],
              ['Hosting', result.hosting],
            ].map(([k,v]) =>
              React.createElement('div', { key: k, className: 'info-row' },
                React.createElement('span', { className: 'info-key' }, k),
                React.createElement('span', { className: 'info-val', style: { fontSize: 12 } }, v)
              )
            )
          )
        ),

        React.createElement('div', { className: 'card' },
          React.createElement('div', { className: 'card-title', style: { marginBottom: 10 } }, '🔍 Identity'),
          React.createElement('div', { className: 'info-list' },
            [
              ['IP Address', result.ip],
              ['Reverse DNS', result.reverseDns],
              ['Risk Level', riskLabel(result.risk)],
            ].map(([k,v]) =>
              React.createElement('div', { key: k, className: 'info-row' },
                React.createElement('span', { className: 'info-key' }, k),
                React.createElement('span', { className: 'info-val mono', style: { fontSize: 12 } }, v)
              )
            )
          )
        )
      ),

      React.createElement('div', { className: 'card' },
        React.createElement('div', { className: 'card-title', style: { marginBottom: 14 } }, '🔌 Port Scan Results', React.createElement('span', { style: { fontSize: 11, color: 'var(--text-muted)', marginLeft: 8, fontWeight: 400 } }, '(Top ports — legal passive scan simulation)')),
        React.createElement('div', { className: 'table-wrap' },
          React.createElement('table', null,
            React.createElement('thead', null,
              React.createElement('tr', null,
                ['Port', 'Service', 'Status', 'Version'].map(h => React.createElement('th', { key: h }, h))
              )
            ),
            React.createElement('tbody', null,
              result.ports.map(p =>
                React.createElement('tr', { key: p.port },
                  React.createElement('td', null, React.createElement('span', { className: 'mono' }, p.port)),
                  React.createElement('td', null, p.service),
                  React.createElement('td', null, React.createElement('span', {
                    className: p.status === 'open' ? 'port-open' : p.status === 'filtered' ? 'port-filtered' : 'port-closed'
                  }, p.status === 'open' ? '● Open' : p.status === 'filtered' ? '◌ Filtered' : '○ Closed')),
                  React.createElement('td', null, React.createElement('span', { className: 'mono', style: { fontSize: 12 } }, p.version || '—'))
                )
              )
            )
          )
        )
      )
    ),

    !result && !loading && React.createElement(EmptyState, { icon: '🖥️', title: 'No IP Analyzed', desc: 'Enter an IP address to begin geolocation, ASN, and port analysis' })
  );
}

// ─── Threat Intel Page ────────────────────────────────────────
function ThreatIntelPage() {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function runScan() {
    if (!input.trim()) return;
    setLoading(true); setResult(null);
    await sleep(2000);
    const r = simulateThreatScan(input.trim());
    setResult(r);
    setLoading(false);
    showToast(r.risk > 70 ? '🚨 High threat detected!' : 'Threat check complete', r.risk > 70 ? 'error' : 'success');
  }

  const totalVT = result ? (result.virusTotal.malicious + result.virusTotal.suspicious + result.virusTotal.harmless + result.virusTotal.undetected) : 0;

  return React.createElement('div', { className: 'page-content fade-in' },
    React.createElement('div', { className: 'card', style: { marginBottom: 16 } },
      React.createElement('div', { className: 'card-title', style: { marginBottom: 14 } }, '🦠 Threat Intelligence Analysis'),
      React.createElement('div', { className: 'alert alert-warning', style: { marginBottom: 12 } },
        '⚠️ Reputation checks use VirusTotal & AbuseIPDB simulated data. In production, configure real API keys.'
      ),
      React.createElement('div', { className: 'input-with-btn' },
        React.createElement('input', { className: 'input-field', placeholder: 'Enter domain, IP, or URL (e.g., malware-c2.xyz, 185.220.101.1)', value: input, onChange: e => setInput(e.target.value), onKeyDown: e => e.key === 'Enter' && runScan() }),
        React.createElement('button', { className: 'btn btn-danger', onClick: runScan, disabled: loading || !input.trim() },
          loading ? React.createElement(Spinner) : '🦠', loading ? ' Checking...' : ' Check Threats'
        )
      )
    ),

    loading && React.createElement('div', { style: { textAlign: 'center', padding: 48 } },
      React.createElement(Spinner, { large: true }),
      React.createElement('div', { style: { marginTop: 16, color: 'var(--text-muted)' } }, 'Querying threat intelligence databases...')
    ),

    result && React.createElement('div', { className: 'result-section' },
      result.flags.length > 0 && React.createElement('div', { className: 'alert alert-danger', style: { fontSize: 15, fontWeight: 700 } },
        '🚨 THREAT DETECTED — This target has ', result.flags.length, ' active threat indicator(s)'
      ),

      React.createElement('div', { className: 'grid-2', style: { marginBottom: 16 } },
        React.createElement('div', { className: 'card glow-blue' },
          React.createElement('div', { className: 'card-title', style: { marginBottom: 14 } }, '🔴 Overall Risk Score'),
          React.createElement('div', { className: 'risk-circle-container' },
            React.createElement(RiskCircle, { score: result.risk }),
            React.createElement('div', null,
              React.createElement('div', { style: { fontSize: 20, fontWeight: 800, color: riskColor(result.risk), marginBottom: 6 } }, riskLabel(result.risk), ' Risk'),
              React.createElement('div', { style: { fontSize: 13, color: 'var(--text-secondary)' } }, result.virusTotal.malicious, ' AV engines flagged'),
              React.createElement('div', { style: { fontSize: 12, color: 'var(--text-muted)', marginTop: 4 } }, 'AbuseIPDB Score: ', result.abuseIPDB.abuseScore, '/100')
            )
          )
        ),

        React.createElement('div', { className: 'card' },
          React.createElement('div', { className: 'card-title', style: { marginBottom: 14 } }, '🛡️ VirusTotal Results'),
          React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 10 } },
            [
              ['Malicious',  result.virusTotal.malicious,  '#ef4444'],
              ['Suspicious', result.virusTotal.suspicious,  '#f59e0b'],
              ['Harmless',   result.virusTotal.harmless,   '#10b981'],
              ['Undetected', result.virusTotal.undetected, '#64748b'],
            ].map(([label, count, color]) =>
              React.createElement('div', { key: label },
                React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 } },
                  React.createElement('span', { style: { color } }, label),
                  React.createElement('span', { style: { color } }, count, '/', totalVT)
                ),
                React.createElement('div', { className: 'progress-bar-wrap' },
                  React.createElement('div', { className: 'progress-bar', style: { width: totalVT > 0 ? (count/totalVT*100)+'%' : '0%', background: color } })
                )
              )
            )
          ),
          React.createElement('div', { style: { marginTop: 12, fontSize: 11, color: 'var(--text-muted)' } },
            'Last analysis: ', result.virusTotal.lastAnalysis,
            React.createElement('br'),
            'Categories: ', result.virusTotal.categories.join(', ')
          )
        )
      ),

      React.createElement('div', { className: 'card', style: { marginBottom: 16 } },
        React.createElement('div', { className: 'card-title', style: { marginBottom: 14 } }, '🚫 AbuseIPDB Report'),
        React.createElement('div', { className: 'grid-3' },
          [
            ['Abuse Score', result.abuseIPDB.abuseScore + '/100'],
            ['Total Reports', result.abuseIPDB.totalReports],
            ['Last Reported', result.abuseIPDB.lastReported],
          ].map(([k,v]) =>
            React.createElement('div', { key: k, style: { textAlign: 'center', padding: 16, background: 'var(--bg-secondary)', borderRadius: 8, border: '1px solid var(--border)' } },
              React.createElement('div', { style: { fontSize: 24, fontWeight: 800, color: result.abuseIPDB.abuseScore > 50 ? 'var(--accent-red)' : 'var(--accent-green)', marginBottom: 4 } }, v),
              React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)' } }, k)
            )
          )
        ),
        result.abuseIPDB.categories.length > 0 && React.createElement('div', { style: { marginTop: 12 } },
          React.createElement('div', { className: 'section-title' }, 'Abuse Categories'),
          React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 6 } },
            result.abuseIPDB.categories.map((c,i) => React.createElement('span', { key: i, className: 'tag tag-red' }, c))
          )
        )
      ),

      result.flags.length > 0 && React.createElement('div', { className: 'card' },
        React.createElement('div', { className: 'card-title', style: { marginBottom: 14 } }, '🚩 Threat Flags'),
        result.flags.map((f,i) =>
          React.createElement('div', { key: i, className: 'threat-row' },
            React.createElement('div', null,
              React.createElement('div', { style: { fontSize: 13, fontWeight: 700, color: f.severity === 'critical' ? '#fca5a5' : '#fcd34d' } }, f.type),
              React.createElement('div', { style: { fontSize: 12, color: 'var(--text-muted)', marginTop: 3 } }, f.desc)
            ),
            React.createElement('span', { className: `risk-badge ${f.severity === 'critical' ? 'risk-critical' : 'risk-high'}` }, f.severity)
          )
        )
      )
    ),

    !result && !loading && React.createElement(EmptyState, { icon: '🦠', title: 'No Target Analyzed', desc: 'Enter a domain or IP to check against threat intelligence databases' })
  );
}

// ─── Network Graph Page ───────────────────────────────────────
function NetworkGraphPage() {
  const cyRef = useRef(null);
  const cyInstance = useRef(null);
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [graphCreated, setGraphCreated] = useState(false);
  const [selected, setSelected] = useState(null);

  function buildGraph(domain) {
    const elements = [];
    const d = domain || 'example.com';
    const ip1 = '93.184.'+randomBetween(200,250)+'.'+randomBetween(1,100);
    const ip2 = '185.220.'+randomBetween(100,120)+'.'+randomBetween(1,50);
    const asn1 = 'AS15133';
    const asn2 = 'AS206264';

    const nodes = [
      { id: 'root',    label: d,               type: 'domain',    risk: 30 },
      { id: 'sub1',    label: 'www.'+d,         type: 'subdomain', risk: 10 },
      { id: 'sub2',    label: 'api.'+d,         type: 'subdomain', risk: 15 },
      { id: 'sub3',    label: 'mail.'+d,        type: 'subdomain', risk: 20 },
      { id: 'sub4',    label: 'admin.'+d,       type: 'subdomain', risk: 65 },
      { id: 'ip1',     label: ip1,              type: 'ip',        risk: 25 },
      { id: 'ip2',     label: ip2,              type: 'ip',        risk: 72 },
      { id: 'asn1',    label: asn1+' (CDN)',    type: 'asn',       risk: 10 },
      { id: 'asn2',    label: asn2+' (VPS)',    type: 'asn',       risk: 68 },
      { id: 'domain2', label: 'related-site.net', type: 'domain', risk: 55 },
    ];

    const edges = [
      { source: 'root', target: 'sub1' }, { source: 'root', target: 'sub2' },
      { source: 'root', target: 'sub3' }, { source: 'root', target: 'sub4' },
      { source: 'root', target: 'ip1' },  { source: 'sub4', target: 'ip2' },
      { source: 'ip1',  target: 'asn1' }, { source: 'ip2',  target: 'asn2' },
      { source: 'sub2', target: 'ip1' },  { source: 'ip2',  target: 'domain2' },
    ];

    nodes.forEach(n => elements.push({ data: { id: n.id, label: n.label, type: n.type, risk: n.risk } }));
    edges.forEach((e,i) => elements.push({ data: { id: 'e'+i, source: e.source, target: e.target } }));
    return elements;
  }

  useEffect(() => {
    if (!graphCreated || !cyRef.current) return;
    if (cyInstance.current) { cyInstance.current.destroy(); cyInstance.current = null; }

    const elements = buildGraph(domain);
    const colorMap = { domain: '#2563eb', subdomain: '#06b6d4', ip: '#7c3aed', asn: '#10b981' };

    const cy = window.cytoscape({
      container: cyRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': ele => colorMap[ele.data('type')] || '#2563eb',
            'background-opacity': 0.9,
            'label': 'data(label)',
            'color': '#f1f5f9',
            'font-size': '10px',
            'font-family': 'JetBrains Mono, monospace',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'text-margin-y': 4,
            'border-width': ele => ele.data('risk') > 60 ? 3 : 1,
            'border-color': ele => ele.data('risk') > 60 ? '#ef4444' : 'rgba(255,255,255,0.2)',
            'width': ele => ele.data('type') === 'domain' && ele.data('id') === 'root' ? 50 : 36,
            'height': ele => ele.data('type') === 'domain' && ele.data('id') === 'root' ? 50 : 36,
          }
        },
        {
          selector: 'edge',
          style: {
            'line-color': 'rgba(100,116,139,0.6)',
            'width': 1.5,
            'curve-style': 'bezier',
            'target-arrow-shape': 'triangle',
            'target-arrow-color': 'rgba(100,116,139,0.6)',
            'arrow-scale': 0.8,
          }
        },
        {
          selector: ':selected',
          style: {
            'border-width': 3,
            'border-color': '#60a5fa',
            'box-shadow': '0 0 15px #2563eb',
          }
        }
      ],
      layout: { name: 'cose', animate: true, animationDuration: 800, randomize: false, nodeRepulsion: 8000, idealEdgeLength: 120 },
      wheelSensitivity: 0.3,
    });

    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      setSelected({ label: node.data('label'), type: node.data('type'), risk: node.data('risk'), id: node.data('id') });
    });

    cy.on('tap', evt => { if (evt.target === cy) setSelected(null); });
    cyInstance.current = cy;
  }, [graphCreated, domain]);

  async function handleBuild() {
    setLoading(true);
    await sleep(1000);
    setGraphCreated(true);
    setLoading(false);
    showToast('Network graph built successfully!', 'success');
  }

  const legendItems = [
    { color: '#2563eb', label: 'Domain' },
    { color: '#06b6d4', label: 'Subdomain' },
    { color: '#7c3aed', label: 'IP Address' },
    { color: '#10b981', label: 'ASN / Network' },
  ];

  return React.createElement('div', { className: 'page-content fade-in' },
    React.createElement('div', { className: 'card', style: { marginBottom: 16 } },
      React.createElement('div', { className: 'card-title', style: { marginBottom: 14 } }, '🕸️ Attack Surface Network Graph'),
      React.createElement('div', { className: 'input-with-btn' },
        React.createElement('input', { className: 'input-field', placeholder: 'Enter root domain (e.g., example.com)', value: domain, onChange: e => setDomain(e.target.value) }),
        React.createElement('button', { className: 'btn btn-cyan', onClick: handleBuild, disabled: loading },
          loading ? React.createElement(Spinner) : '🕸️', loading ? ' Building...' : ' Build Graph'
        ),
        graphCreated && cyInstance.current && React.createElement('button', { className: 'btn btn-outline', onClick: () => cyInstance.current?.fit() }, '🔍 Fit'),
        graphCreated && cyInstance.current && React.createElement('button', { className: 'btn btn-outline', onClick: () => cyInstance.current?.zoom({ level: cyInstance.current.zoom() + 0.2 }) }, '➕'),
        graphCreated && cyInstance.current && React.createElement('button', { className: 'btn btn-outline', onClick: () => cyInstance.current?.zoom({ level: cyInstance.current.zoom() - 0.2 }) }, '➖')
      )
    ),

    React.createElement('div', { className: 'card' },
      React.createElement('div', { style: { display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap', alignItems: 'center' } },
        React.createElement('span', { style: { fontSize: 12, color: 'var(--text-muted)', marginRight: 8 } }, 'Legend:'),
        legendItems.map(l => React.createElement('div', { key: l.label, style: { display: 'flex', alignItems: 'center', gap: 5, fontSize: 12 } },
          React.createElement('div', { style: { width: 12, height: 12, borderRadius: '50%', background: l.color } }),
          React.createElement('span', { style: { color: 'var(--text-secondary)' } }, l.label)
        )),
        React.createElement('span', { style: { fontSize: 12, color: '#ef4444', marginLeft: 8 } }, '🔴 Red border = High risk node')
      ),
      React.createElement('div', { id: 'cy', ref: cyRef, style: { display: graphCreated ? 'block' : 'none' } }),
      !graphCreated && React.createElement(EmptyState, { icon: '🕸️', title: 'No Graph Generated', desc: 'Enter a domain and click "Build Graph" to visualize the attack surface' }),
      selected && React.createElement('div', { style: { marginTop: 12, padding: 14, background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8 } },
        React.createElement('div', { style: { fontSize: 13, fontWeight: 700, marginBottom: 8 } }, '📌 Selected Node'),
        React.createElement('div', { className: 'info-list' },
          [
            ['Label', selected.label],
            ['Type', selected.type],
            ['Risk Score', selected.risk + '/100'],
          ].map(([k,v]) =>
            React.createElement('div', { key: k, className: 'info-row' },
              React.createElement('span', { className: 'info-key' }, k),
              React.createElement('span', { className: 'info-val' }, k === 'Risk Score' ? React.createElement('span', { style: { color: riskColor(selected.risk) } }, v) : v)
            )
          )
        )
      )
    )
  );
}

// ─── SIEM Dashboard Page ──────────────────────────────────────
function SIEMPage() {
  const [logs, setLogs] = useState(MOCK_LOGS);
  const [filter, setFilter] = useState('all');
  const [alertRules, setAlertRules] = useState([
    { id: 1, name: 'High Risk Domain Alert', condition: 'Risk score > 80', active: true },
    { id: 2, name: 'Rate Limit Warning',      condition: 'Requests > 100/min', active: true },
    { id: 3, name: 'Failed Login Attempts',   condition: 'Failed logins > 5', active: false },
    { id: 4, name: 'New Threat Detected',     condition: 'VT malicious > 10', active: true },
  ]);

  const filtered = filter === 'all' ? logs : logs.filter(l => l.level === filter);
  const levelCounts = { info: logs.filter(l=>l.level==='info').length, warn: logs.filter(l=>l.level==='warn').length, error: logs.filter(l=>l.level==='error').length, success: logs.filter(l=>l.level==='success').length };

  function addLogEntry() {
    const msgs = [
      { level: 'info', msg: 'Automated scan triggered for scheduled target' },
      { level: 'warn', msg: 'Unusual traffic pattern detected from 10.0.0.99' },
      { level: 'error', msg: 'External API connection failed: timeout after 30s' },
    ];
    const entry = msgs[Math.floor(Math.random() * msgs.length)];
    const now = new Date();
    const time = `${now.getHours().toString().padStart(2,'0')}:${now.getMinutes().toString().padStart(2,'0')}:${now.getSeconds().toString().padStart(2,'0')}`;
    setLogs(prev => [{ id: Date.now(), time, ...entry, user: 'system', ip: '0.0.0.0' }, ...prev]);
    showToast('New log entry added', 'info');
  }

  return React.createElement('div', { className: 'page-content fade-in' },
    React.createElement('div', { className: 'grid-4', style: { marginBottom: 20 } },
      [
        { label: 'INFO', count: levelCounts.info,    color: '#2563eb', icon: 'ℹ️' },
        { label: 'WARN', count: levelCounts.warn,    color: '#f59e0b', icon: '⚠️' },
        { label: 'ERROR', count: levelCounts.error,  color: '#ef4444', icon: '❌' },
        { label: 'SUCCESS', count: levelCounts.success, color: '#10b981', icon: '✅' },
      ].map(s =>
        React.createElement('div', { key: s.label, className: 'stat-card blue', style: { cursor: 'pointer' }, onClick: () => setFilter(s.label.toLowerCase()) },
          React.createElement('div', { style: { fontSize: 24 } }, s.icon),
          React.createElement('div', { className: 'stat-value', style: { color: s.color } }, s.count),
          React.createElement('div', { className: 'stat-label' }, s.label, ' Events')
        )
      )
    ),

    React.createElement('div', { className: 'grid-2', style: { marginBottom: 20 } },
      React.createElement('div', { className: 'card' },
        React.createElement('div', { className: 'card-header' },
          React.createElement('div', { className: 'card-title' }, '📋 System Log Stream'),
          React.createElement('div', { style: { display: 'flex', gap: 8 } },
            React.createElement('select', { className: 'input-field', style: { width: 'auto', padding: '4px 10px', fontSize: 12 }, value: filter, onChange: e => setFilter(e.target.value) },
              ['all','info','warn','error','success'].map(v => React.createElement('option', { key: v, value: v }, v.toUpperCase()))
            ),
            React.createElement('button', { className: 'btn btn-outline btn-sm', onClick: addLogEntry }, '+ Simulate Log')
          )
        ),
        React.createElement('div', { className: 'log-list', style: { maxHeight: 380, overflowY: 'auto' } },
          filtered.map(entry =>
            React.createElement('div', { key: entry.id, className: 'log-item' },
              React.createElement('span', { className: 'log-time' }, entry.time),
              React.createElement('span', { className: `log-level level-${entry.level}` }, entry.level.toUpperCase()),
              React.createElement('span', { className: 'log-msg' }, entry.msg),
              React.createElement('span', { className: 'log-user' }, entry.ip)
            )
          )
        )
      ),

      React.createElement('div', { className: 'card' },
        React.createElement('div', { className: 'card-header' },
          React.createElement('div', { className: 'card-title' }, '🔔 Alert Rules'),
          React.createElement('button', { className: 'btn btn-primary btn-sm', onClick: () => showToast('Alert rule created (demo)', 'success') }, '+ New Rule')
        ),
        alertRules.map(rule =>
          React.createElement('div', { key: rule.id, className: 'alert-rule' },
            React.createElement('div', null,
              React.createElement('div', { style: { fontSize: 13, fontWeight: 600 } }, rule.name),
              React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)', marginTop: 2 } }, rule.condition)
            ),
            React.createElement('button', {
              className: `switch ${rule.active ? 'on' : ''}`,
              onClick: () => setAlertRules(prev => prev.map(r => r.id === rule.id ? { ...r, active: !r.active } : r))
            })
          )
        ),

        React.createElement('div', { style: { marginTop: 16 } },
          React.createElement('div', { className: 'card-title', style: { marginBottom: 12 } }, '🚨 Active Alerts'),
          MOCK_ALERTS.slice(0,3).map(a =>
            React.createElement('div', { key: a.id, className: `alert ${a.severity === 'critical' ? 'alert-danger' : a.severity === 'high' ? 'alert-danger' : 'alert-warning'}`, style: { marginBottom: 6 } },
              React.createElement('span', null, a.severity === 'critical' || a.severity === 'high' ? '🚨' : '⚠️'),
              React.createElement('div', null,
                React.createElement('strong', null, a.title),
                React.createElement('div', { style: { fontSize: 11, marginTop: 2 } }, a.desc)
              )
            )
          )
        )
      )
    )
  );
}

// ─── User Management Page ─────────────────────────────────────
function UserManagementPage({ currentUser }) {
  const [users, setUsers] = useState(MOCK_USERS_TABLE);
  const [showModal, setShowModal] = useState(false);
  const [newUser, setNewUser] = useState({ name: '', email: '', role: 'Analyst' });

  if (currentUser.role !== 'Admin') {
    return React.createElement('div', { className: 'page-content fade-in' },
      React.createElement('div', { className: 'alert alert-danger' }, '🔒 Access denied. Admin privileges required.')
    );
  }

  function createUser() {
    if (!newUser.name || !newUser.email) { showToast('Name and email required', 'error'); return; }
    setUsers(prev => [...prev, { ...newUser, id: Date.now(), status: 'Active', scans: 0, lastSeen: 'Just now' }]);
    setShowModal(false);
    setNewUser({ name: '', email: '', role: 'Analyst' });
    showToast('User created successfully', 'success');
  }

  function toggleStatus(id) {
    setUsers(prev => prev.map(u => u.id === id ? { ...u, status: u.status === 'Active' ? 'Inactive' : 'Active' } : u));
    showToast('User status updated', 'info');
  }

  return React.createElement('div', { className: 'page-content fade-in' },
    React.createElement('div', { className: 'card', style: { marginBottom: 16 } },
      React.createElement('div', { className: 'card-header' },
        React.createElement('div', { className: 'card-title' }, '👥 Team Members & RBAC'),
        React.createElement('button', { className: 'btn btn-primary', onClick: () => setShowModal(true) }, '+ Add User')
      ),
      React.createElement('div', { className: 'table-wrap' },
        React.createElement('table', null,
          React.createElement('thead', null,
            React.createElement('tr', null,
              ['User', 'Email', 'Role', 'Status', 'Scans', 'Last Seen', 'Actions'].map(h => React.createElement('th', { key: h }, h))
            )
          ),
          React.createElement('tbody', null,
            users.map(u =>
              React.createElement('tr', { key: u.id },
                React.createElement('td', null,
                  React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 10 } },
                    React.createElement('div', { style: { width: 32, height: 32, borderRadius: '50%', background: 'var(--gradient-purple)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 13, fontWeight: 700 } }, u.name[0]),
                    React.createElement('span', { style: { fontWeight: 600, color: 'var(--text-primary)' } }, u.name)
                  )
                ),
                React.createElement('td', null, React.createElement('span', { className: 'mono', style: { fontSize: 12 } }, u.email)),
                React.createElement('td', null, React.createElement('span', { className: `role-pill role-${u.role.toLowerCase()}` }, u.role)),
                React.createElement('td', null, React.createElement('span', { style: { color: u.status === 'Active' ? 'var(--accent-green)' : 'var(--text-muted)', fontSize: 12 } }, u.status === 'Active' ? '● Active' : '○ Inactive')),
                React.createElement('td', null, u.scans),
                React.createElement('td', null, u.lastSeen),
                React.createElement('td', null,
                  React.createElement('div', { style: { display: 'flex', gap: 6 } },
                    React.createElement('button', { className: 'btn btn-outline btn-xs', onClick: () => toggleStatus(u.id) }, u.status === 'Active' ? 'Suspend' : 'Activate'),
                    React.createElement('button', { className: 'btn btn-outline btn-xs', onClick: () => showToast('Edit user (demo)', 'info') }, '✏️')
                  )
                )
              )
            )
          )
        )
      )
    ),

    React.createElement('div', { className: 'card' },
      React.createElement('div', { className: 'card-title', style: { marginBottom: 14 } }, '🔐 Role Permissions Matrix'),
      React.createElement('div', { className: 'table-wrap' },
        React.createElement('table', null,
          React.createElement('thead', null,
            React.createElement('tr', null,
              ['Permission', 'Admin', 'Analyst', 'Viewer'].map(h => React.createElement('th', { key: h }, h))
            )
          ),
          React.createElement('tbody', null,
            [
              ['View Dashboard',    true,  true,  true ],
              ['Run Social OSINT',  true,  true,  false],
              ['Domain Analysis',   true,  true,  false],
              ['IP Intelligence',   true,  true,  false],
              ['Threat Intel',      true,  true,  true ],
              ['Network Graph',     true,  true,  true ],
              ['SIEM Dashboard',    true,  true,  false],
              ['Manage Users',      true,  false, false],
              ['Export Reports',    true,  true,  false],
              ['View Audit Log',    true,  true,  false],
              ['Configure Alerts',  true,  false, false],
              ['API Key Access',    true,  false, false],
            ].map(([perm, admin, analyst, viewer]) =>
              React.createElement('tr', { key: perm },
                React.createElement('td', null, perm),
                [admin, analyst, viewer].map((allowed, i) =>
                  React.createElement('td', { key: i, style: { textAlign: 'center', color: allowed ? 'var(--accent-green)' : 'var(--text-muted)' } },
                    allowed ? '✅' : '❌'
                  )
                )
              )
            )
          )
        )
      )
    ),

    showModal && React.createElement('div', { className: 'modal-overlay', onClick: e => e.target === e.currentTarget && setShowModal(false) },
      React.createElement('div', { className: 'modal' },
        React.createElement('div', { className: 'modal-header' },
          React.createElement('div', { className: 'modal-title' }, '+ Create New User'),
          React.createElement('button', { className: 'modal-close', onClick: () => setShowModal(false) }, '×')
        ),
        React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 14 } },
          React.createElement('div', { className: 'input-group' },
            React.createElement('label', { className: 'input-label' }, 'FULL NAME'),
            React.createElement('input', { className: 'input-field', placeholder: 'John Doe', value: newUser.name, onChange: e => setNewUser(p => ({ ...p, name: e.target.value })) })
          ),
          React.createElement('div', { className: 'input-group' },
            React.createElement('label', { className: 'input-label' }, 'EMAIL ADDRESS'),
            React.createElement('input', { className: 'input-field', type: 'email', placeholder: 'user@company.io', value: newUser.email, onChange: e => setNewUser(p => ({ ...p, email: e.target.value })) })
          ),
          React.createElement('div', { className: 'input-group' },
            React.createElement('label', { className: 'input-label' }, 'ROLE'),
            React.createElement('select', { className: 'input-field', value: newUser.role, onChange: e => setNewUser(p => ({ ...p, role: e.target.value })) },
              ['Admin', 'Analyst', 'Viewer'].map(r => React.createElement('option', { key: r, value: r }, r))
            )
          ),
          React.createElement('div', { style: { display: 'flex', gap: 10, justifyContent: 'flex-end' } },
            React.createElement('button', { className: 'btn btn-outline', onClick: () => setShowModal(false) }, 'Cancel'),
            React.createElement('button', { className: 'btn btn-primary', onClick: createUser }, '✅ Create User')
          )
        )
      )
    )
  );
}

// ─── Audit Log Page ───────────────────────────────────────────
function AuditLogPage() {
  const auditData = [
    { id: 1, time: '2026-04-16 15:47', actor: 'admin@cyberscope.io',   action: 'USER_CREATED',   resource: 'viewer@cyberscope.io',       ip: '10.0.0.1', status: 'success' },
    { id: 2, time: '2026-04-16 15:43', actor: 'admin@cyberscope.io',   action: 'LOGIN',           resource: 'Auth System',                 ip: '10.0.0.1', status: 'success' },
    { id: 3, time: '2026-04-16 15:40', actor: 'analyst@cyberscope.io', action: 'SCAN_EXECUTED',   resource: 'malware-c2.xyz',              ip: '10.0.0.5', status: 'success' },
    { id: 4, time: '2026-04-16 15:35', actor: 'analyst@cyberscope.io', action: 'REPORT_EXPORTED', resource: 'scan_2847.pdf',               ip: '10.0.0.5', status: 'success' },
    { id: 5, time: '2026-04-16 15:30', actor: 'unknown',               action: 'LOGIN_FAILED',    resource: 'Auth System',                 ip: '203.0.113.5', status: 'failure' },
    { id: 6, time: '2026-04-16 15:25', actor: 'admin@cyberscope.io',   action: 'USER_SUSPENDED',  resource: 'mlee@cyberscope.io',         ip: '10.0.0.1', status: 'success' },
    { id: 7, time: '2026-04-16 15:20', actor: 'analyst@cyberscope.io', action: 'SCAN_EXECUTED',   resource: '185.220.101.22',              ip: '10.0.0.5', status: 'success' },
    { id: 8, time: '2026-04-16 15:15', actor: 'viewer@cyberscope.io',  action: 'NETWORK_GRAPH',   resource: 'example.com',                ip: '10.0.0.8', status: 'success' },
  ];

  return React.createElement('div', { className: 'page-content fade-in' },
    React.createElement('div', { className: 'card' },
      React.createElement('div', { className: 'card-header', style: { marginBottom: 16 } },
        React.createElement('div', { className: 'card-title' }, '📋 Security Audit Trail'),
        React.createElement('button', { className: 'btn btn-outline btn-sm', onClick: () => showToast('Audit log exported (demo)', 'success') }, '📥 Export Log')
      ),
      React.createElement('div', { className: 'alert alert-info', style: { marginBottom: 16 } },
        '🔒 Immutable audit trail — all user actions are logged and cannot be modified.'
      ),
      React.createElement('div', { className: 'table-wrap' },
        React.createElement('table', null,
          React.createElement('thead', null,
            React.createElement('tr', null,
              ['Timestamp', 'Actor', 'Action', 'Resource', 'IP Address', 'Status'].map(h => React.createElement('th', { key: h }, h))
            )
          ),
          React.createElement('tbody', null,
            auditData.map(e =>
              React.createElement('tr', { key: e.id },
                React.createElement('td', null, React.createElement('span', { className: 'mono', style: { fontSize: 12 } }, e.time)),
                React.createElement('td', null, React.createElement('span', { style: { fontSize: 12 } }, e.actor)),
                React.createElement('td', null,
                  React.createElement('span', { className: `tag ${e.action.includes('LOGIN_FAILED') || e.action.includes('SUSPEND') ? 'tag-red' : e.action.includes('SCAN') ? 'tag-purple' : ''}` }, e.action)
                ),
                React.createElement('td', null, React.createElement('span', { className: 'mono', style: { fontSize: 12 } }, e.resource)),
                React.createElement('td', null, React.createElement('span', { className: 'mono', style: { fontSize: 12 } }, e.ip)),
                React.createElement('td', null,
                  React.createElement('span', { style: { color: e.status === 'success' ? 'var(--accent-green)' : 'var(--accent-red)', fontSize: 12, fontWeight: 600 } },
                    e.status === 'success' ? '● ' : '● ', e.status
                  )
                )
              )
            )
          )
        )
      )
    )
  );
}

// ─── Main App ─────────────────────────────────────────────────
function App() {
  const [user, setUser] = useState(null);
  const [page, setPage] = useState('dashboard');
  const [scanCount] = useState(47);

  const pageComponents = {
    dashboard: React.createElement(DashboardPage),
    social:    React.createElement(SocialOSINTPage),
    domain:    React.createElement(DomainIntelPage),
    ip:        React.createElement(IPIntelPage),
    threat:    React.createElement(ThreatIntelPage),
    network:   React.createElement(NetworkGraphPage),
    siem:      React.createElement(SIEMPage),
    users:     React.createElement(UserManagementPage, { currentUser: user }),
    auditlog:  React.createElement(AuditLogPage),
  };

  if (!user) {
    return React.createElement(React.Fragment, null,
      React.createElement(LoginPage, { onLogin: setUser }),
      React.createElement(ToastContainer)
    );
  }

  return React.createElement(React.Fragment, null,
    React.createElement('div', { className: 'app-wrapper' },
      React.createElement(Sidebar, { activePage: page, setPage, user, onLogout: () => { setUser(null); showToast('Logged out successfully', 'info'); } }),
      React.createElement('div', { className: 'main-content' },
        React.createElement(Topbar, { page, user, scanCount }),
        pageComponents[page] || React.createElement('div', { className: 'page-content' }, '404')
      )
    ),
    React.createElement(ToastContainer)
  );
}

// ─── Mount ────────────────────────────────────────────────────
const root = createRoot(document.getElementById('root'));
root.render(React.createElement(App));
