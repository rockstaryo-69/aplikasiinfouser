# CyberScope — OSINT Intelligence Platform

> **Legal Notice:** This platform is for authorized penetration testing, defensive security research, and educational purposes ONLY. Unauthorized use against systems you do not own or have explicit written permission to test is illegal and strictly prohibited.

---

## 🔭 Overview

CyberScope is a full-stack, modular OSINT (Open Source Intelligence) platform for cybersecurity analysts, red teams, and threat intelligence professionals. It provides domain/IP intelligence, social media OSINT, threat reputation checks, network graph visualization, ML risk scoring, SIEM monitoring, and multi-user RBAC — all in a dark-mode, premium web interface.

---

## 🚀 Quick Start (Standalone Frontend)

**No installation required.** Simply open the file directly in your browser:

```
osint-platform/index.html
```

Use the demo accounts:
| Email | Password | Role |
|-------|----------|------|
| `admin@cyberscope.io` | `admin123` | Admin |
| `analyst@cyberscope.io` | `analyst123` | Analyst |
| `viewer@cyberscope.io` | `viewer123` | Viewer |

---

## 🗂️ Project Structure

```
osint-platform/
├── index.html              ← Standalone frontend (React CDN)
├── styles.css              ← Dark UI stylesheet
├── app.js                  ← Full React application
├── docker-compose.yml      ← Full stack orchestration
│
└── backend/
    ├── .env.example        ← Environment variable template
    ├── Dockerfile          ← API container
    ├── Dockerfile.worker   ← Scan worker container
    ├── package.json
    └── src/
        ├── server.js               ← Express entry point
        ├── middleware/
        │   ├── auth.js             ← JWT + RBAC
        │   ├── inputValidator.js   ← Sanitization
        │   ├── logger.js           ← Winston logging
        │   └── errorHandler.js     ← Global error handling
        ├── routes/
        │   ├── auth.js             ← POST /auth/login|register
        │   ├── domain.js           ← GET /domain
        │   ├── ip.js               ← GET /ip
        │   ├── osint.js            ← GET /osint/social
        │   ├── scan.js             ← POST /scan (async queue)
        │   ├── threat.js           ← GET /threat-check
        │   ├── risk.js             ← POST /risk-score
        │   ├── graph.js            ← GET /network-graph
        │   ├── users.js            ← GET/PUT/DELETE /users
        │   └── logs.js             ← GET /logs/activity|audit
        ├── services/
        │   ├── domainService.js    ← WHOIS, DNS, crt.sh
        │   ├── ipService.js        ← ip-api.com, rDNS
        │   ├── threatService.js    ← VirusTotal, AbuseIPDB
        │   └── socialService.js    ← Public profile probing
        ├── ml/
        │   └── riskModel.js        ← Weighted logistic regression
        ├── workers/
        │   └── scanWorker.js       ← BullMQ + Nmap + Puppeteer
        └── db/
            ├── db.js               ← PostgreSQL pool
            └── schema.sql          ← Full DB schema
```

---

## ⚙️ Backend Setup (Full Stack)

### Prerequisites
- Node.js ≥ 18
- PostgreSQL 15
- Redis 7
- Nmap (for port scanning)
- Docker + Docker Compose (optional)

### 1. Configure Environment
```bash
cd backend
cp .env.example .env
# Edit .env — add your API keys (VirusTotal, AbuseIPDB)
```

### 2. Install & Run
```bash
npm install
npm run migrate    # Run schema.sql against PostgreSQL
npm run dev        # Start API on port 4000
node src/workers/scanWorker.js  # Start worker (separate terminal)
```

### 3. Docker (Recommended)
```bash
# From project root
docker-compose up -d

# Services:
#   Frontend:  http://localhost:3000
#   Backend:   http://localhost:4000
#   PgAdmin:   connect to localhost:5432
```

---

## 🔌 API Endpoints

| Method | Endpoint | Auth | Role | Description |
|--------|----------|------|------|-------------|
| POST | `/auth/login` | ❌ | Any | Login + get JWT |
| POST | `/auth/register` | ✅ | Admin | Create user |
| GET  | `/auth/me` | ✅ | Any | Current user info |
| GET  | `/domain?name=` | ✅ | Analyst+ | Domain intelligence |
| GET  | `/domain/whois?name=` | ✅ | Analyst+ | WHOIS lookup |
| GET  | `/domain/dns?name=` | ✅ | Analyst+ | DNS records |
| GET  | `/domain/subdomains?name=` | ✅ | Analyst+ | Subdomain enum (crt.sh) |
| GET  | `/ip?address=` | ✅ | Analyst+ | IP intelligence |
| GET  | `/osint/social?username=` | ✅ | Analyst+ | Social OSINT |
| POST | `/scan` | ✅ | Analyst+ | Queue async scan |
| GET  | `/scan/:jobId` | ✅ | Analyst+ | Job status |
| GET  | `/threat-check?target=` | ✅ | Any | Threat reputation |
| POST | `/risk-score` | ✅ | Any | ML risk score |
| GET  | `/network-graph?domain=` | ✅ | Any | Graph data |
| GET  | `/users` | ✅ | Admin | List users |
| GET  | `/logs/activity` | ✅ | Analyst+ | Activity logs |
| GET  | `/logs/audit` | ✅ | Analyst+ | Audit trail |

---

## 🧠 ML Risk Scoring

`POST /risk-score` — send any combination of features:

```json
{
  "domainAge": 45,
  "subdomainCount": 12,
  "vtMalicious": 8,
  "asnRisk": 70,
  "usernameAnomaly": true,
  "linkSpam": false,
  "sslValid": false,
  "target": "abc123xyz.top",
  "registrarReputable": false
}
```

Response:
```json
{
  "score": 82,
  "label": "High",
  "confidence": "high",
  "explanation": ["8 VirusTotal detections", "No valid SSL certificate", "New domain (45 days)"],
  "features_used": { "vtMalicious": 14.4, "sslInvalid": 10, ... }
}
```

---

## 🔐 Security Features

| Feature | Implementation |
|---------|---------------|
| Authentication | JWT (8h expiry) |
| Password Hashing | bcrypt (cost 12) |
| Input Validation | express-validator (sanitized, length-limited) |
| Rate Limiting | express-rate-limit (100/min global, 5/min scans) |
| Private IP Block | Regex filter before any scan |
| Role-Based Access | Middleware per route |
| Scan Sandboxing | Child process, no shell=true, timeout |
| Audit Trail | Immutable DB table, no DELETE |
| HTTPS | Configure nginx/Caddy reverse proxy in production |

---

## 🌐 External API Keys Required

| Service | Purpose | Free Tier | Link |
|---------|---------|-----------|------|
| VirusTotal | Threat reputation | 4 req/min | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | IP abuse reports | 1000 checks/day | [abuseipdb.com](https://www.abuseipdb.com/register) |
| ip-api.com | Geolocation | 45 req/min (free) | No key needed |
| crt.sh | Subdomain CT logs | Unlimited | No key needed |

---

## 🚢 Deployment

### Vercel (Frontend)
```bash
cd frontend
npx vercel --prod
```

### Render / Railway (Backend)
```bash
# Set environment variables in dashboard
# Deploy from git → start command: node src/server.js
```

### AWS / GCP (Production)
- Use provided `docker-compose.yml`
- Add nginx reverse proxy + SSL (Let's Encrypt)
- Set `NODE_ENV=production`
- Use managed PostgreSQL (RDS / Cloud SQL)
- Use managed Redis (ElastiCache / Memorystore)

---

## ⚖️ Legal Disclaimer

> This application is designed exclusively for:
> - Authorized penetration testing of systems you own or have explicit written permission to test
> - Defensive security research using publicly available data
> - Educational cybersecurity training
>
> **UNAUTHORIZED USE IS ILLEGAL.** The authors accept no liability for misuse.
> Always obtain written authorization before testing any target system.

---

*Built with ❤️ for the security community — CyberScope v1.0*
