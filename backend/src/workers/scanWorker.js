/**
 * BullMQ Scan Worker
 * Processes async scan jobs from the Redis queue
 * Handles: Port scanning (Nmap via child_process), Puppeteer screenshots
 *
 * Run standalone: node src/workers/scanWorker.js
 */
require('dotenv').config({ path: require('path').join(__dirname, '../../.env') });
const { Worker, Queue } = require('bullmq');
const { logger } = require('../middleware/logger');

const REDIS_CONFIG = {
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT) || 6379,
};

// ─── Queue Definitions ────────────────────────────────────────
const scanQueue      = new Queue('scan-jobs',      { connection: REDIS_CONFIG });
const screenshotQueue = new Queue('screenshot-jobs', { connection: REDIS_CONFIG });

// ─── Scan Worker ──────────────────────────────────────────────
const scanWorker = new Worker('scan-jobs', async (job) => {
  const { target, type, ports = 'top-100', timeout = 10000, userId } = job.data;

  logger.info(`[Worker] Processing scan job ${job.id}: ${type}://${target}`);
  await job.updateProgress(10);

  // Validate target is not private
  if (/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|localhost)/i.test(target)) {
    throw new Error('Private/loopback targets are not allowed');
  }

  let result = {};

  if (type === 'port-scan') {
    result = await performPortScan(target, ports, timeout, job);
  } else if (type === 'domain') {
    const domainService = require('../services/domainService');
    result = await domainService.fullAnalysis(target);
  } else if (type === 'ip') {
    const ipService = require('../services/ipService');
    result = await ipService.fullAnalysis(target);
  }

  await job.updateProgress(100);
  logger.info(`[Worker] Job ${job.id} completed for ${target}`);
  return { target, type, result, completedAt: new Date().toISOString() };

}, {
  connection: REDIS_CONFIG,
  concurrency: 3,                      // Max 3 scans at once
  limiter: { max: 10, duration: 60000 }, // Max 10 jobs/minute globally
});

// ─── Screenshot Worker ────────────────────────────────────────
const screenshotWorker = new Worker('screenshot-jobs', async (job) => {
  const { url, userId } = job.data;
  logger.info(`[Screenshot] Processing: ${url}`);

  let puppeteer;
  try {
    puppeteer = require('puppeteer');
  } catch {
    throw new Error('Puppeteer not installed. Run: npm install puppeteer');
  }

  const browser = await puppeteer.launch({
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--single-process',
    ],
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    await page.setUserAgent('Mozilla/5.0 (compatible; CyberScope-OSINT/1.0)');

    // Set timeout
    const timeout = parseInt(process.env.PUPPETEER_TIMEOUT_MS) || 15000;
    await page.goto(url, { waitUntil: 'networkidle2', timeout });

    // Collect metadata
    const title         = await page.title();
    const finalUrl      = page.url();
    const screenshotBuf = await page.screenshot({ type: 'webp', quality: 80, fullPage: false });

    // Detect tech stack (basic)
    const techDetection = await page.evaluate(() => ({
      hasReact:  !!window.React || !!document.querySelector('[data-reactroot]'),
      hasVue:    !!window.Vue,
      hasAngular:!!window.angular || !!document.querySelector('[ng-version]'),
      hasJQuery: !!window.jQuery,
      generator: document.querySelector('meta[name="generator"]')?.content || null,
    }));

    // Redirect chain (navigation entries)
    const redirectChain = [];

    return {
      url, finalUrl, title,
      screenshot: screenshotBuf.toString('base64'),
      screenshotMime: 'image/webp',
      techDetection,
      redirectChain,
      capturedAt: new Date().toISOString(),
    };
  } finally {
    await browser.close();
  }
}, {
  connection: REDIS_CONFIG,
  concurrency: 2,
});

// ─── Port Scan (Sandboxed Nmap) ───────────────────────────────
async function performPortScan(target, ports, timeout, job) {
  const { spawn } = require('child_process');

  // Build safe Nmap command (no shell=true, argument list)
  const portFlag = ports === 'top-100' ? '--top-ports 100' :
                   ports === 'top-1000' ? '--top-ports 1000' :
                   ports === 'common' ? '-p 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443' :
                   '--top-ports 100';

  const args = [
    '-sV',          // Service version detection
    '--open',       // Only show open ports
    '-T3',          // Reasonable timing (not aggressive)
    '--host-timeout', String(Math.floor(timeout / 1000)),
    ...portFlag.split(' '),
    '-oX', '-',     // XML output to stdout
    target
  ];

  return new Promise((resolve, reject) => {
    let stdout = '', stderr = '';
    const proc = spawn('nmap', args, {
      timeout,
      uid: process.getuid?.(),  // Run as current user, not root
    });

    proc.stdout.on('data', d => { stdout += d; job.updateProgress(50); });
    proc.stderr.on('data', d => stderr += d);
    proc.on('close', code => {
      if (code !== 0 && !stdout) return reject(new Error(`Nmap failed: ${stderr}`));
      // Parse XML output (simplified)
      const ports = [];
      const portMatches = stdout.matchAll(/<port protocol="[^"]*" portid="(\d+)">[\s\S]*?<state state="([^"]*)"[\s\S]*?<service name="([^"]*)"[^>]*version="([^"]*)"[^/]*/g);
      for (const m of portMatches) {
        ports.push({ port: parseInt(m[1]), state: m[2], service: m[3], version: m[4] || '' });
      }
      resolve({ ports, rawXml: stdout.slice(0, 5000) });
    });
    proc.on('error', err => {
      if (err.code === 'ENOENT') reject(new Error('Nmap not installed. Install nmap first.'));
      else reject(err);
    });
  });
}

// ─── Worker Event Handlers ────────────────────────────────────
[scanWorker, screenshotWorker].forEach(worker => {
  worker.on('completed',  job => logger.info(`[Worker] ${job.id} completed`));
  worker.on('failed',    (job, err) => logger.error(`[Worker] ${job?.id} failed: ${err.message}`));
  worker.on('error',     err => logger.error(`[Worker] Error: ${err.message}`));
});

logger.info('🔧 CyberScope Workers started (scan + screenshot)');

module.exports = { scanQueue, screenshotQueue };
