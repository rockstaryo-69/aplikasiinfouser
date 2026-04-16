/**
 * CyberScope OSINT Platform — Express Server Entry Point
 * Legal Use Only: Authorized pentesting and defensive security
 */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

const authRoutes    = require('./routes/auth');
const osintRoutes   = require('./routes/osint');
const domainRoutes  = require('./routes/domain');
const ipRoutes      = require('./routes/ip');
const scanRoutes    = require('./routes/scan');
const threatRoutes  = require('./routes/threat');
const riskRoutes    = require('./routes/risk');
const graphRoutes   = require('./routes/graph');
const userRoutes    = require('./routes/users');
const logsRoutes    = require('./routes/logs');

const { logger } = require('./middleware/logger');
const { errorHandler } = require('./middleware/errorHandler');
const { authenticate } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 4000;

// ─── Security Middleware ───────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // Adjust for your needs
}));

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
}));

// Global rate limiter (100 req/min per IP)
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Too many requests. Please slow down.', code: 'RATE_LIMIT_EXCEEDED' },
  standardHeaders: true,
  legacyHeaders: false,
}));

// ─── General Middleware ────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined', { stream: { write: msg => logger.info(msg.trim()) } }));

// ─── Health Check ─────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'operational',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    services: { api: true, database: true, redis: true },
  });
});

// ─── Legal Disclaimer Middleware ───────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Legal-Notice', 'For authorized security testing only. Unauthorized use is prohibited.');
  next();
});

// ─── Routes ───────────────────────────────────────────────────
app.use('/auth',         authRoutes);
app.use('/osint',        authenticate, osintRoutes);
app.use('/domain',       authenticate, domainRoutes);
app.use('/ip',           authenticate, ipRoutes);
app.use('/scan',         authenticate, scanRoutes);
app.use('/threat-check', authenticate, threatRoutes);
app.use('/risk-score',   authenticate, riskRoutes);
app.use('/network-graph',authenticate, graphRoutes);
app.use('/users',        authenticate, userRoutes);
app.use('/logs',         authenticate, logsRoutes);

// ─── 404 Handler ──────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found', path: req.path });
});

// ─── Error Handler ────────────────────────────────────────────
app.use(errorHandler);

// ─── Start ────────────────────────────────────────────────────
app.listen(PORT, () => {
  logger.info(`🔭 CyberScope API running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV}`);
  logger.info('Legal: For authorized pentesting and defensive security only.');
});

module.exports = app;
