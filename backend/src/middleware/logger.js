/**
 * Winston Logger + Request Activity Logger
 */
const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Ensure log directory exists
const logDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

const { combine, timestamp, printf, colorize, json } = winston.format;

const consoleFormat = printf(({ level, message, timestamp }) =>
  `${timestamp} [${level.toUpperCase()}] ${message}`
);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: combine(timestamp(), json()),
  transports: [
    new winston.transports.File({ filename: path.join(logDir, 'error.log'), level: 'error' }),
    new winston.transports.File({ filename: path.join(logDir, 'cyberscope.log') }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: combine(colorize(), timestamp({ format: 'HH:mm:ss' }), consoleFormat),
  }));
}

/**
 * Middleware to log API activity to the DB (activity_logs table)
 * Must be used after authentication middleware
 */
function activityLogger(action) {
  return async (req, res, next) => {
    const userId = req.user?.id;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const metadata = {
      method: req.method,
      path: req.path,
      body: req.body,
      query: req.query,
    };
    logger.info(`[ACTIVITY] user=${userId} action=${action} ip=${ip} path=${req.path}`);

    // TODO: Insert into activity_logs table via DB pool
    // await db.query('INSERT INTO activity_logs (user_id, action, metadata, ip) VALUES ($1,$2,$3,$4)',
    //   [userId, action, JSON.stringify(metadata), ip]);

    next();
  };
}

module.exports = { logger, activityLogger };
