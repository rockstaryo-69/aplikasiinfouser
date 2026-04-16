/**
 * Global Error Handler Middleware
 */
const { logger } = require('./logger');

function errorHandler(err, req, res, next) {
  const status = err.status || err.statusCode || 500;
  const message = err.message || 'Internal server error';

  logger.error(`[ERROR] ${req.method} ${req.path} — ${status}: ${message}`, {
    stack: err.stack,
    user: req.user?.email,
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
  });

  // Don't leak stack traces in production
  res.status(status).json({
    error: message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
}

class AppError extends Error {
  constructor(message, status = 500) {
    super(message);
    this.status = status;
    this.name = 'AppError';
  }
}

module.exports = { errorHandler, AppError };
