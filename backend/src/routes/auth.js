/**
 * Auth Routes — Login, Register, Refresh Token, Logout
 * POST /auth/login
 * POST /auth/register (Admin only after first setup)
 * GET  /auth/me
 * POST /auth/logout
 */
const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { validators } = require('../middleware/inputValidator');
const { authenticate, requireRole } = require('../middleware/auth');
const { logger } = require('../middleware/logger');

// Strict rate limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
});

// ─── In-memory user store (replace with PostgreSQL in production) ───
const users = [
  { id: 1, email: 'admin@cyberscope.io',   password: bcrypt.hashSync('admin123', 10),   name: 'Admin User',  role: 'Admin'   },
  { id: 2, email: 'analyst@cyberscope.io', password: bcrypt.hashSync('analyst123', 10), name: 'Sarah Chen',  role: 'Analyst' },
  { id: 3, email: 'viewer@cyberscope.io',  password: bcrypt.hashSync('viewer123', 10),  name: 'John Viewer', role: 'Viewer'  },
];
let nextId = 4;

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
  );
}

// POST /auth/login
router.post('/login', authLimiter, validators.login, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      logger.warn(`Failed login attempt: ${email}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = signToken(user);
    logger.info(`Login: ${email} (${user.role})`);
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch (err) { next(err); }
});

// POST /auth/register (Admin only)
router.post('/register', authenticate, requireRole('Admin'), validators.register, async (req, res, next) => {
  try {
    const { email, password, name, role = 'Analyst' } = req.body;
    if (users.find(u => u.email === email)) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    const hashed = await bcrypt.hash(password, 12);
    const newUser = { id: nextId++, email, password: hashed, name, role };
    users.push(newUser);
    logger.info(`New user created: ${email} (${role}) by ${req.user.email}`);
    res.status(201).json({ message: 'User created', user: { id: newUser.id, email, name, role } });
  } catch (err) { next(err); }
});

// GET /auth/me
router.get('/me', authenticate, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, email: user.email, name: user.name, role: user.role });
});

// POST /auth/logout (client-side token invalidation; add token blacklist for production)
router.post('/logout', authenticate, (req, res) => {
  logger.info(`Logout: ${req.user.email}`);
  res.json({ message: 'Logged out successfully' });
});

module.exports = router;
