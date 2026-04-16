/**
 * Authentication Middleware — JWT + Role-Based Access Control
 */
const jwt = require('jsonwebtoken');

const ROLE_HIERARCHY = { Admin: 3, Analyst: 2, Viewer: 1 };

/**
 * Verifies JWT access token on every protected request
 */
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { id, email, role, name }
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired. Please login again.' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/**
 * Role-based access control factory
 * Usage: router.get('/admin-route', requireRole('Admin'), handler)
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthenticated' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Access denied. Requires one of: ${roles.join(', ')}`,
        yourRole: req.user.role,
      });
    }
    next();
  };
}

/**
 * Minimum role level check (e.g., requireMinRole('Analyst') = Analyst + Admin can access)
 */
function requireMinRole(minRole) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthenticated' });
    const userLevel = ROLE_HIERARCHY[req.user.role] || 0;
    const minLevel  = ROLE_HIERARCHY[minRole] || 0;
    if (userLevel < minLevel) {
      return res.status(403).json({
        error: `Access denied. Minimum role required: ${minRole}`,
        yourRole: req.user.role,
      });
    }
    next();
  };
}

module.exports = { authenticate, requireRole, requireMinRole };
