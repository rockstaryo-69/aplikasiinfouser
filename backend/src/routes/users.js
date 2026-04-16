/**
 * User Management Routes (Admin only)
 * GET    /users
 * GET    /users/:id
 * PUT    /users/:id
 * DELETE /users/:id
 */
const router = require('express').Router();
const bcrypt = require('bcryptjs');
const { requireRole } = require('../middleware/auth');
const { activityLogger } = require('../middleware/logger');

// In-memory store (replace with PostgreSQL in production)
let users = [
  { id: 1, email: 'admin@cyberscope.io',   name: 'Admin User',  role: 'Admin',   status: 'active', scans: 142, createdAt: '2026-01-01' },
  { id: 2, email: 'analyst@cyberscope.io', name: 'Sarah Chen',  role: 'Analyst', status: 'active', scans: 89,  createdAt: '2026-02-15' },
  { id: 3, email: 'viewer@cyberscope.io',  name: 'John Viewer', role: 'Viewer',  status: 'active', scans: 12,  createdAt: '2026-03-01' },
];

// GET /users
router.get('/', requireRole('Admin'), (req, res) => {
  res.json({ success: true, users: users.map(u => ({ ...u, password: undefined })) });
});

// GET /users/:id
router.get('/:id', requireRole('Admin'), (req, res) => {
  const user = users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ success: true, user: { ...user, password: undefined } });
});

// PUT /users/:id — Update role or status
router.put('/:id',
  requireRole('Admin'),
  activityLogger('USER_UPDATED'),
  (req, res) => {
    const idx = users.findIndex(u => u.id === parseInt(req.params.id));
    if (idx === -1) return res.status(404).json({ error: 'User not found' });
    const allowed = ['role', 'status', 'name'];
    allowed.forEach(field => {
      if (req.body[field] !== undefined) users[idx][field] = req.body[field];
    });
    res.json({ success: true, user: { ...users[idx], password: undefined } });
  }
);

// DELETE /users/:id
router.delete('/:id',
  requireRole('Admin'),
  activityLogger('USER_DELETED'),
  (req, res) => {
    const id = parseInt(req.params.id);
    if (id === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account' });
    users = users.filter(u => u.id !== id);
    res.json({ success: true, message: 'User deleted' });
  }
);

module.exports = router;
