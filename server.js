// ═══════════════════════════════════════════
// NOVA BANK — Full Backend Server
// ═══════════════════════════════════════════

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── DATABASE SETUP ──────────────────────────
const dbDir = path.join(__dirname, 'data');
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir);
const db = new Database(path.join(dbDir, 'novabank.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    balance REAL DEFAULT 0,
    role TEXT DEFAULT 'user',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    amount REAL NOT NULL,
    method TEXT,
    note TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS withdrawals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    method TEXT NOT NULL,
    details TEXT NOT NULL,
    amount REAL NOT NULL,
    fee REAL NOT NULL,
    usdt_amount REAL NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// Seed admin user if not exists
const adminEmail = process.env.ADMIN_EMAIL || 'admin@novabank.com';
const adminPass = process.env.ADMIN_PASSWORD || 'Admin@123';
const existingAdmin = db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail);
if (!existingAdmin) {
  const hash = bcrypt.hashSync(adminPass, 10);
  db.prepare('INSERT INTO users (name, email, password_hash, role, balance) VALUES (?, ?, ?, ?, 0)')
    .run('Admin', adminEmail, hash, 'admin');
}

// Seed demo users
const demoUsers = [
  { name: 'Alice Johnson', email: 'alice@example.com', pass: 'Alice@123', balance: 2500 },
  { name: 'Bob Smith',     email: 'bob@example.com',   pass: 'Bob@123',   balance: 1200.50 },
  { name: 'Carol Davis',   email: 'carol@example.com', pass: 'Carol@123', balance: 875.25 },
];
for (const u of demoUsers) {
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(u.email);
  if (!existing) {
    const hash = bcrypt.hashSync(u.pass, 10);
    db.prepare('INSERT INTO users (name, email, password_hash, balance) VALUES (?, ?, ?, ?)')
      .run(u.name, u.email, hash, u.balance);
  }
}

// ─── MIDDLEWARE ──────────────────────────────
function authMiddleware(requiredRole) {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
      const user = db.prepare('SELECT id, name, email, role, balance FROM users WHERE id = ?').get(decoded.id);
      if (!user) return res.status(404).json({ error: 'User not found' });
      if (requiredRole && user.role !== requiredRole)
        return res.status(403).json({ error: 'Insufficient permissions' });
      req.user = user;
      next();
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

function userAuth(req, res, next) { return authMiddleware(null)(req, res, next); }
function adminAuth(req, res, next) { return authMiddleware('admin')(req, res, next); }

// ─── FEES CONFIG ─────────────────────────────
const METHOD_FEES = {
  bank:     { rate: 0.005, label: 'Bank Transfer', min: 10 },
  paypal:   { rate: 0.015, label: 'PayPal',        min: 5 },
  cashapp:  { rate: 0.01,  label: 'Cash App',      min: 5 },
  venmo:    { rate: 0.01,  label: 'Venmo',         min: 5 },
};
const USDT_RATE = 1.08; // USD per USDT

// ═══════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════

// Register
app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Name, email, and password required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)'
    ).run(name, email, hash);

    const user = db.prepare('SELECT id, name, email, role, balance FROM users WHERE id = ?').get(result.lastInsertRowid);
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || 'fallback-secret', { expiresIn: '7d' });
    res.json({ user, token });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'Email already registered' });
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Invalid credentials' });

  const { password_hash, ...safeUser } = user;
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || 'fallback-secret', { expiresIn: '7d' });
  res.json({ user: safeUser, token });
});

// Get current user
app.get('/api/auth/me', userAuth, (req, res) => {
  res.json({ user: req.user });
});

// ═══════════════════════════════════════════
// USER ROUTES
// ═══════════════════════════════════════════

// Get balance
app.get('/api/user/balance', userAuth, (req, res) => {
  const user = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.user.id);
  res.json({ balance: user.balance });
});

// Get transaction history
app.get('/api/user/history', userAuth, (req, res) => {
  const txns = db.prepare(
    'SELECT type, amount, method, note, created_at FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50'
  ).all(req.user.id);
  res.json({ transactions: txns });
});

// ─── WITHDRAWAL FLOW ────────────────────────

// Step 1: Initiate withdrawal (select method + details)
app.post('/api/user/withdraw/initiate', userAuth, (req, res) => {
  const { method, amount, details } = req.body;

  const feeConfig = METHOD_FEES[method];
  if (!feeConfig) return res.status(400).json({ error: 'Invalid method' });
  if (!amount || amount < feeConfig.min)
    return res.status(400).json({ error: `Minimum withdrawal is $${feeConfig.min}` });

  const user = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.user.id);
  if (amount > user.balance)
    return res.status(400).json({ error: 'Insufficient balance' });

  const fee = parseFloat((amount * feeConfig.rate).toFixed(2));
  const usdtAmount = parseFloat((fee / USDT_RATE).toFixed(4));

  const result = db.prepare(
    'INSERT INTO withdrawals (user_id, method, details, amount, fee, usdt_amount, status) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(req.user.id, method, JSON.stringify(details), amount, fee, usdtAmount, 'pending');

  res.json({
    withdrawalId: result.lastInsertRowid,
    fee,
    usdtAmount,
    method: feeConfig.label,
    amount,
  });
});

// Step 2: Confirm USDT purchase
app.post('/api/user/withdraw/usdt', userAuth, (req, res) => {
  const { withdrawalId, paymentMethod } = req.body;

  const withdrawal = db.prepare('SELECT * FROM withdrawals WHERE id = ? AND user_id = ?').get(withdrawalId, req.user.id);
  if (!withdrawal) return res.status(404).json({ error: 'Withdrawal not found' });
  if (withdrawal.status !== 'pending') return res.status(400).json({ error: 'Withdrawal already processed' });

  db.prepare("UPDATE withdrawals SET status = 'usdt_purchased' WHERE id = ?").run(withdrawalId);

  res.json({
    success: true,
    message: `USDT purchase confirmed via ${paymentMethod || 'Card'}`,
    withdrawalId,
    nextStep: 'confirm',
  });
});

// Step 3: Finalize withdrawal
app.post('/api/user/withdraw/confirm', userAuth, (req, res) => {
  const { withdrawalId } = req.body;

  const withdrawal = db.prepare('SELECT * FROM withdrawals WHERE id = ? AND user_id = ?').get(withdrawalId, req.user.id);
  if (!withdrawal) return res.status(404).json({ error: 'Withdrawal not found' });
  if (withdrawal.status !== 'usdt_purchased') return res.status(400).json({ error: 'USDT not purchased yet' });

  // Deduct balance
  db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(withdrawal.amount, req.user.id);

  // Log transaction
  db.prepare(
    'INSERT INTO transactions (user_id, type, amount, method, note) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user.id, 'withdraw', withdrawal.amount, withdrawal.method, `Fee: $${withdrawal.fee} (USDT)`);

  // Mark complete
  db.prepare("UPDATE withdrawals SET status = 'completed' WHERE id = ?").run(withdrawalId);

  const updatedUser = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.user.id);

  res.json({
    success: true,
    message: 'Withdrawal processed successfully',
    amount: withdrawal.amount,
    method: withdrawal.method,
    newBalance: updatedUser.balance,
  });
});

// ═══════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════

// Get all users
app.get('/api/admin/users', adminAuth, (req, res) => {
  const users = db.prepare('SELECT id, name, email, balance, role, created_at FROM users WHERE role = ?').all('user');
  res.json({ users });
});

// Send money to a user
app.post('/api/admin/send-money', adminAuth, (req, res) => {
  const { userId, amount, note } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Valid amount required' });

  const user = db.prepare('SELECT id, name, balance FROM users WHERE id = ? AND role = ?').get(userId, 'user');
  if (!user) return res.status(404).json({ error: 'User not found' });

  // Add to user balance
  db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(amount, userId);

  // Log transaction
  db.prepare(
    'INSERT INTO transactions (user_id, type, amount, method, note) VALUES (?, ?, ?, ?, ?)'
  ).run(userId, 'deposit', amount, 'Admin', note || 'Admin transfer');

  const updated = db.prepare('SELECT balance FROM users WHERE id = ?').get(userId);

  res.json({
    success: true,
    message: `Sent $${amount.toFixed(2)} to ${user.name}`,
    user: { id: user.id, name: user.name, newBalance: updated.balance },
  });
});

// Get all transactions
app.get('/api/admin/transactions', adminAuth, (req, res) => {
  const txns = db.prepare(`
    SELECT t.*, u.name as user_name, u.email as user_email
    FROM transactions t
    JOIN users u ON t.user_id = u.id
    ORDER BY t.created_at DESC
    LIMIT 100
  `).all();
  res.json({ transactions: txns });
});

// Get all withdrawals
app.get('/api/admin/withdrawals', adminAuth, (req, res) => {
  const withdrawals = db.prepare(`
    SELECT w.*, u.name as user_name
    FROM withdrawals w
    JOIN users u ON w.user_id = u.id
    ORDER BY w.created_at DESC
    LIMIT 50
  `).all();
  res.json({ withdrawals });
});

// Admin stats
app.get('/api/admin/stats', adminAuth, (req, res) => {
  const totalUsers = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'user'").get().count;
  const totalBalance = db.prepare("SELECT COALESCE(SUM(balance), 0) as total FROM users WHERE role = 'user'").get().total;
  const totalTxns = db.prepare("SELECT COUNT(*) as count FROM transactions").get().count;
  const totalWithdrawals = db.prepare("SELECT COUNT(*) as count FROM withdrawals WHERE status = 'completed'").get().count;

  res.json({
    totalUsers,
    totalBalance,
    totalTxns,
    totalWithdrawals,
  });
});

// ═══════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════
// Serve the Nova-Bank homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🏦 NovaBank running on http://localhost:${PORT}`);
  console.log(`   Admin login: ${adminEmail} / ${adminPass}`);
  console.log(`   Demo user:   alice@example.com / Alice@123\n`);
});
