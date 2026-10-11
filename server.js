require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'skrill-secret-key-change-in-prod';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ===== HELPERS =====
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
};

const getSetting = (key) => {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
};

// ===== AUTH ROUTES =====
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const existing = db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(email, username);
    if (existing) return res.status(409).json({ error: 'Username or email already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
    const result = stmt.run(username, email, hashed);

    const token = jwt.sign({ id: result.lastInsertRowid, username, role: 'user' }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { username, email, role: 'user' } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ? OR username = ?').get(email, email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { username: user.username, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', authenticate, (req, res) => {
  const user = db.prepare('SELECT id, username, email, role, balance, btc_balance FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// ===== USER ROUTES =====
app.get('/api/user/balance', authenticate, (req, res) => {
  const user = db.prepare('SELECT balance, btc_balance FROM users WHERE id = ?').get(req.user.id);
  res.json(user);
});

app.get('/api/user/transactions', authenticate, (req, res) => {
  const txns = db.prepare(`
    SELECT t.*, u.username as sender_name,
    COALESCE(r.username, t.recipient_name) as recipient_name
    FROM transactions t
    LEFT JOIN users u ON t.sender_id = u.id
    LEFT JOIN users r ON t.recipient_id = r.id
    WHERE t.sender_id = ? OR t.recipient_id = ?
    ORDER BY t.created_at DESC
    LIMIT 100
  `).all(req.user.id, req.user.id);
  res.json(txns);
});

// Internal transfer (FREE)
app.post('/api/transfers/internal', authenticate, (req, res) => {
  try {
    const { recipient, amount } = req.body;
    const sender = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);

    if (!recipient || !amount || amount <= 0) {
      return res.status(400).json({ error: 'Recipient and valid amount required' });
    }
    if (amount > sender.balance) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    let recipientUser = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(recipient, recipient);
    if (!recipientUser) {
      return res.status(404).json({ error: 'Recipient not found' });
    }
    if (recipientUser.id === sender.id) {
      return res.status(400).json({ error: 'Cannot send to yourself' });
    }

    const transfer = db.transaction(() => {
      db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(amount, sender.id);
      db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(amount, recipientUser.id);
      db.prepare('INSERT INTO transactions (sender_id, recipient_id, type, amount, status) VALUES (?, ?, ?, ?, ?)')
        .run(sender.id, recipientUser.id, 'internal', amount, 'completed');
    });
    transfer();

    res.json({ message: `Sent $${amount.toFixed(2)} to ${recipientUser.username} — free! 🎉` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// External transfer (BTC FEE)
app.post('/api/transfers/external', authenticate, (req, res) => {
  try {
    const { method, recipient, amount } = req.body;
    const sender = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);

    if (!method || !recipient || !amount || amount <= 0) {
      return res.status(400).json({ error: 'Method, recipient, and valid amount required' });
    }

    const feeRate = parseFloat(getSetting('btc_fee_rate') || '0.0001');
    const feeMin = parseFloat(getSetting('btc_fee_min') || '0.00005');
    const btcFee = Math.max(feeRate * amount, feeMin);

    if (amount > sender.balance) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    if (btcFee > sender.btc_balance) {
      return res.status(400).json({ error: `Insufficient BTC for fee. Need ${btcFee.toFixed(6)} BTC, have ${sender.btc_balance.toFixed(6)}` });
    }

    const transfer = db.transaction(() => {
      db.prepare('UPDATE users SET balance = balance - ?, btc_balance = btc_balance - ? WHERE id = ?')
        .run(amount, btcFee, sender.id);
      db.prepare('INSERT INTO transactions (sender_id, recipient_name, type, method, amount, btc_fee, status) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(sender.id, recipient, 'external', method, amount, btcFee, 'completed');
    });
    transfer();

    res.json({
      message: `External transfer of $${amount.toFixed(2)} via ${method} to ${recipient} — fee: ${btcFee.toFixed(6)} BTC ✅`,
      btc_fee: btcFee
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add BTC to wallet
app.post('/api/user/add-btc', authenticate, (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Valid BTC amount required' });
  db.prepare('UPDATE users SET btc_balance = btc_balance + ? WHERE id = ?').run(amount, req.user.id);
  const user = db.prepare('SELECT btc_balance FROM users WHERE id = ?').get(req.user.id);
  res.json({ message: `Added ${amount} BTC`, btc_balance: user.btc_balance });
});

// ===== ADMIN ROUTES =====
app.get('/api/admin/stats', authenticate, requireAdmin, (req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  const totalBalance = db.prepare('SELECT COALESCE(SUM(balance), 0) as total FROM users').get().total;
  const totalBtc = db.prepare('SELECT COALESCE(SUM(btc_balance), 0) as total FROM users').get().total;
  const totalTxns = db.prepare('SELECT COUNT(*) as count FROM transactions').get().count;
  const totalInternal = db.prepare("SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE type = 'internal'").get().total;
  const totalExternal = db.prepare("SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE type = 'external'").get().total;
  const totalFees = db.prepare('SELECT COALESCE(SUM(btc_fee), 0) as total FROM transactions').get().total;

  res.json({ totalUsers, totalBalance, totalBtc, totalTxns, totalInternal, totalExternal, totalFees });
});

app.get('/api/admin/users', authenticate, requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id, username, email, role, balance, btc_balance, created_at FROM users ORDER BY created_at DESC').all();
  res.json(users);
});

app.get('/api/admin/transactions', authenticate, requireAdmin, (req, res) => {
  const txns = db.prepare(`
    SELECT t.*, u.username as sender_name,
    COALESCE(r.username, t.recipient_name) as recipient_name
    FROM transactions t
    LEFT JOIN users u ON t.sender_id = u.id
    LEFT JOIN users r ON t.recipient_id = r.id
    ORDER BY t.created_at DESC
    LIMIT 200
  `).all();
  res.json(txns);
});

app.put('/api/admin/users/:id', authenticate, requireAdmin, (req, res) => {
  const { username, email, role, balance, btc_balance } = req.body;
  const fields = [];
  const values = [];
  if (username !== undefined) { fields.push('username = ?'); values.push(username); }
  if (email !== undefined) { fields.push('email = ?'); values.push(email); }
  if (role !== undefined) { fields.push('role = ?'); values.push(role); }
  if (balance !== undefined) { fields.push('balance = ?'); values.push(balance); }
  if (btc_balance !== undefined) { fields.push('btc_balance = ?'); values.push(btc_balance); }
  if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });

  values.push(req.params.id);
  db.prepare(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  res.json({ message: 'User updated' });
});

app.delete('/api/admin/users/:id', authenticate, requireAdmin, (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ message: 'User deleted' });
});

app.put('/api/admin/settings', authenticate, requireAdmin, (req, res) => {
  const { btc_fee_rate, btc_fee_min, external_methods } = req.body;
  const upsert = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
  if (btc_fee_rate !== undefined) upsert.run('btc_fee_rate', String(btc_fee_rate));
  if (btc_fee_min !== undefined) upsert.run('btc_fee_min', String(btc_fee_min));
  if (external_methods !== undefined) upsert.run('external_methods', external_methods);
  res.json({ message: 'Settings updated' });
});

app.get('/api/admin/settings', authenticate, requireAdmin, (req, res) => {
  const settings = db.prepare('SELECT key, value FROM settings').all();
  const result = {};
  settings.forEach(s => result[s.key] = s.value);
  res.json(result);
});

// Create admin (first-time setup)
app.post('/api/admin/create', (req, res) => {
  const { username, email, password } = req.body;
  const hashed = bcrypt.hashSync(password, 10);
  try {
    db.prepare('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)').run(username, email, hashed, 'admin');
    res.json({ message: 'Admin created' });
  } catch {
    res.status(409).json({ error: 'Admin already exists' });
  }
});

// ===== START =====
app.listen(PORT, () => {
  console.log(`🚀 Skrill Business running on port ${PORT}`);
  console.log(`   Landing:   http://localhost:${PORT}/index.html`);
  console.log(`   Login:     http://localhost:${PORT}/login.html`);
  console.log(`   Dashboard: http://localhost:${PORT}/dashboard.html`);
  console.log(`   Admin:     http://localhost:${PORT}/admin.html`);
});
