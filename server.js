'use strict';
const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'primazet.db');
const SESSION_DAYS = 7;
const COOKIE = 'pz_sid';
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/* ---------- Base de datos ---------- */
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  name                TEXT NOT NULL,
  email               TEXT NOT NULL UNIQUE,
  pass_hash           TEXT NOT NULL,
  age_declared        INTEGER NOT NULL DEFAULT 0,
  privacy_accepted_at TEXT NOT NULL,
  created_at          TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tickets (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message    TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS contact_messages (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL,
  email      TEXT NOT NULL,
  message    TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`);
const purge = () => db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());
purge();
setInterval(purge, 3600e3).unref();

/* ---------- Utilidades ---------- */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const now = () => new Date().toISOString();
const clean = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, 64);
  return salt.toString('hex') + ':' + h.toString('hex');
}
async function verifyPassword(pw, stored) {
  const [s, h] = stored.split(':');
  const calc = await scrypt(pw, Buffer.from(s, 'hex'), 64);
  const hb = Buffer.from(h, 'hex');
  return hb.length === calc.length && crypto.timingSafeEqual(hb, calc);
}
const DUMMY = hashPassword('contraseña-falsa'); // para igualar tiempos si el email no existe

function getCookie(req, name) {
  const h = req.headers.cookie;
  if (!h) return null;
  for (const p of h.split(';')) {
    const i = p.indexOf('=');
    if (i > 0 && p.slice(0, i).trim() === name) {
      try { return decodeURIComponent(p.slice(i + 1).trim()); } catch { return null; }
    }
  }
  return null;
}

// Limitador sencillo en memoria: max peticiones por ventana e IP+ruta
const hits = new Map();
const limit = (max, windowMs) => (req, res, next) => {
  const k = req.ip + req.path, t = Date.now();
  const a = (hits.get(k) || []).filter(x => t - x < windowMs);
  if (a.length >= max) return res.status(429).json({ ok: false, code: 'rate' });
  a.push(t); hits.set(k, a); next();
};
setInterval(() => {
  const t = Date.now();
  for (const [k, a] of hits) if (!a.some(x => t - x < 3600e3)) hits.delete(k);
}, 600e3).unref();

/* ---------- App ---------- */
const app = express();
app.disable('x-powered-by');
if (process.env.TRUST_PROXY) app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? 1 : process.env.TRUST_PROXY);

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin'
  });
  next();
});
app.use(express.json({ limit: '10kb' }));

// Carga el usuario de la sesión (si existe)
app.use((req, res, next) => {
  const t = getCookie(req, COOKIE);
  if (t) {
    const th = sha(t);
    const u = db.prepare(
      'SELECT u.id, u.name, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?'
    ).get(th, Date.now());
    if (u) { req.user = u; req.tokenHash = th; }
  }
  next();
});
const need = (req, res, next) =>
  req.user ? next() : res.status(401).json({ ok: false, code: 'auth' });

/* ---------- API ---------- */
app.post('/api/register', limit(10, 3600e3), async (req, res) => {
  const b = req.body || {};
  const name = clean(b.name, 80);
  const email = clean(b.email, 254).toLowerCase();
  const pw = typeof b.password === 'string' ? b.password : '';
  if (!name || !EMAIL.test(email) || pw.length < 8 || pw.length > 200 || b.age !== true || b.privacy !== true)
    return res.status(400).json({ ok: false, code: 'inv' });
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email))
    return res.status(409).json({ ok: false, code: 'dup' });
  const h = await hashPassword(pw);
  try {
    db.prepare(
      'INSERT INTO users (name, email, pass_hash, age_declared, privacy_accepted_at, created_at) VALUES (?,?,?,?,?,?)'
    ).run(name, email, h, 1, now(), now());
  } catch (e) {
    if (String(e.code).startsWith('SQLITE_CONSTRAINT')) return res.status(409).json({ ok: false, code: 'dup' });
    throw e;
  }
  res.status(201).json({ ok: true, code: 'done' });
});

app.post('/api/login', limit(10, 15 * 60e3), async (req, res) => {
  const b = req.body || {};
  const email = clean(b.email, 254).toLowerCase();
  const pw = typeof b.password === 'string' ? b.password.slice(0, 200) : '';
  const u = db.prepare('SELECT id, name, pass_hash FROM users WHERE email = ?').get(email);
  const ok = await verifyPassword(pw, u ? u.pass_hash : await DUMMY);
  if (!u || !ok) return res.status(401).json({ ok: false, code: 'bad' });

  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)')
    .run(sha(token), u.id, Date.now() + SESSION_DAYS * 864e5);
  res.cookie(COOKIE, token, {
    httpOnly: true, sameSite: 'lax', secure: req.secure, path: '/', maxAge: SESSION_DAYS * 864e5
  });
  res.json({ ok: true, user: { name: u.name } });
});

app.post('/api/logout', (req, res) => {
  if (req.tokenHash) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(req.tokenHash);
  res.clearCookie(COOKIE, { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  res.json({ ok: true, user: req.user ? { name: req.user.name, email: req.user.email } : null });
});

app.get('/api/tickets', need, (req, res) => {
  const tickets = db.prepare(
    'SELECT id, message, status, created_at FROM tickets WHERE user_id = ? ORDER BY id DESC LIMIT 20'
  ).all(req.user.id);
  res.json({ ok: true, tickets });
});

app.post('/api/tickets', need, limit(20, 3600e3), (req, res) => {
  const message = clean((req.body || {}).message, 1000);
  if (!message) return res.status(400).json({ ok: false, code: 'inv' });
  const r = db.prepare('INSERT INTO tickets (user_id, message, created_at) VALUES (?,?,?)')
    .run(req.user.id, message, now());
  res.status(201).json({ ok: true, id: Number(r.lastInsertRowid) });
});

app.post('/api/contact', limit(5, 15 * 60e3), (req, res) => {
  const b = req.body || {};
  const name = clean(b.name, 80), email = clean(b.email, 254), message = clean(b.message, 2000);
  if (!name || !EMAIL.test(email) || !message) return res.status(400).json({ ok: false, code: 'inv' });
  db.prepare('INSERT INTO contact_messages (name, email, message, created_at) VALUES (?,?,?,?)')
    .run(name, email, message, now());
  res.status(201).json({ ok: true });
});

app.use('/api', (req, res) => res.status(404).json({ ok: false, code: 'nf' }));

/* ---------- Web estática ---------- */
app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large')
    return res.status(400).json({ ok: false, code: 'inv' });
  console.error(err);
  res.status(500).json({ ok: false, code: 'err' });
});

app.listen(PORT, () => console.log(`PrimaZet en http://localhost:${PORT}  (BD: ${DB_PATH})`));
