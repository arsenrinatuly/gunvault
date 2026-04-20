require('dotenv').config();
const express   = require('express');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');
const path      = require('path');
const crypto    = require('crypto');
const rateLimit = require('express-rate-limit');
const { stmts, upsertLeadFromUser, all, one, run, ready } = require('./db');
const mailer    = require('./mailer');

const app = express();

// Optional Sentry (no-op if DSN not set, env-gated)
let Sentry = null;
if (process.env.SENTRY_DSN) {
  try {
    Sentry = require('@sentry/node');
    Sentry.init({ dsn: process.env.SENTRY_DSN, tracesSampleRate: 0.1, environment: process.env.NODE_ENV || 'development' });
  } catch { /* @sentry/node not installed — silent */ }
}

// Fail hard in production if secrets are not set
if (process.env.NODE_ENV === 'production') {
  if (!process.env.JWT_SECRET)     { console.error('FATAL: JWT_SECRET env var not set'); process.exit(1); }
  if (!process.env.ADMIN_PASSWORD) { console.error('FATAL: ADMIN_PASSWORD env var not set'); process.exit(1); }
}
const JWT_SECRET = process.env.JWT_SECRET || 'dev_only_secret_not_for_production';
const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'dev_admin_only';

// Trust Vercel's proxy (required for correct IP + rate limiting)
app.set('trust proxy', 1);

const allowedOrigins = [
  'http://localhost:3000',
  'https://boundstack.vercel.app',
  'https://www.boundstack.org',
  'https://boundstack.org',
  process.env.APP_URL,
].filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    // allow server-to-server (no origin) and allowed list
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Wait for schema before handling requests
app.use(async (req, res, next) => {
  try { await ready; next(); } catch { next(); }
});

// ─── Rate limiting ────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  message: { error: 'Too many attempts. Please wait 15 minutes.' },
  standardHeaders: true, legacyHeaders: false,
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, max: 200,
  message: { error: 'Too many requests.' },
});
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 50,
  message: { error: 'Too many admin requests. Wait 15 minutes.' },
  standardHeaders: true, legacyHeaders: false,
});
app.use('/api/', apiLimiter);
app.use('/api/admin/', adminLimiter);
app.use('/api/signin', authLimiter);
app.use('/api/signup', authLimiter);
app.use('/api/forgot-password', authLimiter);

// ─── Middleware ───────────────────────────────
function requireAuth(req, res, next) {
  const h = req.headers['authorization'];
  if (!h) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(h.split(' ')[1], JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}
function requireAdmin(req, res, next) {
  if (req.headers['x-admin-password'] !== ADMIN_PASS)
    return res.status(403).json({ error: 'Forbidden' });
  next();
}
function isEmail(s) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s); }
function ok(s)      { return typeof s === 'string' && s.trim().length > 0; }
function getIP(req) { return req.ip || req.connection?.remoteAddress || 'unknown'; }
function isDupe(e)  { return e.code === '23505'; } // PostgreSQL unique_violation

const PLAN_ORDER = ['free', 'starter', 'pro'];
const PLAN_RULES = {
  free: {
    firearmsLimit: 500,
    locationLimit: 1,
    pos: false,
    gunShow: false,
    ai4473: false,
    aiCompliance: false,
    readiness: false,
    migration: false,
    multiLocation: false,
    esign4473: false,
  },
  starter: {
    firearmsLimit: null,
    locationLimit: 1,
    pos: true,
    gunShow: true,
    ai4473: false,
    aiCompliance: false,
    readiness: false,
    migration: false,
    multiLocation: false,
    esign4473: true,
  },
  pro: {
    firearmsLimit: null,
    locationLimit: null,
    pos: true,
    gunShow: true,
    ai4473: true,
    aiCompliance: true,
    readiness: true,
    migration: true,
    multiLocation: true,
    esign4473: true,
  },
};

function normalizePlan(plan) {
  return PLAN_RULES[plan] ? plan : 'free';
}

function getPlanRules(plan) {
  return PLAN_RULES[normalizePlan(plan)];
}

function hasPlan(plan, requiredPlan) {
  return PLAN_ORDER.indexOf(normalizePlan(plan)) >= PLAN_ORDER.indexOf(normalizePlan(requiredPlan));
}

async function getCurrentUserRecord(req) {
  if (!req.currentUserRecord) {
    req.currentUserRecord = await stmts.getUserById(req.user.id);
    if (req.currentUserRecord) req.currentUserRecord.plan = normalizePlan(req.currentUserRecord.plan);
  }
  return req.currentUserRecord;
}

function planError(res, message, requiredPlan) {
  return res.status(403).json({ error: message, upgrade: true, required_plan: requiredPlan });
}

async function requireFeature(req, res, featureKey, requiredPlan, message) {
  const user = await getCurrentUserRecord(req);
  if (!user) {
    res.status(401).json({ error: 'Unauthorized' });
    return null;
  }
  if (!getPlanRules(user.plan)[featureKey]) {
    planError(res, message, requiredPlan);
    return null;
  }
  return user;
}

function escHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function audit(req, tableName, recordId, action, oldData, newData) {
  stmts.addAudit({
    user_id:    req.user?.id || 0,
    table_name: tableName,
    record_id:  recordId || null,
    action,
    old_data: oldData ? JSON.stringify(oldData) : null,
    new_data: newData ? JSON.stringify(newData) : null,
    ip_address: getIP(req)
  }).catch(() => {}); // fire-and-forget, non-critical
}

// ═══════════════════════════════════════════════════════
//  AUTH
// ═══════════════════════════════════════════════════════

app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password, ffl_number, current_software, plan } = req.body;
    if (!ok(name))                            return res.status(400).json({ error: 'Name is required' });
    if (!isEmail(email))                      return res.status(400).json({ error: 'Enter a valid email address' });
    if (!ok(password) || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const existing = await stmts.getUserByEmail(email.toLowerCase().trim());
    if (existing) return res.status(409).json({ error: 'An account with this email already exists' });

    const allowedPlans = ['free', 'starter', 'pro'];
    const selectedPlan = allowedPlans.includes(plan) ? plan : 'free';
    const hash = await bcrypt.hash(password, 12);
    const user = await stmts.createUser({
      name: name.trim(), email: email.toLowerCase().trim(),
      password_hash: hash, ffl_number: ffl_number || null, current_software: current_software || null, plan: selectedPlan
    });

    // 14-day Pro trial + unique referral code
    const refCode = crypto.randomBytes(4).toString('hex').toUpperCase();
    const trialEnds = new Date(Date.now() + 14 * 86400000).toISOString();
    await run('UPDATE users SET trial_ends_at=$1, referral_code=$2 WHERE id=$3', [trialEnds, refCode, user.id]);

    // Handle referral credit
    const refFrom = (req.body.ref || '').toUpperCase().trim();
    if (refFrom) {
      const referrer = await stmts.getUserByReferralCode(refFrom);
      if (referrer && referrer.id !== user.id) {
        await run('UPDATE users SET referred_by_code=$1 WHERE id=$2', [refFrom, user.id]);
        await stmts.createReferral({ referrer_id: referrer.id, referred_id: user.id });
      }
    }

    upsertLeadFromUser({ ...user, ffl_number, current_software }, 'signup').catch(() => {});
    stmts.addWaitlist({ email: user.email, source: 'signup' }).catch(() => {});

    // Generate 6-digit email verification code
    const verifyCode = String(Math.floor(100000 + Math.random() * 900000));
    const verifyExpires = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 min
    await stmts.setEmailVerifyCode(user.id, verifyCode, verifyExpires);
    await mailer.sendVerificationCode({ name: user.name, email: user.email }, verifyCode).catch(e => console.error('[verify-email]', e));

    res.status(201).json({ needs_verification: true, userId: user.id, email: user.email });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ── Verify email code ─────────────────────────
app.post('/api/verify-email', async (req, res) => {
  try {
    const { userId, code } = req.body;
    if (!userId || !ok(String(code || ''))) return res.status(400).json({ error: 'userId and code required' });
    const user = await stmts.checkVerifyCode(parseInt(userId), String(code).trim());
    if (!user) return res.status(400).json({ error: 'Invalid or expired code. Request a new one.' });
    await stmts.markEmailVerified(user.id);
    await mailer.sendWelcome(user).catch(e => console.error('[welcome-email]', e));
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Email verified!', token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan || 'free', ffl_number: user.ffl_number, onboarding_done: user.onboarding_done } });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ── Resend verification code ──────────────────
app.post('/api/resend-verification', authLimiter, async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId required' });
    const u = await stmts.getVerifyData(parseInt(userId));
    if (!u) return res.status(404).json({ error: 'User not found' });
    if (u.email_verified === 1) return res.status(400).json({ error: 'Email already verified' });
    const verifyCode = String(Math.floor(100000 + Math.random() * 900000));
    const verifyExpires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    await stmts.setEmailVerifyCode(u.id, verifyCode, verifyExpires);
    await mailer.sendVerificationCode({ name: u.name, email: u.email }, verifyCode);
    res.json({ message: 'New code sent' });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!isEmail(email)) return res.status(400).json({ error: 'Valid email required' });
    if (!ok(password))   return res.status(400).json({ error: 'Password required' });
    const u = await stmts.getUserByEmail(email.toLowerCase().trim());
    if (!u) return res.status(401).json({ error: 'Invalid email or password' });
    const valid = await bcrypt.compare(password, u.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ id: u.id, email: u.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Signed in!', token, user: { id: u.id, name: u.name, email: u.email, plan: u.plan, ffl_number: u.ffl_number, onboarding_done: u.onboarding_done } });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ── Forgot / Reset password ──────────────────
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!isEmail(email)) return res.status(400).json({ error: 'Valid email required' });
    // IMPORTANT: do all work BEFORE responding — Vercel kills function after res.json()
    const u = await stmts.getUserByEmail(email.toLowerCase().trim());
    if (u) {
      const token   = crypto.randomBytes(32).toString('hex');
      const expires = new Date(Date.now() + 3600000).toISOString();
      await stmts.cleanOldTokens();
      await stmts.createResetToken({ user_id: u.id, token, expires_at: expires });
      await mailer.sendPasswordReset(u, token);
    }
    res.json({ message: 'If that email exists, a reset link has been sent.' });
  } catch(e) { console.error('[forgot-password]', e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!ok(token))                           return res.status(400).json({ error: 'Token required' });
    if (!ok(password) || password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
    const record = await stmts.getResetToken(token);
    if (!record) return res.status(400).json({ error: 'Invalid or expired reset link' });
    const hash = await bcrypt.hash(password, 12);
    await stmts.updatePassword({ password_hash: hash, id: record.user_id });
    await stmts.markTokenUsed(token);
    res.json({ message: 'Password updated! You can now sign in.' });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ═══════════════════════════════════════════════════════
//  USER APP — /api/app/*
// ═══════════════════════════════════════════════════════

app.get('/api/app/me', requireAuth, async (req, res) => {
  try {
    const u = await stmts.getUserById(req.user.id);
    if (!u) return res.status(404).json({ error: 'User not found' });
    res.json({ user: u });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/app/me', requireAuth, async (req, res) => {
  try {
    const { name, phone, shop_name, ffl_number } = req.body;
    await stmts.updateUser({ name: name || '', phone: phone || '', shop_name: shop_name || '', ffl_number: ffl_number || '', id: req.user.id });
    audit(req, 'users', req.user.id, 'UPDATE_PROFILE', null, { name, phone, shop_name, ffl_number });
    res.json({ message: 'Profile updated' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/app/password', requireAuth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!ok(current_password)) return res.status(400).json({ error: 'Current password required' });
    if (!ok(new_password) || new_password.length < 6) return res.status(400).json({ error: 'New password min 6 chars' });
    const u = await stmts.getUserByEmail(req.user.email);
    if (!u) return res.status(404).json({ error: 'User not found' });
    const valid = await bcrypt.compare(current_password, u.password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
    const hash = await bcrypt.hash(new_password, 12);
    await stmts.updatePassword({ password_hash: hash, id: req.user.id });
    res.json({ message: 'Password changed successfully' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/app/onboarding/complete', requireAuth, async (req, res) => {
  try { await stmts.completeOnboard(req.user.id); res.json({ message: 'Done' }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/app/dashboard', requireAuth, async (req, res) => {
  try {
    const uid = req.user.id;
    const [f, c, u, byType, byMonth, top5mfr, salesStats] = await Promise.all([
      stmts.countFirearms(uid),
      stmts.countCustomers(uid),
      stmts.getUserById(uid),
      all("SELECT type, COUNT(*)::int AS count FROM firearms WHERE user_id=$1 AND disposition_date IS NULL GROUP BY type", [uid]),
      all("SELECT LEFT(acquisition_date,7) AS month, COUNT(*)::int AS count FROM firearms WHERE user_id=$1 AND acquisition_date IS NOT NULL AND acquisition_date!='' GROUP BY month ORDER BY month DESC LIMIT 12", [uid]),
      all("SELECT manufacturer, COUNT(*)::int AS count FROM firearms WHERE user_id=$1 GROUP BY manufacturer ORDER BY count DESC LIMIT 5", [uid]),
      stmts.countSales(uid),
    ]);
    res.json({
      total_firearms:    f?.total        || 0,
      in_inventory:      f?.in_inventory || 0,
      transferred:       (f?.total || 0) - (f?.in_inventory || 0),
      total_customers:   c?.total        || 0,
      plan:              u?.plan,
      onboarding_done:   u?.onboarding_done,
      by_type:           byType,
      by_month:          byMonth,
      top_manufacturers: top5mfr,
      total_sales:       salesStats?.total   || 0,
      total_revenue:     salesStats?.revenue || 0,
    });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ── Global search ────────────────────────────
app.get('/api/app/search', requireAuth, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    if (q.length < 2) return res.json({ firearms: [], customers: [] });
    const like = `%${q}%`;
    const [firearms, customers] = await Promise.all([
      all("SELECT id,manufacturer,model,serial_number,type,caliber,acquisition_date,disposition_date FROM firearms WHERE user_id=$1 AND (manufacturer ILIKE $2 OR model ILIKE $2 OR serial_number ILIKE $2 OR caliber ILIKE $2) LIMIT 10", [req.user.id, like]),
      all("SELECT id,first_name,last_name,email,phone FROM customers WHERE user_id=$1 AND (first_name ILIKE $2 OR last_name ILIKE $2 OR email ILIKE $2 OR phone ILIKE $2) LIMIT 10", [req.user.id, like]),
    ]);
    res.json({ firearms, customers });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── Locations ────────────────────────────────
app.get('/api/app/locations', requireAuth, async (req, res) => {
  try { res.json({ locations: await stmts.getLocations(req.user.id) }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/app/locations', requireAuth, async (req, res) => {
  try {
    const { name, address, ffl_number, is_primary } = req.body;
    if (!ok(name)) return res.status(400).json({ error: 'Location name required' });
    const user = await getCurrentUserRecord(req);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    const rules = getPlanRules(user.plan);
    if (rules.locationLimit != null) {
      const existing = await stmts.getLocations(req.user.id);
      if (existing.length >= rules.locationLimit) {
        return planError(res, 'Multi-location support is available on Pro only.', 'pro');
      }
    }
    if (is_primary) await stmts.setPrimaryLoc(req.user.id);
    const r = await stmts.addLocation({ user_id: req.user.id, name, address: address || null, ffl_number: ffl_number || null, is_primary: is_primary ? 1 : 0 });
    res.status(201).json({ message: 'Location added', id: r.id });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/app/locations/:id', requireAuth, async (req, res) => {
  try {
    const { name, address, ffl_number, is_primary } = req.body;
    if (is_primary) {
      await stmts.setPrimaryLoc(req.user.id);
      await stmts.makePrimaryLoc(req.params.id, req.user.id);
    }
    await stmts.updateLocation({ name, address: address || null, ffl_number: ffl_number || null, id: req.params.id, user_id: req.user.id });
    res.json({ message: 'Updated' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/app/locations/:id', requireAuth, async (req, res) => {
  try { await stmts.deleteLocation(req.params.id, req.user.id); res.json({ message: 'Deleted' }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── Firearms ─────────────────────────────────
app.get('/api/app/firearms', requireAuth, async (req, res) => {
  try { res.json({ firearms: await stmts.getFirearms(req.user.id) }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/app/firearms', requireAuth, async (req, res) => {
  try {
    const { manufacturer, importer, model, serial_number, caliber, type, acquisition_date, acquisition_from, notes, location_id, is_nfa, nfa_type, nfa_form_type, nfa_form_number } = req.body;
    if (!ok(manufacturer)||!ok(model)||!ok(serial_number)||!ok(caliber)||!ok(type)||!ok(acquisition_date)||!ok(acquisition_from))
      return res.status(400).json({ error: 'All required fields must be filled' });
    const u = await getCurrentUserRecord(req);
    if (!u) return res.status(401).json({ error: 'Unauthorized' });
    const rules = getPlanRules(u.plan);
    if (rules.firearmsLimit != null) {
      const cnt = await stmts.countFirearms(req.user.id);
      if (cnt && cnt.total >= rules.firearmsLimit) {
        return res.status(403).json({ error: `Free plan limit reached (${rules.firearmsLimit} A&D records). Upgrade to add more.`, limit: true });
      }
    }
    const r = await stmts.addFirearm({ user_id: req.user.id, location_id: location_id || null, manufacturer, importer: importer || null, model, serial_number, caliber, type, acquisition_date, acquisition_from, notes: notes || null, is_nfa: !!is_nfa, nfa_type: nfa_type || null, nfa_form_type: nfa_form_type || null, nfa_form_number: nfa_form_number || null });
    audit(req, 'firearms', r.id, 'ADD', null, { manufacturer, model, serial_number, caliber, type, acquisition_date });
    res.status(201).json({ message: 'Firearm added', id: r.id });
  } catch(e) {
    if (isDupe(e)) return res.status(409).json({ error: 'Duplicate serial number' });
    console.error(e); res.status(500).json({ error: 'Server error' });
  }
});

// ── Bulk CSV import ──────────────────────────
app.post('/api/app/firearms/import', requireAuth, async (req, res) => {
  try {
    const user = await requireFeature(req, res, 'migration', 'pro', 'CSV migration tools are available on Pro only.');
    if (!user) return;
    const { rows } = req.body;
    if (!Array.isArray(rows) || !rows.length) return res.status(400).json({ error: 'No rows provided' });
    let imported = 0, skipped = 0, errors = [];
    for (const row of rows) {
      try {
        if (!row.manufacturer||!row.model||!row.serial_number||!row.caliber||!row.type||!row.acquisition_date||!row.acquisition_from) { skipped++; continue; }
        await stmts.addFirearm({ user_id: req.user.id, location_id: null, manufacturer: row.manufacturer, importer: row.importer || null, model: row.model, serial_number: row.serial_number, caliber: row.caliber, type: row.type, acquisition_date: row.acquisition_date, acquisition_from: row.acquisition_from, notes: row.notes || null });
        imported++;
      } catch(e) {
        if (isDupe(e)) skipped++;
        else errors.push(`Serial ${row.serial_number}: ${e.message}`);
      }
    }
    audit(req, 'firearms', null, 'BULK_IMPORT', null, { imported, skipped });
    res.json({ message: `Imported ${imported} records. Skipped ${skipped} duplicates.`, imported, skipped, errors: errors.slice(0, 10) });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/app/firearms/:id', requireAuth, async (req, res) => {
  try {
    const { manufacturer, importer, model, serial_number, caliber, type, acquisition_date, acquisition_from, notes, is_nfa, nfa_type, nfa_form_type, nfa_form_number } = req.body;
    if (!ok(manufacturer)||!ok(model)||!ok(serial_number)||!ok(caliber)||!ok(type)||!ok(acquisition_date)||!ok(acquisition_from))
      return res.status(400).json({ error: 'All required fields must be filled' });
    const old = await stmts.getFirearm(req.params.id, req.user.id);
    if (!old) return res.status(404).json({ error: 'Firearm not found' });
    if (old.disposition_date) return res.status(400).json({ error: 'Cannot edit a disposed firearm' });
    await stmts.updateFirearm({ manufacturer, importer: importer || null, model, serial_number, caliber, type, acquisition_date, acquisition_from, notes: notes || null, is_nfa: !!is_nfa, nfa_type: nfa_type || null, nfa_form_type: nfa_form_type || null, nfa_form_number: nfa_form_number || null, id: req.params.id, user_id: req.user.id });
    audit(req, 'firearms', parseInt(req.params.id), 'UPDATE', old, { manufacturer, model, serial_number });
    res.json({ message: 'Firearm updated' });
  } catch(e) {
    if (isDupe(e)) return res.status(409).json({ error: 'Duplicate serial number' });
    console.error(e); res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/app/firearms/:id/dispose', requireAuth, async (req, res) => {
  try {
    const { disposition_date, disposition_to, disposition_customer_id } = req.body;
    if (!ok(disposition_date)||!ok(disposition_to)) return res.status(400).json({ error: 'Date and transferee required' });
    await stmts.disposeFirearm({ disposition_date, disposition_to, disposition_customer_id: disposition_customer_id || null, id: req.params.id, user_id: req.user.id });
    audit(req, 'firearms', parseInt(req.params.id), 'DISPOSE', null, { disposition_date, disposition_to });
    res.json({ message: 'Disposition recorded' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/app/firearms/:id', requireAuth, async (req, res) => {
  try {
    const old = await stmts.getFirearm(req.params.id, req.user.id);
    audit(req, 'firearms', parseInt(req.params.id), 'DELETE', old, null);
    await stmts.deleteFirearm(req.params.id, req.user.id);
    res.json({ message: 'Deleted' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── Customers ─────────────────────────────────
app.get('/api/app/customers', requireAuth, async (req, res) => {
  try { res.json({ customers: await stmts.getCustomers(req.user.id) }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/app/customers', requireAuth, async (req, res) => {
  try {
    const { first_name, last_name, email, phone, address, id_type, id_number, dob, notes } = req.body;
    if (!ok(first_name)||!ok(last_name)) return res.status(400).json({ error: 'Name required' });
    const r = await stmts.addCustomer({ user_id: req.user.id, first_name, last_name, email: email || null, phone: phone || null, address: address || null, id_type: id_type || null, id_number: id_number || null, dob: dob || null, notes: notes || null });
    res.status(201).json({ message: 'Customer added', id: r.id });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/app/customers/:id', requireAuth, async (req, res) => {
  try {
    const { first_name, last_name, email, phone, address, id_type, id_number, dob, notes } = req.body;
    await stmts.updateCustomer({ first_name, last_name, email: email || null, phone: phone || null, address: address || null, id_type: id_type || null, id_number: id_number || null, dob: dob || null, notes: notes || null, id: req.params.id, user_id: req.user.id });
    res.json({ message: 'Updated' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/app/customers/:id', requireAuth, async (req, res) => {
  try { await stmts.deleteCustomer(req.params.id, req.user.id); res.json({ message: 'Deleted' }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── Form 4473 ────────────────────────────────
app.get('/api/app/form4473', requireAuth, async (req, res) => {
  try { res.json({ forms: await stmts.get4473s(req.user.id) }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/app/form4473', requireAuth, async (req, res) => {
  try {
    const d = req.body;
    const user = await getCurrentUserRecord(req);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    const fullName = [d.transferee_last, d.transferee_first, d.transferee_middle].filter(Boolean).join(', ');
    const r = await stmts.add4473({
      user_id:              req.user.id,
      firearm_id:           d.firearm_id          || null,
      customer_id:          d.customer_id         || null,
      transferee_name:      fullName              || d.transferee_name || null,
      transferee_address:   d.transferee_address  || null,
      transferee_city:      d.transferee_city     || null,
      transferee_state:     d.id_state            || d.transferee_state || null,
      transferee_zip:       d.transferee_zip      || null,
      transferee_dob:       d.transferee_dob      || null,
      transferee_id_type:   d.id_type             || d.transferee_id_type || null,
      transferee_id_num:    d.id_number           || d.transferee_id_num  || null,
      transferee_gender:    d.transferee_sex      || d.transferee_gender  || null,
      is_us_citizen:           d.q21k === 'yes' ? 0 : 1,
      is_felon:                d.q21c === 'yes' ? 1 : 0,
      is_fugitive:             d.q21d === 'yes' ? 1 : 0,
      is_drug_user:            d.q21e === 'yes' ? 1 : 0,
      is_mental_health:        d.q21f === 'yes' ? 1 : 0,
      is_domestic_violence:    d.q21i === 'yes' ? 1 : 0,
      is_renounced_citizen:    d.q21j === 'yes' ? 1 : 0,
      is_nonimmigrant_alien:   d.q21l === 'yes' ? 1 : 0,
      signature_data:          getPlanRules(user.plan).esign4473 ? (d.signature_data || null) : null,
      nics_transaction:     d.nics_transaction_number || d.nics_transaction || null,
      nics_result:          d.nics_result         || null,
      transfer_date:        d.transaction_date    || d.transfer_date    || null,
      status:               'pending',
      notes:                d.nics_notes          || d.notes            || null,
    });
    audit(req, 'form_4473', r.id, 'CREATE', null, { transferee: fullName });
    res.status(201).json({ message: 'Form 4473 saved', id: r.id });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/app/form4473/:id', requireAuth, async (req, res) => {
  try {
    const { status, nics_transaction, nics_result, notes } = req.body;
    await stmts.update4473({ status: status || 'pending', nics_transaction: nics_transaction || null, nics_result: nics_result || null, notes: notes || null, id: req.params.id, user_id: req.user.id });
    res.json({ message: 'Form updated' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── Audit log ─────────────────────────────────
app.get('/api/app/audit-log', requireAuth, async (req, res) => {
  try { res.json({ log: await stmts.getAuditLog(req.user.id) }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── Sales / POS ───────────────────────────────
app.get('/api/app/sales', requireAuth, async (req, res) => {
  try {
    const user = await requireFeature(req, res, 'pos', 'starter', 'POS and barcode scanning are available on Starter or Pro.');
    if (!user) return;
    res.json({ sales: await stmts.getSales(req.user.id) });
  }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/app/sales', requireAuth, async (req, res) => {
  try {
    const user = await requireFeature(req, res, 'pos', 'starter', 'POS and barcode scanning are available on Starter or Pro.');
    if (!user) return;
    const { customer_id, firearm_id, sale_date, amount, payment_method, notes } = req.body;
    if (!ok(sale_date)) return res.status(400).json({ error: 'Sale date required' });
    if (isNaN(parseFloat(amount))) return res.status(400).json({ error: 'Valid amount required' });
    const r = await stmts.addSale({ user_id: req.user.id, customer_id: customer_id || null, firearm_id: firearm_id || null, sale_date, amount: parseFloat(amount), payment_method: payment_method || 'cash', notes: notes || null });
    audit(req, 'sales', r.id, 'ADD', null, { sale_date, amount });
    res.status(201).json({ message: 'Sale recorded', id: r.id });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/app/sales/:id', requireAuth, async (req, res) => {
  try {
    const user = await requireFeature(req, res, 'pos', 'starter', 'POS and barcode scanning are available on Starter or Pro.');
    if (!user) return;
    const { customer_id, firearm_id, sale_date, amount, payment_method, notes } = req.body;
    if (!ok(sale_date)) return res.status(400).json({ error: 'Sale date required' });
    await stmts.updateSale({ customer_id: customer_id || null, firearm_id: firearm_id || null, sale_date, amount: parseFloat(amount) || 0, payment_method: payment_method || 'cash', notes: notes || null, id: req.params.id, user_id: req.user.id });
    res.json({ message: 'Updated' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/app/sales/:id', requireAuth, async (req, res) => {
  try {
    const user = await requireFeature(req, res, 'pos', 'starter', 'POS and barcode scanning are available on Starter or Pro.');
    if (!user) return;
    await stmts.deleteSale(req.params.id, req.user.id); res.json({ message: 'Deleted' });
  }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── Layaways ──────────────────────────────────
app.get('/api/app/layaways', requireAuth, async (req, res) => {
  try { res.json({ layaways: await stmts.getLayaways(req.user.id) }); }
  catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/app/layaways', requireAuth, async (req, res) => {
  try {
    const { customer_id, firearm_id, total_amount, amount_paid, installment_amt, next_due_date, notes } = req.body;
    if (!total_amount || isNaN(parseFloat(total_amount))) return res.status(400).json({ error: 'Total amount required' });
    const r = await stmts.addLayaway({
      user_id: req.user.id, customer_id: customer_id||null, firearm_id: firearm_id||null,
      total_amount: parseFloat(total_amount), amount_paid: parseFloat(amount_paid)||0,
      installment_amt: installment_amt ? parseFloat(installment_amt) : null,
      next_due_date: next_due_date||null, notes: notes||null
    });
    res.status(201).json({ message: 'Layaway created', id: r.id });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/app/layaways/:id', requireAuth, async (req, res) => {
  try {
    const { amount_paid, installment_amt, next_due_date, status, notes } = req.body;
    await stmts.updateLayaway({
      id: req.params.id, user_id: req.user.id,
      amount_paid: parseFloat(amount_paid)||0,
      installment_amt: installment_amt ? parseFloat(installment_amt) : null,
      next_due_date: next_due_date||null, status: status||'active', notes: notes||null
    });
    res.json({ message: 'Updated' });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/app/layaways/:id', requireAuth, async (req, res) => {
  try { await stmts.deleteLayaway(req.params.id, req.user.id); res.json({ message: 'Deleted' }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/app/layaways/:id/remind', requireAuth, async (req, res) => {
  try {
    const lay = await stmts.getLayaway(req.params.id, req.user.id);
    if (!lay) return res.status(404).json({ error: 'Not found' });
    if (!lay.customer_email) return res.status(400).json({ error: 'Customer has no email address' });
    const u = await stmts.getUserById(req.user.id);
    const shopName = u.shop_name || u.name;
    const firearmDesc = lay.manufacturer ? `${lay.manufacturer} ${lay.model} (S/N: ${lay.serial_number})` : 'Firearm';
    await mailer.sendLayawayReminder({
      shopName, customerName: `${lay.first_name} ${lay.last_name}`,
      customerEmail: lay.customer_email, firearmDesc,
      totalAmount: lay.total_amount, amountPaid: lay.amount_paid,
      installmentAmt: lay.installment_amt, nextDueDate: lay.next_due_date || 'See shop'
    });
    res.json({ message: 'Reminder sent to ' + lay.customer_email });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ── Work Orders (Gunsmithing) ─────────────────
app.get('/api/app/work-orders', requireAuth, async (req, res) => {
  try {
    res.json({ work_orders: await stmts.getWorkOrders(req.user.id) });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/app/work-orders', requireAuth, async (req, res) => {
  try {
    const { customer_id, firearm_manufacturer, firearm_model, firearm_serial,
            description, status, estimated_price, actual_price,
            received_date, promised_date, completed_date, notes } = req.body;
    if (!ok(description))    return res.status(400).json({ error: 'Description required' });
    if (!ok(received_date))  return res.status(400).json({ error: 'Received date required' });
    const r = await stmts.addWorkOrder({
      user_id: req.user.id,
      customer_id: customer_id || null,
      firearm_manufacturer: firearm_manufacturer || null,
      firearm_model: firearm_model || null,
      firearm_serial: firearm_serial || null,
      description,
      status: status || 'received',
      estimated_price: estimated_price || null,
      actual_price: actual_price || null,
      received_date,
      promised_date: promised_date || null,
      completed_date: completed_date || null,
      notes: notes || null,
    });
    audit(req, 'work_orders', r.id, 'CREATE', null, { description, received_date });
    res.status(201).json({ message: 'Work order created', id: r.id });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/app/work-orders/:id', requireAuth, async (req, res) => {
  try {
    const { status, actual_price, promised_date, completed_date, notes } = req.body;
    const old = await stmts.getWorkOrder(req.params.id, req.user.id);
    if (!old) return res.status(404).json({ error: 'Work order not found' });
    await stmts.updateWorkOrder({
      status: status || old.status,
      actual_price: actual_price !== undefined ? actual_price : old.actual_price,
      promised_date: promised_date !== undefined ? promised_date : old.promised_date,
      completed_date: completed_date !== undefined ? completed_date : old.completed_date,
      notes: notes !== undefined ? notes : old.notes,
      id: req.params.id,
      user_id: req.user.id,
    });
    audit(req, 'work_orders', parseInt(req.params.id), 'UPDATE', old, { status, actual_price });
    res.json({ message: 'Work order updated' });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/app/work-orders/:id', requireAuth, async (req, res) => {
  try {
    const old = await stmts.getWorkOrder(req.params.id, req.user.id);
    if (!old) return res.status(404).json({ error: 'Work order not found' });
    audit(req, 'work_orders', parseInt(req.params.id), 'DELETE', old, null);
    await stmts.deleteWorkOrder(req.params.id, req.user.id);
    res.json({ message: 'Deleted' });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ── Inventory Alerts ──────────────────────────
app.get('/api/app/inventory-alerts', requireAuth, async (req, res) => {
  try {
    const uid = req.user.id;
    const [slow_movers, high_value_disposed, recent_acquisitions] = await Promise.all([
      all(
        `SELECT id, manufacturer, model, serial_number, caliber, type, acquisition_date, notes
         FROM firearms
         WHERE user_id=$1
           AND disposition_date IS NULL
           AND acquisition_date IS NOT NULL
           AND acquisition_date != ''
           AND acquisition_date::date <= NOW() - INTERVAL '90 days'
         ORDER BY acquisition_date ASC`,
        [uid]
      ),
      all(
        `SELECT id, manufacturer, model, serial_number, disposition_date, disposition_to
         FROM firearms
         WHERE user_id=$1
           AND disposition_date IS NOT NULL
           AND disposition_date != ''
           AND disposition_date::date >= NOW() - INTERVAL '30 days'
         ORDER BY disposition_date DESC`,
        [uid]
      ),
      all(
        `SELECT id, manufacturer, model, serial_number, caliber, type, acquisition_date
         FROM firearms
         WHERE user_id=$1
           AND acquisition_date IS NOT NULL
           AND acquisition_date != ''
           AND acquisition_date::date >= NOW() - INTERVAL '7 days'
         ORDER BY acquisition_date DESC`,
        [uid]
      ),
    ]);
    res.json({
      slow_movers,
      recent_count:  recent_acquisitions.length,
      disposed_30d:  high_value_disposed.length,
    });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ── NICS Status Update ────────────────────────
app.patch('/api/app/form4473/:id/nics', requireAuth, async (req, res) => {
  try {
    const { nics_transaction, nics_result, nics_checked_at } = req.body;
    const form = await stmts.get4473(req.params.id, req.user.id);
    if (!form) return res.status(404).json({ error: 'Form not found' });
    await run(
      `UPDATE form_4473
       SET nics_transaction=$1, nics_result=$2, nics_checked_at=$3
       WHERE id=$4 AND user_id=$5`,
      [nics_transaction || form.nics_transaction,
       nics_result      || form.nics_result,
       nics_checked_at  || null,
       req.params.id, req.user.id]
    );
    audit(req, 'form_4473', parseInt(req.params.id), 'NICS_UPDATE', null,
      { nics_transaction, nics_result, nics_checked_at });
    res.json({ message: 'NICS status updated' });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ── AI Compliance Checker ─────────────────────
app.post('/api/app/compliance-check', requireAuth, async (req, res) => {
  try {
    const user = await requireFeature(req, res, 'aiCompliance', 'pro', 'AI compliance checks are available on Pro only.');
    if (!user) return;
    const { type } = req.body;
    if (!['adbook', '4473', 'full'].includes(type))
      return res.status(400).json({ error: 'type must be adbook, 4473, or full' });

    const anthropicKey = (process.env.ANTHROPIC_API_KEY || '').trim();
    if (!anthropicKey) {
      return res.status(503).json({ error: 'AI compliance requires an Anthropic API key. Add ANTHROPIC_API_KEY to your environment variables.' });
    }

    const uid = req.user.id;
    let dataForAI = {};

    if (type === 'adbook' || type === 'full') {
      dataForAI.firearms = await stmts.getFirearms(uid);
    }
    if (type === '4473' || type === 'full') {
      dataForAI.forms_4473 = await stmts.get4473s(uid);
    }

    const recordCount = (dataForAI.firearms?.length || 0) + (dataForAI.forms_4473?.length || 0);
    if (recordCount === 0)
      return res.json({ issues: [], summary: 'No records found to check.' });

    // Build prompt
    let prompt = `You are an ATF compliance expert reviewing FFL dealer records. Analyze the following data for ATF compliance issues.\n\n`;

    if (dataForAI.firearms?.length) {
      prompt += `A&D BOUND BOOK RECORDS (${dataForAI.firearms.length} firearms):\n`;
      prompt += JSON.stringify(dataForAI.firearms.map(f => ({
        id: f.id,
        manufacturer: f.manufacturer,
        importer: f.importer,
        model: f.model,
        serial_number: f.serial_number,
        caliber: f.caliber,
        type: f.type,
        acquisition_date: f.acquisition_date,
        acquisition_from: f.acquisition_from,
        disposition_date: f.disposition_date,
        disposition_to: f.disposition_to,
        is_nfa: f.is_nfa,
        nfa_type: f.nfa_type,
      })), null, 2);
      prompt += '\n\n';
    }

    if (dataForAI.forms_4473?.length) {
      prompt += `FORM 4473 RECORDS (${dataForAI.forms_4473.length} forms):\n`;
      prompt += JSON.stringify(dataForAI.forms_4473.map(f => ({
        id: f.id,
        transferee_name: f.transferee_name,
        transferee_dob: f.transferee_dob,
        transferee_id_type: f.transferee_id_type,
        transferee_id_num: f.transferee_id_num,
        is_felon: f.is_felon,
        is_fugitive: f.is_fugitive,
        is_drug_user: f.is_drug_user,
        is_mental_health: f.is_mental_health,
        is_domestic_violence: f.is_domestic_violence,
        nics_transaction: f.nics_transaction,
        nics_result: f.nics_result,
        transfer_date: f.transfer_date,
        firearm_serial: f.serial_number,
        status: f.status,
      })), null, 2);
      prompt += '\n\n';
    }

    prompt += `Check for these issues:
1. Missing required fields (manufacturer, model, serial number, caliber, type, acquisition date/from, disposition info)
2. Suspicious or invalid serial numbers (all zeros, too short, all same digit)
3. Date order issues (disposition before acquisition, future acquisition dates)
4. Disposition recorded without a corresponding acquisition
5. Form 4473 missing transferee name, DOB, or ID information
6. Form 4473 with prohibited-person flags (felon, fugitive, etc.) that still show completed transfer
7. Missing NICS transaction numbers for completed transfers
8. NFA items missing required form information

Return a JSON object with this exact structure:
{
  "issues": [
    { "severity": "high"|"medium"|"low", "field": "field_name_or_record_id", "message": "description of the issue" }
  ],
  "summary": "overall compliance summary in 1-2 sentences"
}

Return ONLY the JSON object, no other text.`;

    // Dynamic require to avoid startup errors if SDK not yet installed
    const Anthropic = require('@anthropic-ai/sdk');
    const client = new Anthropic({ apiKey: anthropicKey });

    const message = await client.messages.create({
      model: 'claude-3-5-haiku-20241022',
      max_tokens: 1024,
      messages: [{ role: 'user', content: prompt }],
    });

    const rawText = message.content[0]?.text || '{}';
    let parsed;
    try {
      // Strip any markdown code fences if present
      const cleaned = rawText.replace(/^```(?:json)?\n?/i, '').replace(/\n?```$/i, '').trim();
      parsed = JSON.parse(cleaned);
    } catch {
      parsed = { issues: [], summary: 'Compliance check completed. Unable to parse detailed results.' };
    }

    audit(req, 'compliance_check', null, 'AI_CHECK', null, { type, record_count: recordCount });
    res.json({
      issues:  Array.isArray(parsed.issues)  ? parsed.issues  : [],
      summary: typeof parsed.summary === 'string' ? parsed.summary : 'Check complete.',
    });
  } catch(e) {
    console.error('Compliance check error:', e);
    res.status(500).json({ error: 'Compliance check failed. Please try again.' });
  }
});

// ═══════════════════════════════════════════════════════
//  PHASE 2 — POS, Importers, AI Validate, Readiness,
//            Referrals, Sync, Multi-sale, Onboarding step
// ═══════════════════════════════════════════════════════

// ── POS Checkout (real multi-item transaction with split tender) ──
app.post('/api/app/pos/checkout', requireAuth, async (req, res) => {
  try {
    const user = await requireFeature(req, res, 'pos', 'starter', 'POS and barcode scanning are available on Starter or Pro.');
    if (!user) return;
    const { customer_id, items, tax, tender, notes } = req.body;
    if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'Cart is empty' });

    let subtotal = 0;
    const validated = [];
    for (const it of items) {
      const price = parseFloat(it.price || 0);
      const qty   = parseInt(it.qty || 1, 10);
      if (isNaN(price) || isNaN(qty) || qty < 1) return res.status(400).json({ error: 'Invalid line item' });
      subtotal += price * qty;
      validated.push({ sku: it.sku || null, firearm_id: it.firearm_id || null, description: it.description || '', qty, price });
    }
    const taxAmt = parseFloat(tax || 0) || 0;
    const total  = subtotal + taxAmt;

    // tender = [{method:'cash',amount:N}, {method:'card',amount:N}]
    const tenderArr = Array.isArray(tender) ? tender : [];
    const paidTotal = tenderArr.reduce((s, t) => s + (parseFloat(t.amount) || 0), 0);
    if (paidTotal + 0.01 < total) return res.status(400).json({ error: `Under-tender: paid ${paidTotal.toFixed(2)}, total ${total.toFixed(2)}` });

    const receiptNo = 'R' + Date.now().toString(36).toUpperCase();
    const txn = await stmts.addPosTxn({
      user_id: req.user.id, customer_id: customer_id || null,
      items: JSON.stringify(validated), subtotal, tax: taxAmt, total,
      tender: JSON.stringify(tenderArr), receipt_no: receiptNo, notes: notes || null,
    });

    // Auto-dispose any firearm line items + record a sale row
    for (const it of validated) {
      if (it.firearm_id) {
        try {
          await stmts.disposeFirearm({
            disposition_date: new Date().toISOString().slice(0,10),
            disposition_to: 'POS sale',
            disposition_customer_id: customer_id || null,
            id: it.firearm_id, user_id: req.user.id,
          });
        } catch {}
        try {
          await stmts.addSale({
            user_id: req.user.id, customer_id: customer_id || null,
            firearm_id: it.firearm_id,
            sale_date: new Date().toISOString().slice(0,10),
            amount: it.price * it.qty,
            payment_method: (tenderArr[0]?.method) || 'cash',
            notes: `POS ${receiptNo}`,
          });
        } catch {}
      }
    }

    audit(req, 'pos_transactions', txn.id, 'CHECKOUT', null, { receiptNo, total, items: validated.length });
    res.status(201).json({ message: 'Transaction complete', id: txn.id, receipt_no: receiptNo, subtotal, tax: taxAmt, total });
  } catch(e) { console.error(e); res.status(500).json({ error: 'POS checkout failed' }); }
});

app.get('/api/app/pos/history', requireAuth, async (req, res) => {
  try {
    const user = await requireFeature(req, res, 'pos', 'starter', 'POS and barcode scanning are available on Starter or Pro.');
    if (!user) return;
    res.json({ txns: await stmts.getPosTxns(req.user.id) });
  }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── Migration importers — FastBound, Orchid eBound, Bravo ──
// Accepts either { csv: "<raw csv text>", format: 'fastbound'|'orchid'|'bravo' }
// or already-parsed { rows:[...], format }
function parseCSV(text) {
  const lines = text.split(/\r?\n/).filter(l => l.trim());
  if (!lines.length) return [];
  const parse = (line) => {
    const out = []; let cur = ''; let inQ = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (inQ) {
        if (c === '"' && line[i+1] === '"') { cur += '"'; i++; }
        else if (c === '"') inQ = false;
        else cur += c;
      } else {
        if (c === '"') inQ = true;
        else if (c === ',') { out.push(cur); cur = ''; }
        else cur += c;
      }
    }
    out.push(cur);
    return out;
  };
  const headers = parse(lines[0]).map(h => h.trim().toLowerCase());
  return lines.slice(1).map(l => {
    const vals = parse(l);
    const obj = {};
    headers.forEach((h, i) => obj[h] = (vals[i] || '').trim());
    return obj;
  });
}

// Vendor-specific field mappers
const IMPORTERS = {
  fastbound: (r) => ({
    manufacturer: r.manufacturer || r.make || '',
    importer:     r.importer || '',
    model:        r.model || '',
    serial_number: r.serial || r.serial_number || r['serial number'] || '',
    caliber:      r.caliber || r.cal || '',
    type:         r.type || r['firearm type'] || 'Unknown',
    acquisition_date: r['acquisition date'] || r.acq_date || r.acquisition_date || '',
    acquisition_from: r['acquired from'] || r.acquisition_from || r.source || '',
    notes: r.notes || '',
  }),
  orchid: (r) => ({
    manufacturer: r.mfr || r.manufacturer || r['manufacturer name'] || '',
    importer:     r.importer || '',
    model:        r.model || r['model name'] || '',
    serial_number: r['serial #'] || r.serial || r.serial_number || '',
    caliber:      r.caliber || r.gauge || '',
    type:         r['firearm type'] || r.type || 'Unknown',
    acquisition_date: r['date acquired'] || r.acquisition_date || '',
    acquisition_from: r['name and address'] || r.source || r.acquisition_from || '',
    notes: r.notes || '',
  }),
  bravo: (r) => ({
    manufacturer: r.manufacturer || r.mfr || '',
    importer:     r.importer || '',
    model:        r.model || '',
    serial_number: r.serial_number || r.serial || '',
    caliber:      r.caliber || '',
    type:         r.category || r.type || 'Unknown',
    acquisition_date: r.received_date || r.acquisition_date || '',
    acquisition_from: r.vendor || r.acquisition_from || '',
    notes: r.notes || '',
  }),
  generic: (r) => ({
    manufacturer: r.manufacturer || '', importer: r.importer || '',
    model: r.model || '', serial_number: r.serial_number || '',
    caliber: r.caliber || '', type: r.type || '',
    acquisition_date: r.acquisition_date || '',
    acquisition_from: r.acquisition_from || '', notes: r.notes || '',
  }),
};

// Dry-run (validate only, show errors, don't commit)
app.post('/api/app/import/dry-run', requireAuth, async (req, res) => {
  try {
    const user = await requireFeature(req, res, 'migration', 'pro', 'CSV migration tools are available on Pro only.');
    if (!user) return;
    const { csv, format, rows: preRows } = req.body;
    const fmt = IMPORTERS[format] ? format : 'generic';
    const mapper = IMPORTERS[fmt];
    const raw = Array.isArray(preRows) ? preRows : (csv ? parseCSV(csv) : []);
    if (!raw.length) return res.status(400).json({ error: 'No rows to import' });

    const preview = [], errors = [];
    raw.forEach((r, i) => {
      const mapped = mapper(r);
      const missing = ['manufacturer','model','serial_number','caliber','type','acquisition_date','acquisition_from']
        .filter(k => !mapped[k]);
      if (missing.length) errors.push({ row: i + 2, missing });
      preview.push(mapped);
    });
    res.json({ format: fmt, total: raw.length, preview: preview.slice(0, 20), errors: errors.slice(0, 50), ok: raw.length - errors.length });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Dry-run failed' }); }
});

// Commit import
app.post('/api/app/import/commit', requireAuth, async (req, res) => {
  try {
    const user = await requireFeature(req, res, 'migration', 'pro', 'CSV migration tools are available on Pro only.');
    if (!user) return;
    const { csv, format, rows: preRows } = req.body;
    const fmt = IMPORTERS[format] ? format : 'generic';
    const mapper = IMPORTERS[fmt];
    const raw = Array.isArray(preRows) ? preRows : (csv ? parseCSV(csv) : []);
    if (!raw.length) return res.status(400).json({ error: 'No rows to import' });

    let imported = 0, skipped = 0, errors = [];
    for (const r of raw) {
      const m = mapper(r);
      if (!m.manufacturer || !m.model || !m.serial_number || !m.caliber || !m.type || !m.acquisition_date || !m.acquisition_from) { skipped++; continue; }
      try {
        await stmts.addFirearm({ user_id: req.user.id, location_id: null, ...m, is_nfa: false });
        imported++;
      } catch(e) {
        if (isDupe(e)) skipped++;
        else errors.push(`Serial ${m.serial_number}: ${e.message}`);
      }
    }
    audit(req, 'firearms', null, 'MIGRATION_IMPORT', null, { format: fmt, imported, skipped });
    res.json({ message: `Imported ${imported}, skipped ${skipped}.`, imported, skipped, errors: errors.slice(0, 10), format: fmt });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Import failed' }); }
});

// ── AI Pre-submit 4473 Validation ──
app.post('/api/app/validate-4473', requireAuth, async (req, res) => {
  try {
    const user = await requireFeature(req, res, 'ai4473', 'pro', 'AI 4473 pre-submit validation is available on Pro only.');
    if (!user) return;
    const d = req.body || {};
    // Local sanity checks (don't need AI for these)
    const issues = [];
    if (!d.transferee_first && !d.transferee_last) issues.push({ severity: 'high', field: 'name', message: 'Transferee name is required.' });
    if (!d.transferee_dob) issues.push({ severity: 'high', field: 'dob', message: 'Date of birth is required.' });
    else {
      const dob = new Date(d.transferee_dob);
      if (isNaN(dob.getTime())) issues.push({ severity: 'high', field: 'dob', message: 'DOB is not a valid date.' });
      else {
        const age = (Date.now() - dob.getTime()) / (365.25 * 86400000);
        if (age < 18) issues.push({ severity: 'high', field: 'dob', message: `Transferee is under 18 (${age.toFixed(1)} yrs).` });
        if (age < 21 && d.firearm_type === 'Handgun') issues.push({ severity: 'high', field: 'dob', message: 'Handgun transfer requires age 21+.' });
      }
    }
    if (!d.id_number) issues.push({ severity: 'high', field: 'id_number', message: 'Government ID number is required.' });
    if (!d.transferee_address) issues.push({ severity: 'medium', field: 'address', message: 'Address is required.' });
    if (d.q21c === 'yes' || d.q21d === 'yes' || d.q21e === 'yes' || d.q21f === 'yes' || d.q21i === 'yes') {
      issues.push({ severity: 'high', field: 'prohibited', message: 'Transferee indicates a prohibited-person status. Transfer must be denied.' });
    }
    if (d.firearm_id) {
      const fa = await stmts.getFirearm(d.firearm_id, req.user.id);
      if (!fa) issues.push({ severity: 'high', field: 'firearm_id', message: 'Selected firearm not found in your inventory.' });
      else if (fa.disposition_date) issues.push({ severity: 'high', field: 'firearm_id', message: 'Selected firearm has already been disposed.' });
    }

    // AI pass (optional, only if key present and enough fields)
    let aiSummary = null, aiIssues = [];
    if (process.env.ANTHROPIC_API_KEY && issues.length < 5) {
      try {
        const Anthropic = require('@anthropic-ai/sdk');
        const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
        const prompt = `You are an ATF compliance reviewer. Check this Form 4473 entry for problems BEFORE the dealer submits it. Return strict JSON only: {"issues":[{"severity":"high"|"medium"|"low","field":"...","message":"..."}],"summary":"1-2 sentences"}. Data:\n` + JSON.stringify({
          name: [d.transferee_first, d.transferee_middle, d.transferee_last].filter(Boolean).join(' '),
          dob: d.transferee_dob, address: d.transferee_address, city: d.transferee_city, state: d.id_state, zip: d.transferee_zip,
          id_type: d.id_type, id_number: d.id_number, sex: d.transferee_sex,
          answers: { c: d.q21c, d: d.q21d, e: d.q21e, f: d.q21f, i: d.q21i, j: d.q21j, k: d.q21k, l: d.q21l },
          nics_transaction: d.nics_transaction_number, nics_result: d.nics_result,
        });
        const m = await client.messages.create({ model: 'claude-3-5-haiku-20241022', max_tokens: 512, messages: [{ role: 'user', content: prompt }] });
        const txt = (m.content[0]?.text || '{}').replace(/^```(?:json)?\n?/i, '').replace(/\n?```$/, '').trim();
        const parsed = JSON.parse(txt);
        if (Array.isArray(parsed.issues)) aiIssues = parsed.issues;
        aiSummary = parsed.summary || null;
      } catch(e) { /* AI optional */ }
    }

    res.json({ issues: [...issues, ...aiIssues], summary: aiSummary || (issues.length ? 'Local checks found issues.' : 'All local checks passed.'), ready: issues.filter(i => i.severity === 'high').length === 0 });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Validation failed' }); }
});

// ── Inspection Readiness Score ──
app.get('/api/app/readiness-score', requireAuth, async (req, res) => {
  try {
    const user = await requireFeature(req, res, 'readiness', 'pro', 'Inspection readiness score is available on Pro only.');
    if (!user) return;
    const uid = req.user.id;
    const [firearms, forms, u] = await Promise.all([
      stmts.getFirearms(uid), stmts.get4473s(uid), stmts.getUserById(uid),
    ]);
    const checks = [];
    // 1. Required user fields
    checks.push({ id: 'ffl', weight: 10, label: 'FFL number on file',    pass: !!u.ffl_number });
    checks.push({ id: 'shop', weight: 5,  label: 'Shop name on file',    pass: !!u.shop_name });
    // 2. Firearms with all required fields
    const badFirearms = firearms.filter(f => !f.manufacturer || !f.model || !f.serial_number || !f.caliber || !f.type || !f.acquisition_date || !f.acquisition_from);
    checks.push({ id: 'firearms_complete', weight: 20, label: `Firearm records complete`, pass: badFirearms.length === 0, detail: badFirearms.length ? `${badFirearms.length} records missing required fields` : null });
    // 3. Disposed firearms with matching 4473
    const disposed = firearms.filter(f => f.disposition_date);
    const serialsFrom4473 = new Set(forms.filter(f => f.firearm_id).map(f => f.firearm_id));
    const disposedWithout4473 = disposed.filter(f => !serialsFrom4473.has(f.id));
    checks.push({ id: 'disposed_has_4473', weight: 20, label: 'Disposed firearms have a Form 4473', pass: disposedWithout4473.length === 0, detail: disposedWithout4473.length ? `${disposedWithout4473.length} dispositions without a linked 4473` : null });
    // 4. Completed transfers with NICS
    const completedNoNics = forms.filter(f => f.status !== 'pending' && !f.nics_transaction);
    checks.push({ id: 'nics_complete', weight: 15, label: 'Completed 4473s have NICS number', pass: completedNoNics.length === 0, detail: completedNoNics.length ? `${completedNoNics.length} missing NICS number` : null });
    // 5. Prohibited-person flags on completed transfers
    const prohibitedCompleted = forms.filter(f => f.status === 'complete' && (f.is_felon || f.is_fugitive || f.is_drug_user || f.is_mental_health || f.is_domestic_violence));
    checks.push({ id: 'prohibited_blocked', weight: 20, label: 'No completed transfers to prohibited persons', pass: prohibitedCompleted.length === 0, detail: prohibitedCompleted.length ? `${prohibitedCompleted.length} completed transfers with prohibited-person flag` : null });
    // 6. Serial number sanity
    const badSerials = firearms.filter(f => /^(0+|1+|)$/.test(f.serial_number || '') || (f.serial_number || '').length < 3);
    checks.push({ id: 'serials_sane', weight: 10, label: 'Serial numbers look valid', pass: badSerials.length === 0, detail: badSerials.length ? `${badSerials.length} suspicious serials` : null });

    const maxScore = checks.reduce((s, c) => s + c.weight, 0);
    const earned   = checks.reduce((s, c) => s + (c.pass ? c.weight : 0), 0);
    const score    = Math.round((earned / maxScore) * 100);
    const grade    = score >= 95 ? 'A' : score >= 85 ? 'B' : score >= 70 ? 'C' : score >= 50 ? 'D' : 'F';

    res.json({ score, grade, checks, total_firearms: firearms.length, total_forms: forms.length });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Readiness check failed' }); }
});

// ── Multi-handgun sale detection (ATF 3310.4) ──
app.get('/api/app/multi-sale/check', requireAuth, async (req, res) => {
  try {
    const user = await requireFeature(req, res, 'pos', 'starter', 'Multi-sale alerts are available on Starter or Pro.');
    if (!user) return;
    const uid = req.user.id;
    // Find any 4473s to the same transferee within 5 business days for 2+ handguns
    const recent = await all(
      `SELECT f4.transferee_name, f4.transferee_dob, f4.transfer_date, f4.firearm_id, f.type, f.manufacturer, f.model, f.serial_number
       FROM form_4473 f4 LEFT JOIN firearms f ON f4.firearm_id=f.id
       WHERE f4.user_id=$1 AND f4.transfer_date IS NOT NULL AND f4.transfer_date != ''
         AND f4.transfer_date::date >= NOW() - INTERVAL '30 days'
       ORDER BY f4.transfer_date DESC`, [uid]);
    const groups = {};
    for (const r of recent) {
      const key = (r.transferee_name || '') + '|' + (r.transferee_dob || '');
      if (!key.trim().replace('|','')) continue;
      groups[key] = groups[key] || [];
      groups[key].push(r);
    }
    const handgunFlags = [], rifleFlags = [];
    for (const k of Object.keys(groups)) {
      const txns = groups[k];
      const handguns = txns.filter(t => /handgun|pistol|revolver/i.test(t.type || ''));
      const rifles   = txns.filter(t => /rifle/i.test(t.type || ''));
      if (handguns.length >= 2) {
        const dates = handguns.map(h => h.transfer_date).sort();
        const diff = (new Date(dates[dates.length-1]) - new Date(dates[0])) / 86400000;
        if (diff <= 5) handgunFlags.push({ key: k, firearms: handguns, first: dates[0], last: dates[dates.length-1] });
      }
      if (rifles.length >= 2) {
        const dates = rifles.map(h => h.transfer_date).sort();
        const diff = (new Date(dates[dates.length-1]) - new Date(dates[0])) / 86400000;
        if (diff <= 5) rifleFlags.push({ key: k, firearms: rifles, first: dates[0], last: dates[dates.length-1] });
      }
    }
    res.json({ form_3310_4: handgunFlags, form_3310_12: rifleFlags });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ── Referrals ──
app.get('/api/app/referrals', requireAuth, async (req, res) => {
  try {
    const u = await stmts.getUserById(req.user.id);
    const referrals = await stmts.getReferralsForUser(req.user.id);
    const baseUrl = process.env.APP_URL || 'https://boundstack.org';
    res.json({
      code: u.referral_code,
      url: `${baseUrl}/?ref=${u.referral_code}`,
      referrals,
      earned: referrals.filter(r => r.credit_status === 'paid').reduce((s, r) => s + parseFloat(r.credit_amount || 0), 0),
      pending: referrals.filter(r => r.credit_status === 'pending').length,
    });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── Onboarding step ──
app.patch('/api/app/onboarding/step', requireAuth, async (req, res) => {
  try {
    const step = parseInt(req.body.step || 0, 10);
    await run('UPDATE users SET onboarding_step=$1 WHERE id=$2', [step, req.user.id]);
    if (step >= 5) await stmts.completeOnboard(req.user.id);
    res.json({ message: 'Step saved', step });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── Offline sync queue (idempotent replay) ──
app.post('/api/app/sync', requireAuth, async (req, res) => {
  try {
    const user = await requireFeature(req, res, 'gunShow', 'starter', 'Gun Show Mode is available on Starter or Pro.');
    if (!user) return;
    const { ops } = req.body;
    if (!Array.isArray(ops)) return res.status(400).json({ error: 'ops must be an array' });
    const results = [];
    for (const op of ops) {
      if (!op.id || !op.type || !op.payload) { results.push({ id: op.id, status: 'error', error: 'Missing id/type/payload' }); continue; }
      const exists = await stmts.getSyncOp(req.user.id, op.id);
      if (exists) { results.push({ id: op.id, status: 'duplicate' }); continue; }
      try {
        if (op.type === 'firearm.add') {
          await stmts.addFirearm({ user_id: req.user.id, ...op.payload });
        } else if (op.type === 'customer.add') {
          await stmts.addCustomer({ user_id: req.user.id, ...op.payload });
        } else if (op.type === 'sale.add') {
          await stmts.addSale({ user_id: req.user.id, ...op.payload });
        } else {
          results.push({ id: op.id, status: 'unknown-type' }); continue;
        }
        await stmts.recordSyncOp({ user_id: req.user.id, op_id: op.id, op_type: op.type, payload: JSON.stringify(op.payload) });
        results.push({ id: op.id, status: 'applied' });
      } catch(e) {
        if (isDupe(e)) { await stmts.recordSyncOp({ user_id: req.user.id, op_id: op.id, op_type: op.type, payload: JSON.stringify(op.payload), status: 'duplicate' }); results.push({ id: op.id, status: 'duplicate' }); }
        else results.push({ id: op.id, status: 'error', error: e.message });
      }
    }
    res.json({ results, applied: results.filter(r => r.status === 'applied').length });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Sync failed' }); }
});

// ── Audit chain verification ──
app.get('/api/app/audit-log/verify', requireAuth, async (req, res) => {
  try { res.json(await stmts.verifyAuditChain(req.user.id)); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ═══════════════════════════════════════════════════════
//  PUBLIC
// ═══════════════════════════════════════════════════════

app.post('/api/demo', async (req, res) => {
  try {
    const { name, email, phone, locations } = req.body;
    if (!ok(name)||!isEmail(email)) return res.status(400).json({ error: 'Name and email required' });
    await stmts.createDemo({ name: name.trim(), email: email.toLowerCase().trim(), phone: phone || null, locations: locations || null });
    await stmts.addWaitlist({ email: email.toLowerCase().trim(), source: 'demo' });
    const existing = await one('SELECT id FROM leads WHERE email=$1 LIMIT 1', [email.toLowerCase().trim()]);
    if (existing) {
      await stmts.updateLeadStage('demo_scheduled', existing.id);
      await stmts.addActivity({ lead_id: existing.id, type: 'demo', description: 'Booked a demo' });
    } else {
      const r = await stmts.createLead({ name: name.trim(), email: email.toLowerCase().trim(), phone: phone || null, shop_name: null, ffl_number: null, current_software: null, source: 'demo', stage: 'demo_scheduled', priority: 'high' });
      await stmts.addActivity({ lead_id: r.id, type: 'demo', description: 'Booked a demo' });
    }
    mailer.sendDemoConfirm({ name, email }).catch(() => {});
    res.status(201).json({ message: "Demo requested! We'll reach out within 1 business day." });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/waitlist', async (req, res) => {
  try {
    const { email, source } = req.body;
    if (!isEmail(email)) return res.status(400).json({ error: 'Valid email required' });
    await stmts.addWaitlist({ email: email.toLowerCase().trim(), source: source || 'direct' });
    res.status(201).json({ message: 'Added!' });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

// ═══════════════════════════════════════════════════════
//  ADMIN — /api/admin/*
// ═══════════════════════════════════════════════════════

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const [users, leads, demos, waitlist, byStage] = await Promise.all([
      stmts.getAllUsers(), stmts.getAllLeads(), stmts.getAllDemos(),
      stmts.getAllWaitlist(), stmts.countLeadsByStage(),
    ]);
    const proUsers = users.filter(u => u.plan === 'pro').length;
    res.json({ total_users: users.length, total_leads: leads.length, total_demos: demos.length, total_waitlist: waitlist.length, mrr: proUsers * 99, stages: Object.fromEntries(byStage.map(r => [r.stage, r.cnt])) });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/admin/leads', requireAdmin, async (req, res) => {
  try { res.json({ leads: await stmts.getAllLeads() }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/leads', requireAdmin, async (req, res) => {
  try {
    const { name, email, phone, shop_name, ffl_number, current_software, source, stage, priority } = req.body;
    if (!ok(name)||!isEmail(email)) return res.status(400).json({ error: 'Name and email required' });
    const r = await stmts.createLead({ name, email: email.toLowerCase(), phone: phone || null, shop_name: shop_name || null, ffl_number: ffl_number || null, current_software: current_software || null, source: source || 'manual', stage: stage || 'new', priority: priority || 'normal' });
    await stmts.addActivity({ lead_id: r.id, type: 'created', description: 'Lead added manually' });
    res.status(201).json({ message: 'Lead created', id: r.id });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/admin/leads/:id', requireAdmin, async (req, res) => {
  try {
    const { name, email, phone, shop_name, priority, next_followup, stage } = req.body;
    const lead = await stmts.getLead(req.params.id);
    if (!lead) return res.status(404).json({ error: 'Not found' });
    await stmts.updateLead({ name: name || lead.name, email: email || lead.email, phone: phone || lead.phone, shop_name: shop_name || lead.shop_name, priority: priority || lead.priority, next_followup: next_followup || lead.next_followup, stage: stage || lead.stage, id: lead.id });
    if (stage && stage !== lead.stage) await stmts.addActivity({ lead_id: lead.id, type: 'stage', description: `Stage changed: ${lead.stage} -> ${stage}` });
    res.json({ message: 'Updated' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/admin/leads/:id', requireAdmin, async (req, res) => {
  try { await stmts.deleteLead(req.params.id); res.json({ message: 'Deleted' }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/admin/leads/:id/notes', requireAdmin, async (req, res) => {
  try { res.json({ notes: await stmts.getNotes(req.params.id) }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/leads/:id/notes', requireAdmin, async (req, res) => {
  try {
    const { content, author } = req.body;
    if (!ok(content)) return res.status(400).json({ error: 'Content required' });
    await stmts.addNote({ lead_id: req.params.id, author: author || 'Admin', content });
    await stmts.addActivity({ lead_id: req.params.id, type: 'note', description: 'Note added' });
    res.status(201).json({ message: 'Note added' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/admin/leads/:id/activity', requireAdmin, async (req, res) => {
  try { res.json({ activities: await stmts.getActivities(req.params.id) }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try { res.json({ users: await stmts.getAllUsers() }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/admin/demos', requireAdmin, async (req, res) => {
  try { res.json({ demos: await stmts.getAllDemos() }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/admin/demos/:id', requireAdmin, async (req, res) => {
  try { await stmts.updateDemoStatus(req.body.status, req.params.id); res.json({ message: 'Updated' }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/admin/waitlist', requireAdmin, async (req, res) => {
  try { res.json({ waitlist: await stmts.getAllWaitlist() }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ─── ATF Inspector Access ─────────────────────
// Generate / regenerate a read-only inspector token
app.post('/api/app/inspector-token', requireAuth, async (req, res) => {
  try {
    const token = crypto.randomBytes(24).toString('hex');
    await stmts.setInspectorToken(req.user.id, token);
    res.json({ token, url: `${process.env.APP_URL || 'https://boundstack.org'}/inspect/${token}` });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// Read-only ATF inspector view
app.get('/inspect/:token', async (req, res) => {
  try {
    const dealer = await stmts.getUserByInspectorToken(req.params.token);
    if (!dealer) return res.status(404).send('<h2>Invalid or expired access link.</h2>');
    const firearms = await stmts.getFirearms(dealer.id);
    const rows = firearms.map(f => `
      <tr>
        <td>${escHtml(f.id)}</td>
        <td>${escHtml(f.manufacturer)}</td>
        <td>${escHtml(f.importer) || '—'}</td>
        <td>${escHtml(f.model)}</td>
        <td style="font-family:monospace">${escHtml(f.serial_number)}</td>
        <td>${escHtml(f.caliber)}</td>
        <td>${escHtml(f.type)}</td>
        <td>${escHtml(f.acquisition_date)}</td>
        <td>${escHtml(f.acquisition_from)}</td>
        <td>${escHtml(f.disposition_date) || '—'}</td>
        <td>${escHtml(f.disposition_to) || '—'}</td>
        <td>${f.is_nfa ? '⚠️ NFA' : ''}</td>
      </tr>`).join('');
    res.send(`<!DOCTYPE html><html lang="en"><head>
      <meta charset="UTF-8"><title>ATF Inspection — ${escHtml(dealer.shop_name || dealer.name)}</title>
      <style>
        body{font-family:Arial,sans-serif;margin:0;padding:24px;background:#f8f8f8;color:#111}
        .header{background:#1a1a2e;color:#fff;padding:20px 24px;border-radius:8px;margin-bottom:24px}
        .header h1{margin:0 0 4px;font-size:20px}
        .header p{margin:0;font-size:13px;opacity:.7}
        .badge{display:inline-block;background:#c41e3a;color:#fff;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;margin-left:8px}
        table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)}
        th{background:#1a1a2e;color:#fff;padding:10px 8px;text-align:left;font-size:12px}
        td{padding:8px;font-size:12px;border-bottom:1px solid #f0f0f0}
        tr:last-child td{border-bottom:none}
        .meta{font-size:12px;color:#666;margin-bottom:16px}
        .readonly{background:#fef3c7;border:1px solid #fbbf24;padding:10px 14px;border-radius:6px;font-size:12px;margin-bottom:20px}
      </style></head><body>
      <div class="header">
        <h1>A&amp;D Bound Book — Read-Only ATF Inspection View <span class="badge">READ ONLY</span></h1>
        <p>${escHtml(dealer.shop_name || dealer.name)} &nbsp;|&nbsp; FFL: ${escHtml(dealer.ffl_number) || 'N/A'} &nbsp;|&nbsp; Generated: ${new Date().toUTCString()}</p>
      </div>
      <div class="readonly">⚠️ <strong>This is a read-only view generated for ATF inspection purposes.</strong> No edits can be made through this link. Powered by BoundStack.</div>
      <p class="meta">Total records: <strong>${firearms.length}</strong> &nbsp;|&nbsp; In inventory: <strong>${firearms.filter(f=>!f.disposition_date).length}</strong> &nbsp;|&nbsp; Transferred: <strong>${firearms.filter(f=>f.disposition_date).length}</strong></p>
      <table>
        <thead><tr>
          <th>Log #</th><th>Manufacturer</th><th>Importer</th><th>Model</th>
          <th>Serial #</th><th>Caliber</th><th>Type</th>
          <th>Acq. Date</th><th>Acquired From</th>
          <th>Disp. Date</th><th>Disposed To</th><th>NFA</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </body></html>`);
  } catch(e) { console.error(e); res.status(500).send('<h2>Server error</h2>'); }
});

// ─── Health ───────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ─── Pages ────────────────────────────────────
// ── Full Backup ──────────────────────────────
app.get('/api/app/backup', requireAuth, async (req, res) => {
  try {
    const [firearms, customers, sales, forms] = await Promise.all([
      stmts.getFirearms(req.user.id),
      stmts.getCustomers(req.user.id),
      stmts.getSales(req.user.id),
      stmts.getForms(req.user.id),
    ]);
    const toCSV = (rows, cols) => {
      if (!rows.length) return cols.join(',') + '\n';
      return cols.join(',') + '\n' + rows.map(r => cols.map(c => {
        const v = r[c] == null ? '' : String(r[c]);
        return v.includes(',') || v.includes('"') || v.includes('\n') ? '"' + v.replace(/"/g,'""') + '"' : v;
      }).join(',')).join('\n');
    };
    const fCols = ['id','manufacturer','importer','model','serial_number','caliber','type','acquisition_date','acquisition_from','disposition_date','disposition_to','is_nfa','nfa_type','nfa_form_type','nfa_form_number','notes'];
    const cCols = ['id','first_name','last_name','email','phone','address','id_type','id_number','dob','notes'];
    const sCols = ['id','sale_date','amount','payment_method','customer_id','firearm_id','notes'];
    const f4Cols = ['id','transferee_name','transferee_address','nics_transaction','nics_result','transfer_date','status'];
    const backup = {
      exported_at: new Date().toISOString(),
      firearms_csv: toCSV(firearms, fCols),
      customers_csv: toCSV(customers, cCols),
      sales_csv: toCSV(sales, sCols),
      forms_4473_csv: toCSV(forms, f4Cols),
    };
    res.json(backup);
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/app',                    (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/admin',                  (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/reset-password',         (req, res) => res.sendFile(path.join(__dirname, 'public', 'reset-password.html')));
app.get('/privacy',                (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/terms',                  (req, res) => res.sendFile(path.join(__dirname, 'public', 'terms.html')));
app.get('/blog',                   (req, res) => res.sendFile(path.join(__dirname, 'public', 'blog.html')));
app.get('/atf-inspection-guide',   (req, res) => res.sendFile(path.join(__dirname, 'public', 'atf-inspection-guide.html')));
app.get('/best-ffl-software',      (req, res) => res.sendFile(path.join(__dirname, 'public', 'best-ffl-software.html')));
app.get('/electronic-bound-book-requirements-2026', (req, res) => res.sendFile(path.join(__dirname, 'public', 'electronic-bound-book-requirements-2026.html')));
app.get('*',                       (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ─── Start (local only — Vercel uses module.exports) ───
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`\n  BoundStack running -> http://localhost:${PORT}`);
    console.log(`  Admin CRM     -> http://localhost:${PORT}/admin  (pw: ${ADMIN_PASS})\n`);
  });
}

module.exports = app;
