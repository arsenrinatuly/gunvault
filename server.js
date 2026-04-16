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

const app        = express();
const JWT_SECRET = process.env.JWT_SECRET || 'change_me_in_production';
const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'admin123';

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
app.use('/api/', apiLimiter);
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
    const { name, email, password, ffl_number, current_software } = req.body;
    if (!ok(name))                            return res.status(400).json({ error: 'Name required' });
    if (!isEmail(email))                      return res.status(400).json({ error: 'Valid email required' });
    if (!ok(password) || password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
    const existing = await stmts.getUserByEmail(email.toLowerCase().trim());
    if (existing) return res.status(409).json({ error: 'Account already exists with this email' });

    const hash = await bcrypt.hash(password, 12);
    const user = await stmts.createUser({
      name: name.trim(), email: email.toLowerCase().trim(),
      password_hash: hash, ffl_number: ffl_number || null, current_software: current_software || null
    });
    upsertLeadFromUser({ ...user, ffl_number, current_software }, 'signup').catch(() => {});
    stmts.addWaitlist({ email: user.email, source: 'signup' }).catch(() => {});
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    mailer.sendWelcome(user).catch(() => {});
    res.status(201).json({ message: 'Account created!', token, user: { ...user, plan: user.plan || 'free' } });
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
    res.json({ message: 'If that email exists, a reset link has been sent.' }); // always succeed
    const u = await stmts.getUserByEmail(email.toLowerCase().trim());
    if (!u) return;
    const token   = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000).toISOString();
    await stmts.cleanOldTokens();
    await stmts.createResetToken({ user_id: u.id, token, expires_at: expires });
    mailer.sendPasswordReset(u, token).catch(console.error);
  } catch(e) { console.error(e); }
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
    // Free plan: max 50 total firearms
    const u = await stmts.getUserById(req.user.id);
    if (u && u.plan === 'free') {
      const cnt = await stmts.countFirearms(req.user.id);
      if (cnt && cnt.total >= 50) return res.status(403).json({ error: 'Free plan limit reached (50 firearms). Upgrade to add more.', limit: true });
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
    // Free plan: max 50 customers
    const u = await stmts.getUserById(req.user.id);
    if (u && u.plan === 'free') {
      const cnt = await stmts.countCustomers(req.user.id);
      if (cnt && cnt.total >= 50) return res.status(403).json({ error: 'Free plan limit reached (50 customers). Upgrade to add more.', limit: true });
    }
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
      is_us_citizen:        d.q21l === 'yes' ? 0 : 1,
      is_felon:             d.q21c === 'yes' ? 1 : 0,
      is_fugitive:          d.q21d === 'yes' ? 1 : 0,
      is_drug_user:         d.q21e === 'yes' ? 1 : 0,
      is_mental_health:     d.q21f === 'yes' ? 1 : 0,
      is_domestic_violence: d.q21i === 'yes' ? 1 : 0,
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
  try { res.json({ sales: await stmts.getSales(req.user.id) }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/app/sales', requireAuth, async (req, res) => {
  try {
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
    const { customer_id, firearm_id, sale_date, amount, payment_method, notes } = req.body;
    if (!ok(sale_date)) return res.status(400).json({ error: 'Sale date required' });
    await stmts.updateSale({ customer_id: customer_id || null, firearm_id: firearm_id || null, sale_date, amount: parseFloat(amount) || 0, payment_method: payment_method || 'cash', notes: notes || null, id: req.params.id, user_id: req.user.id });
    res.json({ message: 'Updated' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/app/sales/:id', requireAuth, async (req, res) => {
  try { await stmts.deleteSale(req.params.id, req.user.id); res.json({ message: 'Deleted' }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
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
    const { type } = req.body;
    if (!['adbook', '4473', 'full'].includes(type))
      return res.status(400).json({ error: 'type must be adbook, 4473, or full' });

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
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

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
    res.json({ token, url: `${process.env.APP_URL || 'https://gunvault.vercel.app'}/inspect/${token}` });
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
        <td>${f.id}</td>
        <td>${f.manufacturer || ''}</td>
        <td>${f.importer || '—'}</td>
        <td>${f.model || ''}</td>
        <td style="font-family:monospace">${f.serial_number || ''}</td>
        <td>${f.caliber || ''}</td>
        <td>${f.type || ''}</td>
        <td>${f.acquisition_date || ''}</td>
        <td>${f.acquisition_from || ''}</td>
        <td>${f.disposition_date || '—'}</td>
        <td>${f.disposition_to || '—'}</td>
        <td>${f.is_nfa ? '⚠️ NFA' : ''}</td>
      </tr>`).join('');
    res.send(`<!DOCTYPE html><html lang="en"><head>
      <meta charset="UTF-8"><title>ATF Inspection — ${dealer.shop_name || dealer.name}</title>
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
        <p>${dealer.shop_name || dealer.name} &nbsp;|&nbsp; FFL: ${dealer.ffl_number || 'N/A'} &nbsp;|&nbsp; Generated: ${new Date().toUTCString()}</p>
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

app.get('/app',            (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/admin',          (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/reset-password', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reset-password.html')));
app.get('/privacy',        (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/terms',          (req, res) => res.sendFile(path.join(__dirname, 'public', 'terms.html')));
app.get('*',               (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ─── Start (local only — Vercel uses module.exports) ───
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`\n  BoundStack running -> http://localhost:${PORT}`);
    console.log(`  Admin CRM     -> http://localhost:${PORT}/admin  (pw: ${ADMIN_PASS})\n`);
  });
}

module.exports = app;
