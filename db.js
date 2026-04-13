require('dotenv').config();
const { Pool } = require('pg');

// ─────────────────────────────────────────────
//  CONNECTION
// ─────────────────────────────────────────────
const isRemote = process.env.DATABASE_URL &&
  !process.env.DATABASE_URL.includes('localhost') &&
  !process.env.DATABASE_URL.includes('127.0.0.1');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost/gunvault',
  ssl: isRemote ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on('error', (err) => console.error('PG pool error:', err.message));

// ─────────────────────────────────────────────
//  QUERY HELPERS
// ─────────────────────────────────────────────
const q   = (sql, p = []) => pool.query(sql, p);
const one = async (sql, p = []) => (await q(sql, p)).rows[0];
const all = async (sql, p = []) => (await q(sql, p)).rows;
const run = async (sql, p = []) => { await q(sql, p); };

// ─────────────────────────────────────────────
//  SCHEMA  (CREATE TABLE IF NOT EXISTS)
// ─────────────────────────────────────────────
async function initSchema() {
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id               SERIAL PRIMARY KEY,
      name             TEXT        NOT NULL,
      email            TEXT        NOT NULL UNIQUE,
      password_hash    TEXT        NOT NULL,
      ffl_number       TEXT,
      shop_name        TEXT,
      phone            TEXT,
      current_software TEXT,
      plan             TEXT        DEFAULT 'free',
      onboarding_done  INTEGER     DEFAULT 0,
      created_at       TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS locations (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name       TEXT        NOT NULL,
      address    TEXT,
      ffl_number TEXT,
      is_primary INTEGER     DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS firearms (
      id                      SERIAL PRIMARY KEY,
      user_id                 INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      location_id             INTEGER     REFERENCES locations(id),
      manufacturer            TEXT        NOT NULL,
      importer                TEXT,
      model                   TEXT        NOT NULL,
      serial_number           TEXT        NOT NULL,
      caliber                 TEXT        NOT NULL,
      type                    TEXT        NOT NULL,
      acquisition_date        TEXT        NOT NULL,
      acquisition_from        TEXT        NOT NULL,
      disposition_date        TEXT,
      disposition_to          TEXT,
      disposition_customer_id INTEGER,
      notes                   TEXT,
      created_at              TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`CREATE UNIQUE INDEX IF NOT EXISTS idx_firearms_serial ON firearms(user_id, serial_number)`);

  await q(`
    CREATE TABLE IF NOT EXISTS customers (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      first_name TEXT        NOT NULL,
      last_name  TEXT        NOT NULL,
      email      TEXT,
      phone      TEXT,
      address    TEXT,
      id_type    TEXT,
      id_number  TEXT,
      dob        TEXT,
      notes      TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS form_4473 (
      id                   SERIAL PRIMARY KEY,
      user_id              INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      firearm_id           INTEGER     REFERENCES firearms(id),
      customer_id          INTEGER     REFERENCES customers(id),
      transferee_name      TEXT,
      transferee_address   TEXT,
      transferee_city      TEXT,
      transferee_state     TEXT,
      transferee_zip       TEXT,
      transferee_dob       TEXT,
      transferee_id_type   TEXT,
      transferee_id_num    TEXT,
      transferee_gender    TEXT,
      is_us_citizen        INTEGER     DEFAULT 1,
      is_felon             INTEGER     DEFAULT 0,
      is_fugitive          INTEGER     DEFAULT 0,
      is_drug_user         INTEGER     DEFAULT 0,
      is_mental_health     INTEGER     DEFAULT 0,
      is_domestic_violence INTEGER     DEFAULT 0,
      nics_transaction     TEXT,
      nics_result          TEXT,
      transfer_date        TEXT,
      status               TEXT        DEFAULT 'pending',
      notes                TEXT,
      created_at           TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      table_name TEXT        NOT NULL,
      record_id  INTEGER,
      action     TEXT        NOT NULL,
      old_data   TEXT,
      new_data   TEXT,
      ip_address TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token      TEXT        NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used       INTEGER     DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS leads (
      id               SERIAL PRIMARY KEY,
      name             TEXT        NOT NULL,
      email            TEXT        NOT NULL,
      phone            TEXT,
      shop_name        TEXT,
      ffl_number       TEXT,
      current_software TEXT,
      source           TEXT        DEFAULT 'organic',
      stage            TEXT        DEFAULT 'new',
      priority         TEXT        DEFAULT 'normal',
      next_followup    TEXT,
      user_id          INTEGER,
      created_at       TIMESTAMPTZ DEFAULT NOW(),
      updated_at       TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS lead_notes (
      id         SERIAL PRIMARY KEY,
      lead_id    INTEGER     NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
      author     TEXT        DEFAULT 'Admin',
      content    TEXT        NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS lead_activities (
      id          SERIAL PRIMARY KEY,
      lead_id     INTEGER     NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
      type        TEXT        NOT NULL,
      description TEXT        NOT NULL,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS demo_requests (
      id         SERIAL PRIMARY KEY,
      name       TEXT        NOT NULL,
      email      TEXT        NOT NULL,
      phone      TEXT,
      locations  TEXT,
      status     TEXT        DEFAULT 'new',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS waitlist (
      id         SERIAL PRIMARY KEY,
      email      TEXT        NOT NULL UNIQUE,
      source     TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
}

// Run schema init once at startup (idempotent)
const ready = initSchema().catch(e => console.error('Schema init error:', e.message));

// ─────────────────────────────────────────────
//  DB FUNCTIONS  (async, mirror old stmts API)
// ─────────────────────────────────────────────
const stmts = {

  // ── Users ─────────────────────────────────
  createUser: ({ name, email, password_hash, ffl_number, current_software }) =>
    one('INSERT INTO users (name,email,password_hash,ffl_number,current_software) VALUES ($1,$2,$3,$4,$5) RETURNING id,name,email,plan',
      [name, email, password_hash, ffl_number || null, current_software || null]),

  getUserByEmail: (email) =>
    one('SELECT * FROM users WHERE email=$1 LIMIT 1', [email]),

  getUserById: (id) =>
    one('SELECT id,name,email,ffl_number,shop_name,phone,plan,onboarding_done,created_at FROM users WHERE id=$1 LIMIT 1', [id]),

  updateUser: ({ name, phone, shop_name, ffl_number, id }) =>
    run('UPDATE users SET name=$1,phone=$2,shop_name=$3,ffl_number=$4 WHERE id=$5',
      [name || '', phone || '', shop_name || '', ffl_number || '', id]),

  updatePassword: ({ password_hash, id }) =>
    run('UPDATE users SET password_hash=$1 WHERE id=$2', [password_hash, id]),

  completeOnboard: (id) =>
    run('UPDATE users SET onboarding_done=1 WHERE id=$1', [id]),

  getAllUsers: () =>
    all('SELECT id,name,email,ffl_number,shop_name,current_software,plan,onboarding_done,created_at FROM users ORDER BY created_at DESC'),

  // ── Password reset ─────────────────────────
  createResetToken: ({ user_id, token, expires_at }) =>
    run('INSERT INTO password_reset_tokens (user_id,token,expires_at) VALUES ($1,$2,$3)',
      [user_id, token, expires_at]),

  getResetToken: (token) =>
    one("SELECT * FROM password_reset_tokens WHERE token=$1 AND used=0 AND expires_at > NOW() LIMIT 1", [token]),

  markTokenUsed: (token) =>
    run('UPDATE password_reset_tokens SET used=1 WHERE token=$1', [token]),

  cleanOldTokens: () =>
    run("DELETE FROM password_reset_tokens WHERE expires_at < NOW() OR used=1"),

  // ── Locations ─────────────────────────────
  addLocation: ({ user_id, name, address, ffl_number, is_primary }) =>
    one('INSERT INTO locations (user_id,name,address,ffl_number,is_primary) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [user_id, name, address || null, ffl_number || null, is_primary || 0]),

  getLocations: (user_id) =>
    all('SELECT * FROM locations WHERE user_id=$1 ORDER BY is_primary DESC, name ASC', [user_id]),

  updateLocation: ({ name, address, ffl_number, id, user_id }) =>
    run('UPDATE locations SET name=$1,address=$2,ffl_number=$3 WHERE id=$4 AND user_id=$5',
      [name, address || null, ffl_number || null, id, user_id]),

  deleteLocation: (id, user_id) =>
    run('DELETE FROM locations WHERE id=$1 AND user_id=$2', [id, user_id]),

  setPrimaryLoc: (user_id) =>
    run('UPDATE locations SET is_primary=0 WHERE user_id=$1', [user_id]),

  makePrimaryLoc: (id, user_id) =>
    run('UPDATE locations SET is_primary=1 WHERE id=$1 AND user_id=$2', [id, user_id]),

  // ── Firearms ──────────────────────────────
  addFirearm: ({ user_id, location_id, manufacturer, importer, model, serial_number, caliber, type, acquisition_date, acquisition_from, notes }) =>
    one('INSERT INTO firearms (user_id,location_id,manufacturer,importer,model,serial_number,caliber,type,acquisition_date,acquisition_from,notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id',
      [user_id, location_id || null, manufacturer, importer || null, model, serial_number, caliber, type, acquisition_date, acquisition_from, notes || null]),

  updateFirearm: ({ manufacturer, importer, model, serial_number, caliber, type, acquisition_date, acquisition_from, notes, id, user_id }) =>
    run('UPDATE firearms SET manufacturer=$1,importer=$2,model=$3,serial_number=$4,caliber=$5,type=$6,acquisition_date=$7,acquisition_from=$8,notes=$9 WHERE id=$10 AND user_id=$11',
      [manufacturer, importer || null, model, serial_number, caliber, type, acquisition_date, acquisition_from, notes || null, id, user_id]),

  getFirearms: (user_id) =>
    all('SELECT f.*,l.name as location_name FROM firearms f LEFT JOIN locations l ON f.location_id=l.id WHERE f.user_id=$1 ORDER BY f.acquisition_date DESC', [user_id]),

  getFirearm: (id, user_id) =>
    one('SELECT * FROM firearms WHERE id=$1 AND user_id=$2', [id, user_id]),

  disposeFirearm: ({ disposition_date, disposition_to, disposition_customer_id, id, user_id }) =>
    run('UPDATE firearms SET disposition_date=$1,disposition_to=$2,disposition_customer_id=$3 WHERE id=$4 AND user_id=$5',
      [disposition_date, disposition_to, disposition_customer_id || null, id, user_id]),

  deleteFirearm: (id, user_id) =>
    run('DELETE FROM firearms WHERE id=$1 AND user_id=$2', [id, user_id]),

  countFirearms: (user_id) =>
    one("SELECT COUNT(*)::int AS total, COALESCE(SUM(CASE WHEN disposition_date IS NULL THEN 1 ELSE 0 END)::int,0) AS in_inventory FROM firearms WHERE user_id=$1", [user_id]),

  // ── Customers ─────────────────────────────
  addCustomer: ({ user_id, first_name, last_name, email, phone, address, id_type, id_number, dob, notes }) =>
    one('INSERT INTO customers (user_id,first_name,last_name,email,phone,address,id_type,id_number,dob,notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id',
      [user_id, first_name, last_name, email || null, phone || null, address || null, id_type || null, id_number || null, dob || null, notes || null]),

  getCustomers: (user_id) =>
    all('SELECT * FROM customers WHERE user_id=$1 ORDER BY last_name ASC', [user_id]),

  getCustomer: (id, user_id) =>
    one('SELECT * FROM customers WHERE id=$1 AND user_id=$2', [id, user_id]),

  updateCustomer: ({ first_name, last_name, email, phone, address, id_type, id_number, dob, notes, id, user_id }) =>
    run('UPDATE customers SET first_name=$1,last_name=$2,email=$3,phone=$4,address=$5,id_type=$6,id_number=$7,dob=$8,notes=$9 WHERE id=$10 AND user_id=$11',
      [first_name, last_name, email || null, phone || null, address || null, id_type || null, id_number || null, dob || null, notes || null, id, user_id]),

  deleteCustomer: (id, user_id) =>
    run('DELETE FROM customers WHERE id=$1 AND user_id=$2', [id, user_id]),

  countCustomers: (user_id) =>
    one('SELECT COUNT(*)::int AS total FROM customers WHERE user_id=$1', [user_id]),

  // ── Form 4473 ─────────────────────────────
  add4473: ({ user_id, firearm_id, customer_id, transferee_name, transferee_address, transferee_city, transferee_state, transferee_zip, transferee_dob, transferee_id_type, transferee_id_num, transferee_gender, is_us_citizen, is_felon, is_fugitive, is_drug_user, is_mental_health, is_domestic_violence, nics_transaction, nics_result, transfer_date, status, notes }) =>
    one(
      `INSERT INTO form_4473
       (user_id,firearm_id,customer_id,transferee_name,transferee_address,transferee_city,
        transferee_state,transferee_zip,transferee_dob,transferee_id_type,transferee_id_num,
        transferee_gender,is_us_citizen,is_felon,is_fugitive,is_drug_user,is_mental_health,
        is_domestic_violence,nics_transaction,nics_result,transfer_date,status,notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
       RETURNING id`,
      [user_id, firearm_id || null, customer_id || null, transferee_name || null,
       transferee_address || null, transferee_city || null, transferee_state || null,
       transferee_zip || null, transferee_dob || null, transferee_id_type || null,
       transferee_id_num || null, transferee_gender || null,
       is_us_citizen ?? 1, is_felon ?? 0, is_fugitive ?? 0, is_drug_user ?? 0,
       is_mental_health ?? 0, is_domestic_violence ?? 0,
       nics_transaction || null, nics_result || null, transfer_date || null,
       status || 'pending', notes || null]),

  get4473s: (user_id) =>
    all('SELECT f4.*,f.manufacturer,f.model,f.serial_number FROM form_4473 f4 LEFT JOIN firearms f ON f4.firearm_id=f.id WHERE f4.user_id=$1 ORDER BY f4.created_at DESC', [user_id]),

  get4473: (id, user_id) =>
    one('SELECT * FROM form_4473 WHERE id=$1 AND user_id=$2', [id, user_id]),

  update4473: ({ status, nics_transaction, nics_result, notes, id, user_id }) =>
    run('UPDATE form_4473 SET status=$1,nics_transaction=$2,nics_result=$3,notes=$4 WHERE id=$5 AND user_id=$6',
      [status || 'pending', nics_transaction || null, nics_result || null, notes || null, id, user_id]),

  // ── Audit log ─────────────────────────────
  addAudit: ({ user_id, table_name, record_id, action, old_data, new_data, ip_address }) =>
    run('INSERT INTO audit_log (user_id,table_name,record_id,action,old_data,new_data,ip_address) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [user_id, table_name, record_id || null, action, old_data || null, new_data || null, ip_address || null]),

  getAuditLog: (user_id) =>
    all('SELECT * FROM audit_log WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200', [user_id]),

  // ── Leads ─────────────────────────────────
  createLead: ({ name, email, phone, shop_name, ffl_number, current_software, source, stage, priority }) =>
    one('INSERT INTO leads (name,email,phone,shop_name,ffl_number,current_software,source,stage,priority) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',
      [name, email, phone || null, shop_name || null, ffl_number || null, current_software || null, source || 'organic', stage || 'new', priority || 'normal']),

  getAllLeads: () =>
    all('SELECT * FROM leads ORDER BY updated_at DESC'),

  getLead: (id) =>
    one('SELECT * FROM leads WHERE id=$1', [id]),

  updateLeadStage: (stage, id) =>
    run('UPDATE leads SET stage=$1,updated_at=NOW() WHERE id=$2', [stage, id]),

  updateLead: ({ name, email, phone, shop_name, priority, next_followup, stage, id }) =>
    run('UPDATE leads SET name=$1,email=$2,phone=$3,shop_name=$4,priority=$5,next_followup=$6,stage=$7,updated_at=NOW() WHERE id=$8',
      [name, email, phone || null, shop_name || null, priority || 'normal', next_followup || null, stage, id]),

  deleteLead: (id) =>
    run('DELETE FROM leads WHERE id=$1', [id]),

  countLeadsByStage: () =>
    all('SELECT stage, COUNT(*)::int AS cnt FROM leads GROUP BY stage'),

  addNote: ({ lead_id, author, content }) =>
    run('INSERT INTO lead_notes (lead_id,author,content) VALUES ($1,$2,$3)',
      [lead_id, author || 'Admin', content]),

  getNotes: (lead_id) =>
    all('SELECT * FROM lead_notes WHERE lead_id=$1 ORDER BY created_at DESC', [lead_id]),

  addActivity: ({ lead_id, type, description }) =>
    run('INSERT INTO lead_activities (lead_id,type,description) VALUES ($1,$2,$3)',
      [lead_id, type, description]),

  getActivities: (lead_id) =>
    all('SELECT * FROM lead_activities WHERE lead_id=$1 ORDER BY created_at DESC LIMIT 20', [lead_id]),

  // ── Demos ─────────────────────────────────
  createDemo: ({ name, email, phone, locations }) =>
    run('INSERT INTO demo_requests (name,email,phone,locations) VALUES ($1,$2,$3,$4)',
      [name, email, phone || null, locations || null]),

  getAllDemos: () =>
    all('SELECT * FROM demo_requests ORDER BY created_at DESC'),

  updateDemoStatus: (status, id) =>
    run('UPDATE demo_requests SET status=$1 WHERE id=$2', [status, id]),

  // ── Waitlist ──────────────────────────────
  addWaitlist: ({ email, source }) =>
    run('INSERT INTO waitlist (email,source) VALUES ($1,$2) ON CONFLICT (email) DO NOTHING',
      [email, source || 'direct']),

  getAllWaitlist: () =>
    all('SELECT * FROM waitlist ORDER BY created_at DESC'),
};

// ─────────────────────────────────────────────
//  UPSERT LEAD FROM USER
// ─────────────────────────────────────────────
async function upsertLeadFromUser(user, source) {
  try {
    const existing = await one('SELECT id FROM leads WHERE email=$1 LIMIT 1', [user.email]);
    if (existing) {
      await run(
        `UPDATE leads SET user_id=$1, stage=CASE WHEN stage='new' THEN 'trial_active' ELSE stage END, updated_at=NOW() WHERE id=$2`,
        [user.id, existing.id]
      );
      await stmts.addActivity({ lead_id: existing.id, type: 'signup', description: 'User completed registration' });
    } else {
      const r = await stmts.createLead({
        name: user.name, email: user.email, phone: null, shop_name: null,
        ffl_number: user.ffl_number || null, current_software: user.current_software || null,
        source: source || 'organic', stage: 'trial_active', priority: 'normal'
      });
      await run('UPDATE leads SET user_id=$1 WHERE id=$2', [user.id, r.id]);
      await stmts.addActivity({ lead_id: r.id, type: 'signup', description: 'Signed up via landing page' });
    }
  } catch(e) { console.error('upsertLeadFromUser error:', e.message); }
}

module.exports = { stmts, upsertLeadFromUser, pool, q, one, all, run, ready };
