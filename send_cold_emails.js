/**
 * BoundStack — Cold Email Sender
 * Usage: node send_cold_emails.js [start] [end]
 * Example: node send_cold_emails.js 101 200
 *
 * List format (emails.json):
 * [{"name":"John Smith","business":"Smith Law","email":"john@smithlaw.com"}]
 */

require('dotenv').config();
const { Resend }    = require('resend');
const nodemailer    = require('nodemailer');
const fs            = require('fs');
const path          = require('path');

const DELAY_MS    = 9000;  // 9 sec between sends (~400/hr — safe for Gmail & Resend)
const START       = parseInt(process.argv[2] || '1');
const END         = parseInt(process.argv[3] || '100');
const LIST_FILE   = path.join(__dirname, 'emails.json');
const LOG_FILE    = path.join(__dirname, 'sent_emails.log');

// ── Providers ────────────────────────────────
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

const gmail = (process.env.EMAIL_USER && process.env.EMAIL_PASS)
  ? nodemailer.createTransport({
      host: 'smtp.gmail.com', port: 587, secure: false,
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
      tls: { rejectUnauthorized: false },
    })
  : null;

// ── Send via best available provider ─────────
async function send({ to, subject, html, text }) {
  // Try Resend first
  if (resend) {
    try {
      const { data, error } = await resend.emails.send({
        from: 'Arsen from BoundStack <hello@boundstack.org>',
        to, subject, html,
      });
      if (!error) return { provider: 'Resend', id: data?.id };
    } catch (_) {}
  }
  // Gmail fallback
  if (gmail) {
    const info = await gmail.sendMail({
      from: `Arsen from BoundStack <${process.env.EMAIL_USER}>`,
      to, subject, html, text,
      headers: { 'List-Unsubscribe': `<mailto:${process.env.EMAIL_USER}?subject=unsubscribe>` },
    });
    return { provider: 'Gmail', id: info.messageId };
  }
  throw new Error('No email provider available');
}

// ── Email template ───────────────────────────
// Plain-text style = highest inbox rate. No heavy HTML, no big banners.
function buildEmail(contact) {
  const firstName = (contact.name || '').split(' ')[0] || 'there';
  // Avoid spam trigger words: "opportunity", "free", "partnership"
  const subject = `Quick question about your bound book — ${contact.business || 'your shop'}`;

  const html = `
<div style="font-family:Georgia,serif;font-size:16px;line-height:1.8;color:#1a1a1a;max-width:560px;margin:0 auto;padding:16px">

  <p>Hi ${firstName},</p>

  <p>My name is Arsen — I'm a founder working on <a href="https://boundstack.org" style="color:#C8641A">BoundStack</a>, an electronic bound book and FFL compliance tool built specifically for dealers like you.</p>

  <p>Quick context: in FY2024 the ATF revoked <strong>195 FFL licenses</strong> — up 122% from the year before. Most violations weren't intentional. They came from late A&amp;D entries, incomplete 4473s, and records that took too long to pull when the IOI showed up.</p>

  <p>BoundStack keeps your bound book, e4473, and NICS in one place — so everything's linked, nothing falls through the cracks, and you can pull any record in under 30 seconds during an inspection.</p>

  <p><strong>It's free to start. No contract, no setup fees.</strong></p>

  <p>Would you be open to taking a quick look? Happy to answer any questions over email or jump on a 15-minute call at your convenience.</p>

  <p>
    Best,<br>
    <strong>Arsen</strong><br>
    Founder, BoundStack<br>
    <a href="https://boundstack.org" style="color:#C8641A">boundstack.org</a>
  </p>

  <p style="font-size:12px;color:#999;border-top:1px solid #eee;margin-top:24px;padding-top:12px">
    You're receiving this because you hold an active FFL license.<br>
    To unsubscribe, reply with "unsubscribe" — I'll remove you right away.
  </p>

</div>`.trim();

  const text = `Hi ${firstName},

My name is Arsen — I'm a founder working on BoundStack (boundstack.org), an electronic bound book and FFL compliance tool built specifically for dealers like you.

Quick context: in FY2024 the ATF revoked 195 FFL licenses — up 122% from the year before. Most violations weren't intentional. They came from late A&D entries, incomplete 4473s, and records that took too long to pull when the IOI showed up.

BoundStack keeps your bound book, e4473, and NICS in one place — so everything's linked, nothing falls through the cracks, and you can pull any record in under 30 seconds during an inspection.

It's free to start. No contract, no setup fees.

Would you be open to taking a quick look? Happy to answer any questions over email or jump on a 15-minute call at your convenience.

Best,
Arsen
Founder, BoundStack
boundstack.org

---
To unsubscribe, reply with "unsubscribe" — I'll remove you right away.`;

  return { subject, html, text };
}

// ── Helpers ──────────────────────────────────
const sleep = ms => new Promise(r => setTimeout(r, ms));

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}`;
  console.log(line);
  fs.appendFileSync(LOG_FILE, line + '\n');
}

// ── Main ─────────────────────────────────────
async function main() {
  if (!resend && !gmail) {
    console.error('❌ No email provider. Set RESEND_API_KEY or EMAIL_USER/EMAIL_PASS in .env');
    process.exit(1);
  }

  if (!fs.existsSync(LIST_FILE)) {
    console.error(`❌ Email list not found: ${LIST_FILE}`);
    console.error('Create emails.json: [{"name":"...","business":"...","email":"..."}]');
    process.exit(1);
  }

  const all   = JSON.parse(fs.readFileSync(LIST_FILE, 'utf8'));
  const batch = all.slice(START - 1, END);

  const provider = resend ? 'Resend' : 'Gmail';
  console.log(`\n📧 BoundStack Cold Email Sender`);
  console.log(`   Provider: ${provider}${resend && gmail ? ' (Gmail fallback ready)' : ''}`);
  console.log(`   Batch:    ${START}–${END} (${batch.length} contacts)`);
  console.log(`   Delay:    ${DELAY_MS / 1000}s between sends`);
  console.log(`   ETA:      ~${Math.round((batch.length * DELAY_MS) / 60000)} min\n`);

  if (gmail) {
    try { await gmail.verify(); console.log('✅ Gmail SMTP connected'); } catch (e) { console.warn('⚠️  Gmail SMTP issue:', e.message); }
  }

  let sent = 0, failed = 0;

  for (let i = 0; i < batch.length; i++) {
    const contact = batch[i];
    const num = START + i;

    if (!contact.email || !contact.email.includes('@')) {
      log(`SKIP [${num}] ${contact.name || '?'} — invalid email`);
      continue;
    }

    const { subject, html, text } = buildEmail(contact);

    try {
      const result = await send({ to: contact.email, subject, html, text });
      sent++;
      log(`SENT [${num}/${END}] via ${result.provider} → ${contact.email}`);
    } catch (err) {
      failed++;
      log(`FAIL [${num}] ${contact.email} — ${err.message}`);
    }

    if (i < batch.length - 1) {
      process.stdout.write(`   Next in ${DELAY_MS / 1000}s...`);
      await sleep(DELAY_MS);
      process.stdout.write('\r                       \r');
    }
  }

  console.log(`\n✅ Done!  Sent: ${sent}  |  Failed: ${failed}  |  Total: ${batch.length}`);
  console.log(`   Log: ${LOG_FILE}`);
}

main().catch(err => { console.error('Fatal:', err.message); process.exit(1); });
