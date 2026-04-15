const nodemailer = require('nodemailer');

const configured = !!(process.env.EMAIL_USER && process.env.EMAIL_PASS);

const transporter = configured
  ? nodemailer.createTransport({
      host: process.env.EMAIL_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.EMAIL_PORT) || 587,
      secure: false,
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    })
  : null;

const APP_URL = process.env.APP_URL || 'http://localhost:3000';
const FROM    = process.env.EMAIL_FROM || 'BoundStack <hello@boundstack.org>';

async function sendMail({ to, subject, html }) {
  if (!configured) {
    console.log('\n📧 [EMAIL — no SMTP configured, showing in console]');
    console.log(`To: ${to}`);
    console.log(`Subject: ${subject}`);
    console.log(`Body: ${html.replace(/<[^>]+>/g, '')}\n`);
    return;
  }
  await transporter.sendMail({ from: FROM, to, subject, html });
}

// ── Templates ────────────────────────────────

async function sendWelcome(user) {
  await sendMail({
    to: user.email,
    subject: 'Welcome to BoundStack — Your FFL Dashboard is Ready',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto">
        <h2 style="color:#c41e3a">Welcome to BoundStack, ${user.name}!</h2>
        <p>Your account is ready. You can now manage your A&D book, customers, and ATF compliance — all in one place.</p>
        <a href="${APP_URL}/app" style="display:inline-block;background:#c41e3a;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;margin:16px 0">Open Dashboard →</a>
        <p style="color:#666;font-size:13px">If you have any questions, reply to this email.</p>
        <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
        <p style="color:#999;font-size:12px">BoundStack — Compliant FFL Management Software</p>
      </div>
    `
  });
}

async function sendPasswordReset(user, token) {
  const link = `${APP_URL}/reset-password?token=${token}`;
  await sendMail({
    to: user.email,
    subject: 'BoundStack — Reset Your Password',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto">
        <h2 style="color:#c41e3a">Reset Your Password</h2>
        <p>Hi ${user.name}, we received a request to reset your BoundStack password.</p>
        <a href="${link}" style="display:inline-block;background:#c41e3a;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;margin:16px 0">Reset Password →</a>
        <p style="color:#666;font-size:13px">This link expires in <strong>1 hour</strong>. If you didn't request this, ignore this email.</p>
        <p style="color:#999;font-size:12px;word-break:break-all">Or copy this link: ${link}</p>
        <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
        <p style="color:#999;font-size:12px">BoundStack — Compliant FFL Management Software</p>
      </div>
    `
  });
}

async function sendDemoConfirm(demo) {
  await sendMail({
    to: demo.email,
    subject: 'BoundStack Demo Request Received',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto">
        <h2 style="color:#c41e3a">Demo Request Confirmed</h2>
        <p>Hi ${demo.name}, we received your demo request!</p>
        <p>We'll reach out within <strong>1 business day</strong> to schedule your 15-minute walkthrough.</p>
        <p style="color:#666;font-size:13px">Questions? Reply to this email.</p>
        <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
        <p style="color:#999;font-size:12px">BoundStack — Compliant FFL Management Software</p>
      </div>
    `
  });
}

module.exports = { sendWelcome, sendPasswordReset, sendDemoConfirm };
