const { Resend } = require('resend');

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

const APP_URL = process.env.APP_URL || 'http://localhost:3000';
const FROM    = 'BoundStack <hello@boundstack.org>';

async function sendMail({ to, subject, html }) {
  if (!resend) {
    console.log('\n📧 [EMAIL — no RESEND_API_KEY configured, showing in console]');
    console.log(`To: ${to}`);
    console.log(`Subject: ${subject}`);
    console.log(`Body: ${html.replace(/<[^>]+>/g, '')}\n`);
    return;
  }
  const { error } = await resend.emails.send({ from: FROM, to, subject, html });
  if (error) {
    console.error('[Resend error]', error);
    throw new Error(error.message || 'Failed to send email');
  }
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

async function sendVerificationCode(user, code) {
  await sendMail({
    to: user.email,
    subject: 'BoundStack — Your Verification Code',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;background:#06080F;padding:32px;border-radius:12px">
        <div style="text-align:center;margin-bottom:24px">
          <div style="display:inline-block;background:linear-gradient(135deg,#C8641A,#8B3A0A);border-radius:10px;padding:14px 20px;margin-bottom:16px">
            <span style="font-family:Arial,sans-serif;font-size:20px;font-weight:900;color:#fff;letter-spacing:.1em">BOUNDSTACK</span>
          </div>
        </div>
        <h2 style="color:#E8EFF8;text-align:center;margin:0 0 8px;font-size:26px">Verify Your Email</h2>
        <p style="color:#7A8BA0;text-align:center;margin:0 0 32px;font-size:15px">Hi ${user.name}, enter this code to activate your account:</p>
        <div style="background:#0D1220;border:2px solid #C8641A;border-radius:12px;padding:28px;text-align:center;margin-bottom:28px">
          <div style="font-family:monospace;font-size:48px;font-weight:900;color:#C8641A;letter-spacing:.3em;line-height:1">${code}</div>
          <div style="color:#7A8BA0;font-size:12px;margin-top:12px;letter-spacing:.08em;text-transform:uppercase">This code expires in 15 minutes</div>
        </div>
        <p style="color:#7A8BA0;font-size:13px;text-align:center;margin:0">If you didn't sign up for BoundStack, you can safely ignore this email.</p>
        <hr style="border:none;border-top:1px solid #1F2E46;margin:24px 0">
        <p style="color:#3A4A60;font-size:11px;text-align:center;letter-spacing:.06em;text-transform:uppercase">BoundStack — Compliant FFL Management Software</p>
      </div>
    `
  });
}

async function sendLayawayReminder({ shopName, customerName, customerEmail, firearmDesc, totalAmount, amountPaid, installmentAmt, nextDueDate }) {
  const remaining = (parseFloat(totalAmount) - parseFloat(amountPaid)).toFixed(2);
  const pct = Math.round((parseFloat(amountPaid) / parseFloat(totalAmount)) * 100);
  await sendMail({
    to: customerEmail,
    subject: `Payment Reminder — Your Layaway at ${shopName}`,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;background:#06080F;padding:32px;border-radius:12px">
        <div style="text-align:center;margin-bottom:24px">
          <div style="display:inline-block;background:linear-gradient(135deg,#C8641A,#8B3A0A);border-radius:10px;padding:12px 20px">
            <span style="font-size:18px;font-weight:900;color:#fff;letter-spacing:.1em">BOUNDSTACK</span>
          </div>
        </div>
        <h2 style="color:#E8EFF8;text-align:center;margin:0 0 6px;font-size:22px">Layaway Payment Reminder</h2>
        <p style="color:#7A8BA0;text-align:center;margin:0 0 28px;font-size:14px">Hi ${customerName}, you have a payment coming up at <strong style="color:#C8641A">${shopName}</strong>.</p>

        <div style="background:#0D1220;border:1px solid #1F2E46;border-radius:12px;padding:24px;margin-bottom:20px">
          <div style="color:#7A8BA0;font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">Item on Layaway</div>
          <div style="color:#E8EFF8;font-size:16px;font-weight:700;margin-bottom:20px">${firearmDesc}</div>

          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:20px">
            <div>
              <div style="color:#7A8BA0;font-size:11px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Total Price</div>
              <div style="color:#E8EFF8;font-size:18px;font-weight:800">$${parseFloat(totalAmount).toFixed(2)}</div>
            </div>
            <div>
              <div style="color:#7A8BA0;font-size:11px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Paid So Far</div>
              <div style="color:#4ade80;font-size:18px;font-weight:800">$${parseFloat(amountPaid).toFixed(2)}</div>
            </div>
            <div>
              <div style="color:#7A8BA0;font-size:11px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Remaining</div>
              <div style="color:#C8641A;font-size:18px;font-weight:800">$${remaining}</div>
            </div>
          </div>

          <div style="background:#06080F;border-radius:6px;height:8px;margin-bottom:20px;overflow:hidden">
            <div style="background:linear-gradient(90deg,#C8641A,#E8841A);height:100%;width:${pct}%;border-radius:6px"></div>
          </div>

          <div style="background:rgba(200,100,26,.1);border:1px solid rgba(200,100,26,.3);border-radius:8px;padding:14px;text-align:center">
            <div style="color:#7A8BA0;font-size:12px;margin-bottom:4px">Next Payment Due</div>
            <div style="color:#C8641A;font-size:22px;font-weight:900">${nextDueDate}</div>
            ${installmentAmt ? `<div style="color:#7A8BA0;font-size:12px;margin-top:4px">Payment amount: <strong style="color:#E8EFF8">$${parseFloat(installmentAmt).toFixed(2)}</strong></div>` : ''}
          </div>
        </div>

        <p style="color:#7A8BA0;font-size:12px;text-align:center;margin:0">Questions? Contact <strong style="color:#E8EFF8">${shopName}</strong> directly.</p>
        <hr style="border:none;border-top:1px solid #1F2E46;margin:20px 0">
        <p style="color:#3A4A60;font-size:11px;text-align:center;letter-spacing:.06em;text-transform:uppercase">BoundStack — Compliant FFL Management Software</p>
      </div>
    `
  });
}

module.exports = { sendWelcome, sendPasswordReset, sendDemoConfirm, sendVerificationCode, sendLayawayReminder };
