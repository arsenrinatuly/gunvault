// GunVault — Database Backup Script
// Run: node backup.js
// Schedule: add to Windows Task Scheduler or cron

const fs   = require('fs');
const path = require('path');

const DB_PATH      = path.join(__dirname, 'gunvault.db');
const BACKUP_DIR   = path.join(__dirname, 'backups');
const MAX_BACKUPS  = 30; // keep last 30 backups

function pad(n) { return String(n).padStart(2, '0'); }

function getTimestamp() {
  const d = new Date();
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}_${pad(d.getHours())}-${pad(d.getMinutes())}`;
}

function run() {
  if (!fs.existsSync(DB_PATH)) {
    console.log('[BACKUP] gunvault.db not found. Run the server first to create the database.');
    process.exit(1);
  }

  if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR);

  const filename = `gunvault_${getTimestamp()}.db`;
  const dest     = path.join(BACKUP_DIR, filename);

  fs.copyFileSync(DB_PATH, dest);
  console.log(`[BACKUP] Created: backups/${filename}`);

  // Clean old backups
  const files = fs.readdirSync(BACKUP_DIR)
    .filter(f => f.endsWith('.db'))
    .sort();

  if (files.length > MAX_BACKUPS) {
    const toDelete = files.slice(0, files.length - MAX_BACKUPS);
    toDelete.forEach(f => {
      fs.unlinkSync(path.join(BACKUP_DIR, f));
      console.log(`[BACKUP] Deleted old backup: ${f}`);
    });
  }

  const stats = fs.statSync(dest);
  console.log(`[BACKUP] Size: ${(stats.size / 1024).toFixed(1)} KB`);
  console.log(`[BACKUP] Total backups kept: ${Math.min(files.length, MAX_BACKUPS)}`);
}

run();
