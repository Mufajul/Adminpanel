#!/usr/bin/env node
'use strict';
/*
 * Raaz — Backend API + Admin Panel server
 * Node.js built-ins only (http, crypto, fs, path, node:sqlite). No npm deps.
 * ONE backend + ONE database shared by the Android app (com.raazindia.raaz)
 * and the web admin panel. Start: node server.js  (PORT env, default 8080)
 */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 8080;
const DIR = __dirname;
const DB_PATH = process.env.RAAZ_DB || path.join(DIR, 'raaz.db');
const PUBLIC_DIR = fs.existsSync(path.join(DIR, 'public', 'admin.html')) ? path.join(DIR, 'public') : DIR; // flat-repo layout (GitHub upload) bhi chalega
const UPLOAD_DIR = process.env.RAAZ_UPLOADS || path.join(PUBLIC_DIR, 'uploads');

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;');

/* ---------------- schema ---------------- */
db.exec(`
CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,email TEXT UNIQUE,pass_hash TEXT,role TEXT,created_at TEXT,last_login_at TEXT);
CREATE TABLE IF NOT EXISTS admin_logins(id INTEGER PRIMARY KEY AUTOINCREMENT,admin_id INTEGER,ip TEXT,success INTEGER,at TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,kind TEXT,subject_id INTEGER,created_at TEXT,expires_at TEXT);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,email TEXT UNIQUE,password_hash TEXT,provider TEXT DEFAULT 'email',is_guest INTEGER DEFAULT 0,is_pro INTEGER DEFAULT 0,pro_plan_id INTEGER,pro_expiry TEXT,coins_cached INTEGER DEFAULT 0,status TEXT DEFAULT 'active',app_version TEXT,created_at TEXT,last_active_at TEXT);
CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,description TEXT,thumb_url TEXT,sort INTEGER DEFAULT 0,visible INTEGER DEFAULT 1,home INTEGER DEFAULT 1,feeds INTEGER DEFAULT 1,shorts INTEGER DEFAULT 1,default_coin_policy TEXT DEFAULT 'inherit',default_ads TEXT DEFAULT '{}',free_pro_visibility TEXT DEFAULT 'all');
CREATE TABLE IF NOT EXISTS videos(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT,description TEXT,thumb_url TEXT,source_type TEXT DEFAULT 'mp4',source_url TEXT,category_id INTEGER,tags TEXT,language TEXT DEFAULT 'Hindi',duration_sec INTEGER DEFAULT 0,status TEXT DEFAULT 'published',published_at TEXT,scheduled_at TEXT,expires_at TEXT,access_type TEXT DEFAULT 'free',coin_price INTEGER DEFAULT 0,pro_free INTEGER DEFAULT 1,featured INTEGER DEFAULT 0,is_short INTEGER DEFAULT 0,provider_name TEXT,views INTEGER DEFAULT 0,sort INTEGER DEFAULT 0,subtitles_url TEXT,warning TEXT,search_keywords TEXT,ads TEXT DEFAULT '{}');
CREATE TABLE IF NOT EXISTS home_sections(key TEXT PRIMARY KEY,title TEXT,visible INTEGER DEFAULT 1,sort INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS feed_collections(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT,description TEXT,layout TEXT DEFAULT 'vertical',sort INTEGER DEFAULT 0,visible INTEGER DEFAULT 1,scheduled_at TEXT);
CREATE TABLE IF NOT EXISTS feed_items(id INTEGER PRIMARY KEY AUTOINCREMENT,collection_id INTEGER,video_id INTEGER,sort INTEGER DEFAULT 0,pinned INTEGER DEFAULT 0,sponsored INTEGER DEFAULT 0,UNIQUE(collection_id,video_id));
CREATE TABLE IF NOT EXISTS watch_history(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,video_id INTEGER,progress_sec INTEGER DEFAULT 0,duration_sec INTEGER DEFAULT 0,updated_at TEXT,UNIQUE(user_id,video_id));
CREATE TABLE IF NOT EXISTS plays(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,video_id INTEGER,at TEXT,watch_sec INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS watch_later(user_id INTEGER,video_id INTEGER,PRIMARY KEY(user_id,video_id));
CREATE TABLE IF NOT EXISTS likes(user_id INTEGER,video_id INTEGER,PRIMARY KEY(user_id,video_id));
CREATE TABLE IF NOT EXISTS unlocks(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,video_id INTEGER,price INTEGER,at TEXT,UNIQUE(user_id,video_id));
CREATE TABLE IF NOT EXISTS coin_ledger(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,type TEXT,amount INTEGER,balance_before INTEGER,balance_after INTEGER,ref_type TEXT,ref_id TEXT,status TEXT DEFAULT 'completed',source TEXT,idempotency_key TEXT UNIQUE,created_at TEXT);
CREATE TABLE IF NOT EXISTS plans(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,duration_days INTEGER,price REAL,currency TEXT DEFAULT 'INR',benefits TEXT,ad_free INTEGER DEFAULT 1,pro_access INTEGER DEFAULT 1,coin_discount_pct INTEGER DEFAULT 0,enabled INTEGER DEFAULT 1,sort INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS coin_packages(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,base_coins INTEGER,bonus_coins INTEGER DEFAULT 0,total_coins INTEGER,price REAL,currency TEXT DEFAULT 'INR',popular INTEGER DEFAULT 0,enabled INTEGER DEFAULT 1,sort INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS payment_claims(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,package_id INTEGER,plan_id INTEGER,amount REAL,currency TEXT DEFAULT 'INR',method TEXT,utr TEXT UNIQUE,status TEXT DEFAULT 'pending',reviewer_id INTEGER,review_reason TEXT,created_at TEXT,reviewed_at TEXT);
CREATE TABLE IF NOT EXISTS reward_config(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE IF NOT EXISTS reward_claims(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,task_key TEXT,amount INTEGER,day TEXT,created_at TEXT,UNIQUE(user_id,task_key,day));
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT,body TEXT,image_url TEXT,deep_link TEXT,audience TEXT,status TEXT DEFAULT 'awaiting_provider',scheduled_at TEXT,sent_at TEXT,created_by INTEGER,created_at TEXT);
CREATE TABLE IF NOT EXISTS app_settings(key TEXT PRIMARY KEY,value TEXT,updated_by INTEGER,updated_at TEXT);
CREATE TABLE IF NOT EXISTS app_version(id INTEGER PRIMARY KEY CHECK(id=1),latest_name TEXT,latest_code INTEGER,min_code INTEGER,force_update INTEGER DEFAULT 0,store_url TEXT,release_notes TEXT);
CREATE TABLE IF NOT EXISTS ad_networks(id INTEGER PRIMARY KEY CHECK(id=1), json TEXT);
CREATE TABLE IF NOT EXISTS branding(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE IF NOT EXISTS payment_config(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,video_id INTEGER,reason TEXT,status TEXT DEFAULT 'open',created_at TEXT,resolved_by INTEGER,resolution TEXT);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,admin_id INTEGER,action TEXT,entity TEXT,entity_id TEXT,reason TEXT,detail TEXT,at TEXT);
CREATE TABLE IF NOT EXISTS db_backups(id INTEGER PRIMARY KEY AUTOINCREMENT,filename TEXT,created_at TEXT,note TEXT);
`);

/* Lightweight migrations for DBs created by earlier builds */
try { db.exec('ALTER TABLE notifications ADD COLUMN target_user_id INTEGER'); } catch (_) {}

/* ---------------- helpers ---------------- */
const now = () => new Date().toISOString();
const today = () => new Date().toISOString().slice(0, 10);
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const h = crypto.pbkdf2Sync(pw, salt, 100000, 32, 'sha256').toString('hex');
  return salt + ':' + h;
}
function verifyPassword(pw, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, h] = stored.split(':');
  const calc = crypto.pbkdf2Sync(pw, salt, 100000, 32, 'sha256').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(calc, 'hex'));
}
function makeToken(kind, subjectId, days = 30) {
  const token = crypto.randomBytes(32).toString('hex');
  const exp = new Date(Date.now() + days * 864e5).toISOString();
  db.prepare('INSERT INTO sessions(token,kind,subject_id,created_at,expires_at) VALUES(?,?,?,?,?)')
    .run(token, kind, subjectId, now(), exp);
  return token;
}
function getSession(token) {
  if (!token) return null;
  const s = db.prepare('SELECT * FROM sessions WHERE token=?').get(token);
  if (!s) return null;
  if (s.expires_at < now()) { db.prepare('DELETE FROM sessions WHERE token=?').run(token); return null; }
  return s;
}
function audit(adminId, action, entity, entityId, reason, detail) {
  db.prepare('INSERT INTO audit_log(admin_id,action,entity,entity_id,reason,detail,at) VALUES(?,?,?,?,?,?,?)')
    .run(adminId || null, action, entity || null, entityId != null ? String(entityId) : null, reason || null, detail ? JSON.stringify(detail) : null, now());
}
function ledger(userId, type, amount, refType, refId, source, idemKey) {
  // Must be called inside a transaction for money-moving operations.
  const u = db.prepare('SELECT coins_cached FROM users WHERE id=?').get(userId);
  if (!u) throw new Error('user not found');
  const before = u.coins_cached, after = before + amount;
  const info = db.prepare('INSERT INTO coin_ledger(user_id,type,amount,balance_before,balance_after,ref_type,ref_id,status,source,idempotency_key,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
    .run(userId, type, amount, before, after, refType || null, refId != null ? String(refId) : null, 'completed', source || 'server', idemKey || null, now());
  db.prepare('UPDATE users SET coins_cached=? WHERE id=?').run(after, userId);
  return { ledgerId: info.lastInsertRowid, balance: after };
}
function tx(fn) {
  db.exec('BEGIN IMMEDIATE');
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { try { db.exec('ROLLBACK'); } catch (_) {} throw e; }
}
function publicUser(u) {
  if (!u) return null;
  return { id: u.id, name: u.name, email: u.is_guest ? null : u.email, provider: u.provider, is_guest: !!u.is_guest, is_pro: !!u.is_pro && (!u.pro_expiry || u.pro_expiry > now()), pro_expiry: u.pro_expiry, coins: u.coins_cached, status: u.status, created_at: u.created_at };
}
const DEFAULT_ADS = { enabled: true, native: true, preroll: false, midroll: false, postroll: false, banner: true, max_freq: 3, min_interval_sec: 300, free_users: true, pro_users: false, rewarded: true, ad_free_override: false };
/* AdMob precedence (documented): 1) legal/consent + global shutdown, 2) individual
   video override, 3) category default_ads, 4) global defaults. Resolved server-side
   here so the app always receives the effective per-video ad config. */
function resolveAds(v, catRow) {
  let videoAds = {}; try { videoAds = JSON.parse(v.ads || '{}'); } catch (_) {}
  let catAds = {}; if (catRow) { try { catAds = JSON.parse(catRow.default_ads || '{}'); } catch (_) {} }
  const eff = Object.assign({}, DEFAULT_ADS, catAds, videoAds);
  const s = getSettings();
  if (!bool(s.admob_enabled)) {
    Object.keys(eff).forEach(k => { if (typeof eff[k] === 'boolean') eff[k] = false; });
    eff.enabled = false; eff.resolved_from = 'global_off';
  } else if (eff.ad_free_override) {
    ['native', 'preroll', 'midroll', 'postroll', 'banner', 'rewarded'].forEach(k => eff[k] = false);
    eff.enabled = false; eff.resolved_from = 'video_ad_free_override';
  } else {
    eff.resolved_from = Object.keys(videoAds).length ? 'video' : (Object.keys(catAds).length ? 'category' : 'global_default');
  }
  return eff;
}
function videoOut(v) {
  if (!v) return null;
  const cat = v.category_id ? db.prepare('SELECT * FROM categories WHERE id=?').get(v.category_id) : null;
  return {
    id: v.id, title: v.title, description: v.description, thumb_url: v.thumb_url, source_type: v.source_type,
    source_url: v.source_url, category_id: v.category_id, category_name: cat ? cat.name : null, tags: v.tags,
    language: v.language, duration_sec: v.duration_sec, published_at: v.published_at, status: v.status,
    access_type: v.access_type, coin_price: v.coin_price, pro_free: !!v.pro_free, featured: !!v.featured,
    is_short: !!v.is_short, provider_name: v.provider_name, views: v.views, sort: v.sort,
    subtitles_url: v.subtitles_url, warning: v.warning, ads: resolveAds(v, cat),
    ads_raw: (() => { try { return JSON.parse(v.ads || '{}'); } catch (_) { return {}; } })()
  };
}
const visibleVideoSQL = `status='published' AND (scheduled_at IS NULL OR scheduled_at<=?) AND (expires_at IS NULL OR expires_at>?)`;
function publishedVideos() {
  const t = now();
  return db.prepare(`SELECT * FROM videos WHERE ${visibleVideoSQL} ORDER BY sort ASC, id DESC`).all(t, t);
}

/* ---------------- seed ---------------- */
function seed() {
  if (!db.prepare('SELECT id FROM admins LIMIT 1').get()) {
    db.prepare('INSERT INTO admins(name,email,pass_hash,role,created_at) VALUES(?,?,?,?,?)')
      .run('Super Admin', 'admin@raaz.app', hashPassword('RaazAdmin@123'), 'super_admin', now());
  }
  if (!db.prepare("SELECT id FROM users WHERE email='demo@raaz.app'").get()) {
    const info = db.prepare('INSERT INTO users(name,email,password_hash,provider,is_guest,coins_cached,created_at,last_active_at) VALUES(?,?,?,?,?,0,?,?)')
      .run('Demo User', 'demo@raaz.app', hashPassword('demo1234'), 'email', 0, now(), now());
    ledger(Number(info.lastInsertRowid), 'promo', 100, 'seed', 'welcome', 'system', 'seed-demo-100');
  }
  const catCount = db.prepare('SELECT COUNT(*) c FROM categories').get().c;
  if (!catCount) {
    const ins = db.prepare('INSERT INTO categories(name,description,sort,visible,home,feeds,shorts) VALUES(?,?,?,?,1,1,1)');
    ['Movies', 'Music', 'Comedy', 'Kids', 'News', 'Sports'].forEach((n, i) => ins.run(n, n + ' videos', i));
  }
  const vidCount = db.prepare('SELECT COUNT(*) c FROM videos').get().c;
  if (!vidCount) {
    const bucket = 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/';
    const catId = name => (db.prepare('SELECT id FROM categories WHERE name=?').get(name) || {}).id;
    const ins = db.prepare(`INSERT INTO videos(title,description,thumb_url,source_type,source_url,category_id,tags,language,duration_sec,status,published_at,access_type,coin_price,pro_free,featured,is_short,provider_name,views,ads)
      VALUES(?,?,?,?,?,?,?,?,?,'published',?,?,?,?,?,?,?,?,?)`);
    const ads = JSON.stringify(DEFAULT_ADS);
    ins.run('Big Buck Bunny', 'A giant rabbit takes revenge on three bullying rodents.', 'https://picsum.photos/seed/raaz-bbb/640/360', 'mp4', bucket + 'BigBuckBunny.mp4', catId('Kids'), 'animation,family', 'English', 596, now(), 'free', 0, 1, 1, 0, 'Sample Studio', 1520, ads);
    ins.run('Sintel', 'A lonely young woman searches for the dragon she once befriended.', 'https://picsum.photos/seed/raaz-sintel/640/360', 'mp4', bucket + 'Sintel.mp4', catId('Movies'), 'fantasy,adventure', 'English', 888, now(), 'free_ads', 0, 1, 1, 0, 'Raaz Originals', 2310, ads);
    ins.run('Tears of Steel', 'A group of scientists stage a reenactment to save the future.', 'https://picsum.photos/seed/raaz-tos/640/360', 'mp4', bucket + 'TearsOfSteel.mp4', catId('Movies'), 'sci-fi,robots', 'English', 734, now(), 'coin', 10, 1, 0, 0, 'Raaz Originals', 980, ads);
    ins.run('Elephants Dream', 'A surreal journey through an infinite machine.', 'https://picsum.photos/seed/raaz-ed/640/360', 'mp4', bucket + 'ElephantsDream.mp4', catId('Movies'), 'surreal,animation', 'English', 653, now(), 'pro', 0, 1, 0, 0, 'Sample Studio', 640, ads);
    ins.run('HLS Test Stream', 'Adaptive HLS sample stream (Mux test).', 'https://picsum.photos/seed/raaz-hls/640/360', 'hls', 'https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8', catId('Sports'), 'live,test', 'English', 600, now(), 'coin', 50, 1, 0, 0, 'Sample Studio', 410, ads);
    ins.run('For Bigger Blazes', 'Short sample clip.', 'https://picsum.photos/seed/raaz-blazes/360/640', 'mp4', bucket + 'ForBiggerBlazes.mp4', catId('Comedy'), 'short,fun', 'English', 15, now(), 'free', 0, 1, 0, 1, 'Sample Studio', 5200, ads);
    ins.run('For Bigger Escapes', 'Short sample clip.', 'https://picsum.photos/seed/raaz-escapes/360/640', 'mp4', bucket + 'ForBiggerEscapes.mp4', catId('Comedy'), 'short,fun', 'English', 15, now(), 'free', 0, 1, 0, 1, 'Sample Studio', 4300, ads);
  }
  if (!db.prepare('SELECT id FROM plans LIMIT 1').get()) {
    db.prepare('INSERT INTO plans(name,duration_days,price,currency,benefits,ad_free,pro_access,coin_discount_pct,enabled,sort) VALUES(?,?,?,?,?,1,1,0,1,?)')
      .run('Monthly', 30, 149, 'INR', 'Ad-free playback, Pro-only videos, exclusive collections', 0);
    db.prepare('INSERT INTO plans(name,duration_days,price,currency,benefits,ad_free,pro_access,coin_discount_pct,enabled,sort) VALUES(?,?,?,?,?,1,1,10,1,?)')
      .run('Annual', 365, 999, 'INR', 'Everything in Monthly + 10% off coin unlocks + priority support', 1);
  }
  if (!db.prepare('SELECT id FROM coin_packages LIMIT 1').get()) {
    const ins = db.prepare('INSERT INTO coin_packages(name,base_coins,bonus_coins,total_coins,price,currency,popular,enabled,sort) VALUES(?,?,?,?,?,?,?,1,?)');
    ins.run('1K Coins', 1000, 0, 1000, 79, 'INR', 0, 0);
    ins.run('3K Coins', 3000, 150, 3150, 199, 'INR', 1, 1);
    ins.run('12K Coins', 12000, 1200, 13200, 599, 'INR', 0, 2);
    ins.run('15K Coins', 15000, 1800, 16800, 699, 'INR', 0, 3);
    ins.run('20K Coins', 20000, 3000, 23000, 899, 'INR', 1, 4);
  }
  if (!db.prepare("SELECT key FROM reward_config WHERE key='config'").get()) {
    const cfg = {
      checkin_amounts: [330, 350, 400, 450, 550, 600, 700],
      tasks: {
        daily_checkin: { enabled: true, title: 'Daily Check-in', daily_limit: 1 },
        rewarded_ad: { enabled: true, title: 'Rewarded Ad', amount: 20, daily_limit: 10, note: 'Coins granted only after AdMob server-side verification (awaiting credentials)' },
        referral: { enabled: true, title: 'Referral Reward', amount: 100, daily_limit: 5 },
        engagement: { enabled: true, title: 'Engagement Rewards', amount: 10, daily_limit: 3 }
      }
    };
    db.prepare('INSERT INTO reward_config(key,value) VALUES(?,?)').run('config', JSON.stringify(cfg));
  }
  const defaults = {
    service_enabled: '1', maintenance: '0', maintenance_message: '', home_enabled: '1', shorts_enabled: '1',
    feeds_enabled: '1', search_enabled: '1', subscriptions_enabled: '1', library_enabled: '1', playback_enabled: '1',
    mp4_enabled: '1', hls_enabled: '1', mkv_enabled: '1', pro_purchase_enabled: '1', coin_purchase_enabled: '1',
    coin_unlock_enabled: '1', rewarded_ads_enabled: '1', admob_enabled: '1', notifications_enabled: '1',
    guest_browsing: '1', google_signin_enabled: '0', email_signin_enabled: '1',
    pay_manual_enabled: '1', pay_paypal_enabled: '0', pay_paytm_enabled: '0',
    admob_app_id: '', feeds_ads_enabled: '1', feeds_native_ads: '1', feeds_ad_frequency: '4'
  };
  const insSet = db.prepare('INSERT OR IGNORE INTO app_settings(key,value) VALUES(?,?)');
  for (const [k, v] of Object.entries(defaults)) insSet.run(k, v);
  // Literal defaults (AD_NETWORKS_DEFAULT const is declared later in the file; seed() runs first)
  db.prepare('INSERT OR IGNORE INTO ad_networks(id,json) VALUES(1,?)').run(JSON.stringify({ monetag: { enabled: false, zone_id: '', script_url: '' }, adsterra: { enabled: false, banner_key: '', native_key: '' } }));
  if (!db.prepare('SELECT id FROM app_version WHERE id=1').get()) {
    db.prepare('INSERT INTO app_version(id,latest_name,latest_code,min_code,force_update,store_url,release_notes) VALUES(1,?,?,?,?,?,?)')
      .run('1.0.0', 1, 1, 0, 'https://play.google.com/store/apps/details?id=com.raazindia.raaz', 'Initial release');
  }
  const brandDefaults = { app_name: 'Raaz', primary_color: '#fa3e55', tagline: 'Premium Video Streaming', logo_url: '', splash_url: '', home_banner_url: '', default_avatar_url: '', placeholder_thumb_url: 'https://picsum.photos/seed/raaz/640/360' };
  const insB = db.prepare('INSERT OR IGNORE INTO branding(key,value) VALUES(?,?)');
  for (const [k, v] of Object.entries(brandDefaults)) insB.run(k, v);
  const payDefaults = { qr_url: '', payee_name: '', upi_id: '', instructions: 'Pay using any UPI app, then enter the UTR / transaction reference in the app.', help_text: 'Coins are credited only after manual verification by the admin team.', claim_expiry_hours: '24', paypal_mode: 'sandbox', paypal_client_id: '', paypal_secret: '', paytm_mode: 'sandbox', paytm_mid: '', paytm_key: '', onesignal_app_id: '', onesignal_api_key: '' };
  const insP = db.prepare('INSERT OR IGNORE INTO payment_config(key,value) VALUES(?,?)');
  for (const [k, v] of Object.entries(payDefaults)) insP.run(k, v);
  if (!db.prepare("SELECT key FROM home_sections LIMIT 1").get()) {
    const ins = db.prepare('INSERT INTO home_sections(key,title,visible,sort) VALUES(?,?,1,?)');
    [['featured', 'Featured', 0], ['trending', 'Trending', 1], ['popular', 'Popular', 2], ['new_releases', 'New Releases', 3], ['recommended', 'Recommended', 4], ['premium', 'Premium Videos', 5], ['coin_unlock', 'Coin Unlock Videos', 6], ['categories', 'Categories', 7], ['sponsored', 'Sponsored', 8]]
      .forEach(([k, t, s]) => ins.run(k, t, s));
  }
  if (!db.prepare('SELECT id FROM feed_collections LIMIT 1').get()) {
    const c = db.prepare('INSERT INTO feed_collections(title,description,layout,sort,visible) VALUES(?,?,?,?,1)').run('Today on Raaz', 'Handpicked videos for you', 'vertical', 0);
    const vids = db.prepare('SELECT id FROM videos ORDER BY id LIMIT 4').all();
    const fi = db.prepare('INSERT OR IGNORE INTO feed_items(collection_id,video_id,sort) VALUES(?,?,?)');
    vids.forEach((v, i) => fi.run(Number(c.lastInsertRowid), v.id, i));
  }
}
seed();

/* ---------------- HTTP plumbing ---------------- */
function send(res, status, obj, headers = {}) {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
  res.writeHead(status, Object.assign({ 'Content-Type': typeof obj === 'string' && headers['Content-Type'] ? headers['Content-Type'] : 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Authorization, Content-Type', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' }, headers));
  res.end(body);
}
const err = (res, status, msg) => send(res, status, { error: msg });
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 8 * 1024 * 1024) { reject(new Error('body too large')); req.destroy(); } });
    req.on('end', () => { if (!data) return resolve({}); try { resolve(JSON.parse(data)); } catch (e) { reject(new Error('invalid JSON')); } });
    req.on('error', reject);
  });
}
const routes = [];
function route(method, pattern, opts, handler) {
  if (typeof opts === 'function') { handler = opts; opts = {}; }
  const keys = [];
  const rx = new RegExp('^' + pattern.replace(/:[^/]+/g, m => { keys.push(m.slice(1)); return '([^/]+)'; }) + '$');
  routes.push({ method, rx, keys, opts, handler });
}
function authUser(req, res) {
  const s = getSession((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!s || s.kind !== 'user') { err(res, 401, 'login required'); return null; }
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(s.subject_id);
  if (!u) { err(res, 401, 'user not found'); return null; }
  if (u.status === 'suspended') { err(res, 403, 'account suspended'); return null; }
  db.prepare('UPDATE users SET last_active_at=? WHERE id=?').run(now(), u.id);
  return u;
}
function optionalUser(req) {
  const s = getSession((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!s || s.kind !== 'user') return null;
  return db.prepare('SELECT * FROM users WHERE id=?').get(s.subject_id) || null;
}
const ROLE_WRITE = { videos: ['super_admin', 'content_manager'], categories: ['super_admin', 'content_manager'], feeds: ['super_admin', 'content_manager'], home: ['super_admin', 'content_manager'], plans: ['super_admin', 'payment_manager'], packages: ['super_admin', 'payment_manager'], claims: ['super_admin', 'payment_manager'], users: ['super_admin', 'support_manager'], rewards: ['super_admin', 'payment_manager', 'content_manager'], settings: ['super_admin'], notifications: ['super_admin', 'content_manager', 'support_manager'], reports: ['super_admin', 'support_manager', 'content_manager'] };
function authAdmin(req, res, roles) {
  const s = getSession((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!s || s.kind !== 'admin') { err(res, 401, 'admin login required'); return null; }
  const a = db.prepare('SELECT * FROM admins WHERE id=?').get(s.subject_id);
  if (!a) { err(res, 401, 'admin not found'); return null; }
  if (roles && roles.length && !roles.includes(a.role)) { err(res, 403, 'insufficient role: requires ' + roles.join(' or ')); return null; }
  return a;
}
function getSettings() {
  const o = {};
  db.prepare('SELECT key,value FROM app_settings').all().forEach(r => o[r.key] = r.value);
  return o;
}
/* Extra ad networks (Monetag / Adsterra) — single-row JSON config, admin-managed.
   AdMob stays on its existing controls (global settings + per-video/category rules);
   these networks are additive and only activate when an admin enables them AND
   pastes the network's real zone/key/script values here. Nothing is faked. */
const AD_NETWORKS_DEFAULT = { monetag: { enabled: false, zone_id: '', script_url: '' }, adsterra: { enabled: false, banner_key: '', native_key: '' } };
function getAdNetworks() {
  const out = JSON.parse(JSON.stringify(AD_NETWORKS_DEFAULT));
  try {
    const row = db.prepare('SELECT json FROM ad_networks WHERE id=1').get();
    if (row && row.json) {
      const stored = JSON.parse(row.json);
      for (const net of Object.keys(out)) {
        if (stored && typeof stored[net] === 'object' && stored[net]) {
          for (const k of Object.keys(out[net])) {
            if (k === 'enabled') { if (typeof stored[net][k] === 'boolean') out[net][k] = stored[net][k]; }
            else if (typeof stored[net][k] === 'string') out[net][k] = stored[net][k];
          }
        }
      }
    }
  } catch (_) {}
  return out;
}
const escHtml = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function getBranding() {
  const o = {};
  db.prepare('SELECT key,value FROM branding').all().forEach(r => o[r.key] = r.value);
  return o;
}
const bool = v => v === '1' || v === 1 || v === true;

/* ================= APP API ================= */
route('GET', '/api/config', (req, res) => {
  const s = getSettings(), b = getBranding();
  const v = db.prepare('SELECT * FROM app_version WHERE id=1').get();
  send(res, 200, {
    settings: {
      service_enabled: bool(s.service_enabled), maintenance: bool(s.maintenance), maintenance_message: s.maintenance_message || '',
      home_enabled: bool(s.home_enabled), shorts_enabled: bool(s.shorts_enabled), feeds_enabled: bool(s.feeds_enabled),
      search_enabled: bool(s.search_enabled), playback_enabled: bool(s.playback_enabled), hls_enabled: bool(s.hls_enabled),
      admob_enabled: bool(s.admob_enabled), rewards_enabled: bool(s.rewards_enabled), pro_enabled: bool(s.pro_purchase_enabled),
      coin_purchase_enabled: bool(s.coin_purchase_enabled), guest_browsing: bool(s.guest_browsing)
    },
    version: { latest_name: v.latest_name, latest_code: v.latest_code, min_code: v.min_code, force_update: !!v.force_update, store_url: v.store_url, release_notes: v.release_notes },
    branding: { app_name: b.app_name, primary_color: b.primary_color, tagline: b.tagline, logo_url: b.logo_url, splash_url: b.splash_url },
    adNetworks: getAdNetworks(),
    ads: {
      admob_enabled: bool(s.admob_enabled), admob_app_id: s.admob_app_id || null,
      precedence: 'legal/consent > global_off > video_override > category_default > global_default',
      global_defaults: DEFAULT_ADS,
      feeds: { enabled: bool(s.feeds_ads_enabled), native: bool(s.feeds_native_ads), frequency: Number(s.feeds_ad_frequency || 4) },
      rewarded_enabled: bool(s.rewarded_ads_enabled)
    }
  });
});
function sectionVideos(key, all) {
  switch (key) {
    case 'featured': return all.filter(v => v.featured);
    case 'trending': return [...all].sort((a, b) => b.views - a.views).slice(0, 10);
    case 'popular': return [...all].sort((a, b) => b.views - a.views).slice(0, 10);
    case 'new_releases': return [...all].sort((a, b) => (b.published_at || '').localeCompare(a.published_at || '')).slice(0, 10);
    case 'premium': return all.filter(v => v.access_type === 'pro' || v.access_type === 'pro_coin');
    case 'coin_unlock': return all.filter(v => v.access_type === 'coin' || v.access_type === 'pro_coin');
    case 'sponsored': return all.filter(v => v.featured).slice(0, 4);
    case 'categories': return [];
    default: return all.slice(0, 10);
  }
}
route('GET', '/api/home', (req, res) => {
  const all = publishedVideos().map(videoOut);
  const sections = db.prepare('SELECT * FROM home_sections WHERE visible=1 ORDER BY sort').all()
    .map(s => ({ key: s.key, title: s.title, videos: sectionVideos(s.key, all) }));
  const categories = db.prepare('SELECT * FROM categories WHERE visible=1 AND home=1 ORDER BY sort').all();
  send(res, 200, { featured: all.filter(v => v.featured), sections, categories });
});
route('GET', '/api/feeds', (req, res) => {
  const s = getSettings();
  const feedsAds = { enabled: bool(s.admob_enabled) && bool(s.feeds_ads_enabled), native: bool(s.feeds_native_ads), frequency: Number(s.feeds_ad_frequency || 4), independent_from_home: true };
  if (!bool(s.feeds_enabled)) return send(res, 200, { enabled: false, collections: [], ads: feedsAds });
  const t = now();
  const cols = db.prepare('SELECT * FROM feed_collections WHERE visible=1 AND (scheduled_at IS NULL OR scheduled_at<=?) ORDER BY sort').all(t);
  const collections = cols.map(c => {
    const items = db.prepare('SELECT v.* FROM feed_items fi JOIN videos v ON v.id=fi.video_id WHERE fi.collection_id=? ORDER BY fi.pinned DESC, fi.sort ASC').all(c.id)
      .filter(v => { const o = videoOut(v); return o.status === 'published'; });
    return { id: c.id, title: c.title, description: c.description, layout: c.layout, videos: items.map(videoOut) };
  });
  send(res, 200, { enabled: true, collections, ads: feedsAds });
});
route('GET', '/api/categories', (req, res) => {
  send(res, 200, db.prepare('SELECT * FROM categories WHERE visible=1 ORDER BY sort').all());
});
route('GET', '/api/videos/:id', (req, res, p) => {
  const v = db.prepare('SELECT * FROM videos WHERE id=?').get(p.id);
  if (!v) return err(res, 404, 'video not found');
  const out = videoOut(v);
  const t = now();
  const related = db.prepare(`SELECT * FROM videos WHERE ${visibleVideoSQL} AND id!=? AND (category_id=? OR access_type=?) ORDER BY views DESC LIMIT 8`)
    .all(t, t, v.id, v.category_id, v.access_type).map(videoOut);
  const u = optionalUser(req);
  let unlocked = false;
  if (u) unlocked = !!db.prepare('SELECT id FROM unlocks WHERE user_id=? AND video_id=?').get(u.id, v.id);
  send(res, 200, Object.assign(out, { related, unlocked, can_watch: out.access_type === 'free' || out.access_type === 'free_ads' || unlocked || (u && u.is_pro && out.pro_free) || (u && u.is_pro && out.access_type === 'pro') }));
});
route('GET', '/api/search', (req, res, p, query) => {
  const q = '%' + (query.q || '') + '%';
  const t = now();
  const rows = db.prepare(`SELECT * FROM videos WHERE ${visibleVideoSQL} AND (title LIKE ? OR tags LIKE ? OR search_keywords LIKE ? OR provider_name LIKE ? OR description LIKE ?) ORDER BY views DESC LIMIT 50`)
    .all(t, t, q, q, q, q, q);
  send(res, 200, rows.map(videoOut));
});
route('GET', '/api/shorts', (req, res) => {
  const t = now();
  send(res, 200, db.prepare(`SELECT * FROM videos WHERE ${visibleVideoSQL} AND is_short=1 ORDER BY views DESC`).all(t, t).map(videoOut));
});
route('POST', '/api/auth/register', async (req, res) => {
  const b = await readBody(req);
  if (!b.name || !b.email || !b.password || String(b.password).length < 6) return err(res, 400, 'name, email and password (min 6 chars) required');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(b.email)) return err(res, 400, 'invalid email');
  if (db.prepare('SELECT id FROM users WHERE email=?').get(String(b.email).toLowerCase())) return err(res, 409, 'email already registered');
  const info = db.prepare('INSERT INTO users(name,email,password_hash,provider,created_at,last_active_at) VALUES(?,?,?,?,?,?)')
    .run(b.name, String(b.email).toLowerCase(), hashPassword(b.password), 'email', now(), now());
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(Number(info.lastInsertRowid));
  send(res, 201, { token: makeToken('user', u.id), user: publicUser(u) });
});
route('POST', '/api/auth/login', async (req, res) => {
  const b = await readBody(req);
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(String(b.email || '').toLowerCase());
  if (!u || u.is_guest || !verifyPassword(b.password || '', u.password_hash)) return err(res, 401, 'invalid email or password');
  if (u.status === 'suspended') return err(res, 403, 'account suspended');
  db.prepare('UPDATE users SET last_active_at=? WHERE id=?').run(now(), u.id);
  send(res, 200, { token: makeToken('user', u.id), user: publicUser(u) });
});
route('POST', '/api/auth/guest', async (req, res) => {
  const s = getSettings();
  if (!bool(s.guest_browsing)) return err(res, 403, 'guest browsing disabled');
  const b = await readBody(req);
  if (!b.device_id) return err(res, 400, 'device_id required');
  const email = 'guest-' + crypto.createHash('sha256').update(String(b.device_id)).digest('hex').slice(0, 20) + '@guest.raaz';
  let u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u) {
    const info = db.prepare('INSERT INTO users(name,email,provider,is_guest,created_at,last_active_at) VALUES(?,?,?,?,?,?)')
      .run('Guest', email, 'guest', 1, now(), now());
    u = db.prepare('SELECT * FROM users WHERE id=?').get(Number(info.lastInsertRowid));
  }
  send(res, 200, { token: makeToken('user', u.id), user: publicUser(u) });
});
route('GET', '/api/me', (req, res) => { const u = authUser(req, res); if (u) send(res, 200, publicUser(u)); });
route('POST', '/api/unlock', async (req, res) => {
  const u = authUser(req, res); if (!u) return;
  const s = getSettings();
  if (!bool(s.coin_unlock_enabled)) return err(res, 403, 'coin unlocks are disabled');
  const b = await readBody(req);
  const v = db.prepare('SELECT * FROM videos WHERE id=?').get(b.videoId);
  if (!v) return err(res, 404, 'video not found');
  if (v.access_type !== 'coin' && v.access_type !== 'pro_coin') return err(res, 400, 'video is not coin-unlockable');
  if (u.is_pro && v.pro_free && v.access_type === 'pro_coin') return send(res, 200, { ok: true, already: true, pro: true, balance: u.coins_cached });
  try {
    const result = tx(() => {
      const existing = db.prepare('SELECT id FROM unlocks WHERE user_id=? AND video_id=?').get(u.id, v.id);
      if (existing) return { already: true, balance: db.prepare('SELECT coins_cached FROM users WHERE id=?').get(u.id).coins_cached };
      const fresh = db.prepare('SELECT coins_cached FROM users WHERE id=?').get(u.id);
      if (fresh.coins_cached < v.coin_price) { const e = new Error('insufficient coins'); e.status = 402; throw e; }
      const idem = 'unlock-' + u.id + '-' + v.id;
      if (db.prepare('SELECT id FROM coin_ledger WHERE idempotency_key=?').get(idem)) {
        db.prepare('INSERT OR IGNORE INTO unlocks(user_id,video_id,price,at) VALUES(?,?,?,?)').run(u.id, v.id, v.coin_price, now());
        return { already: true, balance: fresh.coins_cached };
      }
      const led = ledger(u.id, 'unlock', -v.coin_price, 'video', v.id, 'app-unlock', idem);
      db.prepare('INSERT INTO unlocks(user_id,video_id,price,at) VALUES(?,?,?,?)').run(u.id, v.id, v.coin_price, now());
      return { balance: led.balance };
    });
    send(res, 200, { ok: true, already: !!result.already, balance: result.balance });
  } catch (e) { err(res, e.status || 500, e.message); }
});
route('GET', '/api/wallet', (req, res) => {
  const u = authUser(req, res); if (!u) return;
  const earned = db.prepare('SELECT COALESCE(SUM(amount),0) s FROM coin_ledger WHERE user_id=? AND amount>0').get(u.id).s;
  const spent = -db.prepare('SELECT COALESCE(SUM(amount),0) s FROM coin_ledger WHERE user_id=? AND amount<0').get(u.id).s;
  const rows = db.prepare('SELECT * FROM coin_ledger WHERE user_id=? ORDER BY id DESC LIMIT 100').all(u.id);
  send(res, 200, { balance: u.coins_cached, earned, spent, ledger: rows });
});
route('POST', '/api/rewards/checkin', (req, res) => {
  const u = authUser(req, res); if (!u) return;
  if (u.is_guest) return err(res, 403, 'login required to claim rewards');
  const s = getSettings();
  if (!bool(s.rewards_enabled)) return err(res, 403, 'rewards are disabled');
  const cfg = JSON.parse(db.prepare("SELECT value FROM reward_config WHERE key='config'").get().value);
  if (cfg.tasks && cfg.tasks.daily_checkin && !cfg.tasks.daily_checkin.enabled) return err(res, 403, 'daily check-in disabled');
  const dayStr = today();
  if (db.prepare("SELECT id FROM reward_claims WHERE user_id=? AND task_key='daily_checkin' AND day=?").get(u.id, dayStr))
    return err(res, 409, 'already checked in today');
  const streak = db.prepare("SELECT COUNT(*) c FROM reward_claims WHERE user_id=? AND task_key='daily_checkin'").get(u.id).c;
  const amounts = cfg.checkin_amounts && cfg.checkin_amounts.length ? cfg.checkin_amounts : [10];
  const amount = amounts[Math.min(streak, amounts.length - 1)];
  try {
    const r = tx(() => {
      db.prepare("INSERT INTO reward_claims(user_id,task_key,amount,day,created_at) VALUES(?,'daily_checkin',?,?,?)").run(u.id, amount, dayStr, now());
      return ledger(u.id, 'checkin', amount, 'reward', 'daily_checkin', 'app-checkin', 'checkin-' + u.id + '-' + dayStr);
    });
    send(res, 200, { ok: true, amount, balance: r.balance });
  } catch (e) { err(res, 500, e.message); }
});
route('GET', '/api/coins/packages', (req, res) => {
  send(res, 200, db.prepare('SELECT * FROM coin_packages WHERE enabled=1 ORDER BY sort').all());
});
route('GET', '/api/plans', (req, res) => {
  send(res, 200, db.prepare('SELECT * FROM plans WHERE enabled=1 ORDER BY sort').all());
});
route('POST', '/api/payments/claim', async (req, res) => {
  const u = authUser(req, res); if (!u) return;
  if (u.is_guest) return err(res, 403, 'login required to submit a payment claim');
  const b = await readBody(req);
  if (!b.utr || String(b.utr).trim().length < 4) return err(res, 400, 'a valid UTR / transaction reference is required');
  if (!b.packageId && !b.planId) return err(res, 400, 'packageId or planId required');
  let amount, currency = 'INR', pkg = null, plan = null;
  if (b.packageId) { pkg = db.prepare('SELECT * FROM coin_packages WHERE id=? AND enabled=1').get(b.packageId); if (!pkg) return err(res, 404, 'package not found'); amount = pkg.price; currency = pkg.currency; }
  if (b.planId) { plan = db.prepare('SELECT * FROM plans WHERE id=? AND enabled=1').get(b.planId); if (!plan) return err(res, 404, 'plan not found'); amount = plan.price; currency = plan.currency; }
  if (db.prepare('SELECT id FROM payment_claims WHERE utr=?').get(String(b.utr).trim())) return err(res, 409, 'duplicate UTR: this transaction reference has already been submitted');
  try {
    const info = db.prepare('INSERT INTO payment_claims(user_id,package_id,plan_id,amount,currency,method,utr,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)')
      .run(u.id, pkg ? pkg.id : null, plan ? plan.id : null, amount, currency, b.method || 'manual_upi', String(b.utr).trim(), 'pending', now());
    send(res, 201, { ok: true, claim_id: Number(info.lastInsertRowid), status: 'pending', note: 'Coins/Pro are credited only after admin verification.' });
  } catch (e) { err(res, 409, 'duplicate UTR'); }
});
route('GET', '/api/payments/claims', (req, res) => {
  const u = authUser(req, res); if (!u) return;
  send(res, 200, db.prepare('SELECT * FROM payment_claims WHERE user_id=? ORDER BY id DESC').all(u.id));
});
route('POST', '/api/history', async (req, res) => {
  const u = authUser(req, res); if (!u) return;
  const b = await readBody(req);
  if (!b.videoId) return err(res, 400, 'videoId required');
  db.prepare(`INSERT INTO watch_history(user_id,video_id,progress_sec,duration_sec,updated_at) VALUES(?,?,?,?,?)
    ON CONFLICT(user_id,video_id) DO UPDATE SET progress_sec=excluded.progress_sec, duration_sec=excluded.duration_sec, updated_at=excluded.updated_at`)
    .run(u.id, b.videoId, b.progress_sec || 0, b.duration_sec || 0, now());
  send(res, 200, { ok: true });
});
route('GET', '/api/library', (req, res) => {
  const u = authUser(req, res); if (!u) return;
  const join = `SELECT v.*, h.progress_sec, h.duration_sec AS watched_duration, h.updated_at FROM watch_history h JOIN videos v ON v.id=h.video_id WHERE h.user_id=? ORDER BY h.updated_at DESC`;
  const history = db.prepare(join).all(u.id).map(r => ({ video: videoOut(r), progress_sec: r.progress_sec, duration_sec: r.watched_duration }));
  const cont = history.filter(h => h.progress_sec > 5 && (!h.duration_sec || h.progress_sec < h.duration_sec * 0.95));
  const wl = db.prepare('SELECT v.* FROM watch_later w JOIN videos v ON v.id=w.video_id WHERE w.user_id=?').all(u.id).map(videoOut);
  const liked = db.prepare('SELECT v.* FROM likes l JOIN videos v ON v.id=l.video_id WHERE l.user_id=?').all(u.id).map(videoOut);
  const unlocked = db.prepare('SELECT v.* FROM unlocks un JOIN videos v ON v.id=un.video_id WHERE un.user_id=?').all(u.id).map(videoOut);
  send(res, 200, { history, continue_watching: cont, watch_later: wl, liked, unlocked, playlists: [] });
});
route('POST', '/api/watchlater', async (req, res) => {
  const u = authUser(req, res); if (!u) return;
  const b = await readBody(req);
  const ex = db.prepare('SELECT 1 x FROM watch_later WHERE user_id=? AND video_id=?').get(u.id, b.videoId);
  if (ex) { db.prepare('DELETE FROM watch_later WHERE user_id=? AND video_id=?').run(u.id, b.videoId); return send(res, 200, { ok: true, saved: false }); }
  db.prepare('INSERT INTO watch_later(user_id,video_id) VALUES(?,?)').run(u.id, b.videoId);
  send(res, 200, { ok: true, saved: true });
});
route('POST', '/api/like', async (req, res) => {
  const u = authUser(req, res); if (!u) return;
  const b = await readBody(req);
  const ex = db.prepare('SELECT 1 x FROM likes WHERE user_id=? AND video_id=?').get(u.id, b.videoId);
  if (ex) { db.prepare('DELETE FROM likes WHERE user_id=? AND video_id=?').run(u.id, b.videoId); return send(res, 200, { ok: true, liked: false }); }
  db.prepare('INSERT INTO likes(user_id,video_id) VALUES(?,?)').run(u.id, b.videoId);
  send(res, 200, { ok: true, liked: true });
});
route('POST', '/api/report', async (req, res) => {
  const b = await readBody(req);
  const u = optionalUser(req);
  if (!b.reason) return err(res, 400, 'reason required');
  const info = db.prepare('INSERT INTO reports(user_id,video_id,reason,status,created_at) VALUES(?,?,?,?,?)')
    .run(u ? u.id : null, b.videoId || null, String(b.reason).slice(0, 500), 'open', now());
  send(res, 201, { ok: true, report_id: Number(info.lastInsertRowid) });
});
route('POST', '/api/plays', async (req, res) => {
  const b = await readBody(req);
  const v = db.prepare('SELECT id FROM videos WHERE id=?').get(b.videoId);
  if (!v) return err(res, 404, 'video not found');
  const u = optionalUser(req);
  db.prepare('INSERT INTO plays(user_id,video_id,at,watch_sec) VALUES(?,?,?,?)').run(u ? u.id : null, b.videoId, now(), b.watch_sec || 0);
  db.prepare('UPDATE videos SET views=views+1 WHERE id=?').run(b.videoId);
  send(res, 200, { ok: true });
});

/* ================= ADMIN API ================= */
const loginFails = new Map(); // ip -> [timestamps]
route('POST', '/api/admin/login', async (req, res) => {
  const ip = req.socket.remoteAddress || 'unknown';
  const recent = (loginFails.get(ip) || []).filter(t => Date.now() - t < 10 * 60 * 1000);
  if (recent.length >= 10) return err(res, 429, 'too many failed login attempts; try again later');
  const b = await readBody(req);
  const a = db.prepare('SELECT * FROM admins WHERE email=?').get(String(b.email || '').toLowerCase());
  const okLogin = a && verifyPassword(b.password || '', a.pass_hash);
  db.prepare('INSERT INTO admin_logins(admin_id,ip,success,at) VALUES(?,?,?,?)').run(a ? a.id : null, ip, okLogin ? 1 : 0, now());
  if (!okLogin) { recent.push(Date.now()); loginFails.set(ip, recent); return err(res, 401, 'invalid admin credentials'); }
  loginFails.delete(ip);
  db.prepare('UPDATE admins SET last_login_at=? WHERE id=?').run(now(), a.id);
  audit(a.id, 'admin_login', 'admin', a.id, null, { ip });
  send(res, 200, { token: makeToken('admin', a.id, 2), admin: { id: a.id, name: a.name, email: a.email, role: a.role } });
});
route('POST', '/api/admin/logout-all', (req, res) => {
  const a = authAdmin(req, res); if (!a) return;
  db.prepare("DELETE FROM sessions WHERE kind='admin' AND subject_id=?").run(a.id);
  audit(a.id, 'logout_all_sessions', 'admin', a.id, null, null);
  send(res, 200, { ok: true });
});
route('GET', '/api/admin/dashboard', (req, res) => {
  const a = authAdmin(req, res); if (!a) return;
  const c = (sql, ...p) => db.prepare(sql).get(...p);
  const users = {
    total: c('SELECT COUNT(*) n FROM users').n, guests: c('SELECT COUNT(*) n FROM users WHERE is_guest=1').n,
    pro: db.prepare("SELECT COUNT(*) n FROM users WHERE is_pro=1 AND (pro_expiry IS NULL OR pro_expiry>?)").get(now()).n, free: 0
  };
  users.free = users.total - users.pro - users.guests;
  users.active_7d = db.prepare('SELECT COUNT(*) n FROM users WHERE last_active_at>?').get(new Date(Date.now() - 7 * 864e5).toISOString()).n;
  const videos = {
    total: c('SELECT COUNT(*) n FROM videos').n, published: c("SELECT COUNT(*) n FROM videos WHERE status='published'").n,
    draft: c("SELECT COUNT(*) n FROM videos WHERE status='draft'").n, scheduled: c("SELECT COUNT(*) n FROM videos WHERE status='scheduled'").n,
    archived: c("SELECT COUNT(*) n FROM videos WHERE status='archived'").n
  };
  const playsRow = c('SELECT COUNT(*) n, COALESCE(SUM(watch_sec),0) w FROM plays');
  const coins = c('SELECT COUNT(*) n, COALESCE(SUM(CASE WHEN amount>0 THEN amount ELSE 0 END),0) in_sum, COALESCE(SUM(CASE WHEN amount<0 THEN -amount ELSE 0 END),0) out_sum FROM coin_ledger');
  const claims = {
    pending: c("SELECT COUNT(*) n FROM payment_claims WHERE status='pending'").n,
    approved: c("SELECT COUNT(*) n FROM payment_claims WHERE status='approved'").n,
    rejected: c("SELECT COUNT(*) n FROM payment_claims WHERE status='rejected'").n
  };
  const topVideos = db.prepare('SELECT id,title,views FROM videos ORDER BY views DESC LIMIT 5').all();
  const topCats = db.prepare('SELECT cat.name, COALESCE(SUM(v.views),0) views FROM categories cat LEFT JOIN videos v ON v.category_id=cat.id GROUP BY cat.id ORDER BY views DESC LIMIT 5').all();
  const verDist = db.prepare("SELECT COALESCE(app_version,'(unknown)') v, COUNT(*) n FROM users GROUP BY app_version").all();
  send(res, 200, {
    users, videos, plays: playsRow.n, watch_sec: playsRow.w,
    coins: { transactions: coins.n, credited: coins.in_sum, debited: coins.out_sum },
    claims, active_subscriptions: users.pro,
    top_videos: topVideos, top_categories: topCats, version_distribution: verDist,
    admob_revenue: null, admob_note: 'AdMob reporting not connected (awaiting credentials)',
    recent_audit: db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 10').all()
  });
});

/* --- generic CRUD helpers --- */
function parseVideoBody(b) {
  return {
    title: b.title || 'Untitled', description: b.description || '', thumb_url: b.thumb_url || '', source_type: b.source_type || 'mp4',
    source_url: b.source_url || '', category_id: b.category_id ? Number(b.category_id) : null, tags: b.tags || '', language: b.language || 'Hindi',
    duration_sec: Number(b.duration_sec || 0), status: b.status || 'published',
    published_at: b.published_at || now(), scheduled_at: b.scheduled_at || null, expires_at: b.expires_at || null,
    access_type: b.access_type || 'free', coin_price: Number(b.coin_price || 0), pro_free: b.pro_free === false ? 0 : 1,
    featured: b.featured ? 1 : 0, is_short: b.is_short ? 1 : 0, provider_name: b.provider_name || '', sort: Number(b.sort || 0),
    subtitles_url: b.subtitles_url || null, warning: b.warning || null, search_keywords: b.search_keywords || '',
    ads: JSON.stringify(b.ads || {})
  };
}
function validateVideo(v, res) {
  if ((v.access_type === 'coin' || v.access_type === 'pro_coin') && !(Number(v.coin_price) > 0)) {
    err(res, 400, 'coin_price is required and must be > 0 when access_type is coin or pro_coin (each video has its own price)');
    return false;
  }
  return true;
}
const VIDEO_COLS = 'title,description,thumb_url,source_type,source_url,category_id,tags,language,duration_sec,status,published_at,scheduled_at,expires_at,access_type,coin_price,pro_free,featured,is_short,provider_name,sort,subtitles_url,warning,search_keywords,ads';
route('GET', '/api/admin/videos', (req, res) => { const a = authAdmin(req, res); if (a) send(res, 200, db.prepare('SELECT * FROM videos ORDER BY id DESC').all().map(videoOut)); });
route('POST', '/api/admin/videos', async (req, res) => {
  const a = authAdmin(req, res, ROLE_WRITE.videos); if (!a) return;
  const b = await readBody(req);
  if (!b.source_url || !/^https?:\/\//i.test(b.source_url)) return err(res, 400, 'a valid http(s) source_url is required (format validated; HTTP 200 alone does not guarantee playability)');
  if (!['mp4', 'hls', 'mkv', 'embed'].includes(b.source_type || 'mp4')) return err(res, 400, 'invalid source_type');
  const v = parseVideoBody(b);
  if (!validateVideo(v, res)) return;
  const info = db.prepare(`INSERT INTO videos(${VIDEO_COLS}) VALUES(${VIDEO_COLS.split(',').map(() => '?').join(',')})`).run(...VIDEO_COLS.split(',').map(k => v[k]));
  audit(a.id, 'video_create', 'video', info.lastInsertRowid, null, { title: v.title });
  send(res, 201, videoOut(db.prepare('SELECT * FROM videos WHERE id=?').get(Number(info.lastInsertRowid))));
});
route('PUT', '/api/admin/videos/:id', async (req, res, p) => {
  const a = authAdmin(req, res, ROLE_WRITE.videos); if (!a) return;
  const old = db.prepare('SELECT * FROM videos WHERE id=?').get(p.id);
  if (!old) return err(res, 404, 'video not found');
  const b = await readBody(req);
  const v = parseVideoBody(Object.assign({}, videoOut(old), b, { ads: b.ads || JSON.parse(old.ads || '{}') }));
  if (!validateVideo(v, res)) return;
  db.prepare(`UPDATE videos SET ${VIDEO_COLS.split(',').map(k => k + '=?').join(',')} WHERE id=?`).run(...VIDEO_COLS.split(',').map(k => v[k]), p.id);
  audit(a.id, 'video_update', 'video', p.id, null, { title: v.title, ads_changed: JSON.stringify(b.ads || {}) !== (old.ads || '{}') });
  send(res, 200, videoOut(db.prepare('SELECT * FROM videos WHERE id=?').get(p.id)));
});
route('DELETE', '/api/admin/videos/:id', (req, res, p) => {
  const a = authAdmin(req, res, ROLE_WRITE.videos); if (!a) return;
  if (!db.prepare('SELECT id FROM videos WHERE id=?').get(p.id)) return err(res, 404, 'video not found');
  // Ledger/unlock/audit history referencing this video is intentionally preserved.
  db.prepare('DELETE FROM feed_items WHERE video_id=?').run(p.id);
  db.prepare('DELETE FROM videos WHERE id=?').run(p.id);
  audit(a.id, 'video_delete', 'video', p.id, null, null);
  send(res, 200, { ok: true });
});
route('POST', '/api/admin/videos/:id/duplicate', (req, res, p) => {
  const a = authAdmin(req, res, ROLE_WRITE.videos); if (!a) return;
  const old = db.prepare('SELECT * FROM videos WHERE id=?').get(p.id);
  if (!old) return err(res, 404, 'video not found');
  const cols = VIDEO_COLS.split(',');
  const vals = cols.map(k => k === 'title' ? old.title + ' (Copy)' : old[k]);
  const info = db.prepare(`INSERT INTO videos(${VIDEO_COLS}) VALUES(${cols.map(() => '?').join(',')})`).run(...vals);
  audit(a.id, 'video_duplicate', 'video', info.lastInsertRowid, null, { from: p.id });
  send(res, 201, videoOut(db.prepare('SELECT * FROM videos WHERE id=?').get(Number(info.lastInsertRowid))));
});
function simpleCrud(base, table, roles, entity) {
  route('GET', base, (req, res) => { const a = authAdmin(req, res); if (a) send(res, 200, db.prepare(`SELECT * FROM ${table} ORDER BY sort ASC, id ASC`).all()); });
  route('POST', base, async (req, res) => {
    const a = authAdmin(req, res, roles); if (!a) return;
    const b = await readBody(req);
    const cols = Object.keys(b).filter(k => /^[a-z_]+$/.test(k));
    const info = db.prepare(`INSERT INTO ${table}(${cols.join(',')}) VALUES(${cols.map(() => '?').join(',')})`).run(...cols.map(k => typeof b[k] === 'object' ? JSON.stringify(b[k]) : b[k]));
    audit(a.id, entity + '_create', entity, info.lastInsertRowid, null, null);
    send(res, 201, db.prepare(`SELECT * FROM ${table} WHERE id=?`).get(Number(info.lastInsertRowid)));
  });
  route('PUT', base + '/:id', async (req, res, p) => {
    const a = authAdmin(req, res, roles); if (!a) return;
    if (!db.prepare(`SELECT id FROM ${table} WHERE id=?`).get(p.id)) return err(res, 404, entity + ' not found');
    const b = await readBody(req);
    const cols = Object.keys(b).filter(k => /^[a-z_]+$/.test(k) && k !== 'id');
    if (cols.length) db.prepare(`UPDATE ${table} SET ${cols.map(k => k + '=?').join(',')} WHERE id=?`).run(...cols.map(k => typeof b[k] === 'object' ? JSON.stringify(b[k]) : b[k]), p.id);
    audit(a.id, entity + '_update', entity, p.id, null, null);
    send(res, 200, db.prepare(`SELECT * FROM ${table} WHERE id=?`).get(p.id));
  });
  route('DELETE', base + '/:id', (req, res, p) => {
    const a = authAdmin(req, res, roles); if (!a) return;
    db.prepare(`DELETE FROM ${table} WHERE id=?`).run(p.id);
    audit(a.id, entity + '_delete', entity, p.id, null, null);
    send(res, 200, { ok: true });
  });
}
simpleCrud('/api/admin/categories', 'categories', ROLE_WRITE.categories, 'category');
simpleCrud('/api/admin/plans', 'plans', ROLE_WRITE.plans, 'plan');
simpleCrud('/api/admin/packages', 'coin_packages', ROLE_WRITE.packages, 'package');
route('GET', '/api/admin/feeds', (req, res) => {
  const a = authAdmin(req, res); if (!a) return;
  const cols = db.prepare('SELECT * FROM feed_collections ORDER BY sort').all();
  send(res, 200, cols.map(c => Object.assign({}, c, { items: db.prepare('SELECT * FROM feed_items WHERE collection_id=? ORDER BY sort').all(c.id) })));
});
route('POST', '/api/admin/feeds', async (req, res) => {
  const a = authAdmin(req, res, ROLE_WRITE.feeds); if (!a) return;
  const b = await readBody(req);
  const info = db.prepare('INSERT INTO feed_collections(title,description,layout,sort,visible,scheduled_at) VALUES(?,?,?,?,?,?)')
    .run(b.title || 'Collection', b.description || '', b.layout || 'vertical', Number(b.sort || 0), b.visible === false ? 0 : 1, b.scheduled_at || null);
  const cid = Number(info.lastInsertRowid);
  if (Array.isArray(b.items)) { const fi = db.prepare('INSERT OR IGNORE INTO feed_items(collection_id,video_id,sort,pinned,sponsored) VALUES(?,?,?,?,?)'); b.items.forEach((it, i) => fi.run(cid, it.video_id, it.sort != null ? it.sort : i, it.pinned ? 1 : 0, it.sponsored ? 1 : 0)); }
  audit(a.id, 'feed_create', 'feed_collection', cid, null, null);
  send(res, 201, { id: cid, ok: true });
});
route('PUT', '/api/admin/feeds/:id', async (req, res, p) => {
  const a = authAdmin(req, res, ROLE_WRITE.feeds); if (!a) return;
  const b = await readBody(req);
  const old = db.prepare('SELECT * FROM feed_collections WHERE id=?').get(p.id);
  if (!old) return err(res, 404, 'collection not found');
  db.prepare('UPDATE feed_collections SET title=?,description=?,layout=?,sort=?,visible=?,scheduled_at=? WHERE id=?')
    .run(b.title != null ? b.title : old.title, b.description != null ? b.description : old.description, b.layout || old.layout, b.sort != null ? Number(b.sort) : old.sort, b.visible != null ? (b.visible ? 1 : 0) : old.visible, b.scheduled_at !== undefined ? b.scheduled_at : old.scheduled_at, p.id);
  if (Array.isArray(b.items)) {
    db.prepare('DELETE FROM feed_items WHERE collection_id=?').run(p.id);
    const fi = db.prepare('INSERT OR IGNORE INTO feed_items(collection_id,video_id,sort,pinned,sponsored) VALUES(?,?,?,?,?)');
    b.items.forEach((it, i) => fi.run(p.id, it.video_id, it.sort != null ? it.sort : i, it.pinned ? 1 : 0, it.sponsored ? 1 : 0));
  }
  audit(a.id, 'feed_update', 'feed_collection', p.id, null, null);
  send(res, 200, { ok: true });
});
route('DELETE', '/api/admin/feeds/:id', (req, res, p) => {
  const a = authAdmin(req, res, ROLE_WRITE.feeds); if (!a) return;
  db.prepare('DELETE FROM feed_items WHERE collection_id=?').run(p.id);
  db.prepare('DELETE FROM feed_collections WHERE id=?').run(p.id);
  audit(a.id, 'feed_delete', 'feed_collection', p.id, null, null);
  send(res, 200, { ok: true });
});
route('GET', '/api/admin/home-sections', (req, res) => { const a = authAdmin(req, res); if (a) send(res, 200, db.prepare('SELECT * FROM home_sections ORDER BY sort').all()); });
route('PUT', '/api/admin/home-sections', async (req, res) => {
  const a = authAdmin(req, res, ROLE_WRITE.home); if (!a) return;
  const b = await readBody(req);
  const list = Array.isArray(b) ? b : b.sections;
  if (!Array.isArray(list)) return err(res, 400, 'sections array required');
  tx(() => { const up = db.prepare('INSERT INTO home_sections(key,title,visible,sort) VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET title=excluded.title, visible=excluded.visible, sort=excluded.sort'); list.forEach(s => up.run(s.key, s.title || s.key, s.visible === false ? 0 : 1, Number(s.sort || 0))); });
  audit(a.id, 'home_sections_update', 'home_sections', null, null, null);
  send(res, 200, { ok: true });
});
route('GET', '/api/admin/users', (req, res, p, query) => {
  const a = authAdmin(req, res); if (!a) return;
  let where = '1=1'; const args = [];
  const f = query.filter || 'all';
  if (f === 'free') { where += ' AND is_pro=0 AND is_guest=0'; }
  else if (f === 'pro') { where += ' AND is_pro=1'; }
  else if (f === 'guests') { where += ' AND is_guest=1'; }
  else if (f === 'suspended') { where += " AND status='suspended'"; }
  else if (f === 'recent') { where += ' AND last_active_at>?'; args.push(new Date(Date.now() - 7 * 864e5).toISOString()); }
  else if (f === 'pending_claims') { where += ' AND id IN (SELECT user_id FROM payment_claims WHERE status=\'pending\')'; }
  if (query.q) { where += ' AND (CAST(id AS TEXT)=? OR name LIKE ? OR email LIKE ?)'; args.push(query.q, '%' + query.q + '%', '%' + query.q + '%'); }
  const rows = db.prepare(`SELECT * FROM users WHERE ${where} ORDER BY id DESC LIMIT 500`).all(...args);
  send(res, 200, rows.map(u => Object.assign(publicUser(u), { app_version: u.app_version, last_active_at: u.last_active_at })));
});
route('GET', '/api/admin/users/:id', (req, res, p) => {
  const a = authAdmin(req, res); if (!a) return;
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(p.id);
  if (!u) return err(res, 404, 'user not found');
  audit(a.id, 'user_support_view', 'user', p.id, null, { note: 'read-only support view' });
  send(res, 200, {
    user: Object.assign(publicUser(u), { app_version: u.app_version, last_active_at: u.last_active_at }),
    ledger: db.prepare('SELECT * FROM coin_ledger WHERE user_id=? ORDER BY id DESC LIMIT 100').all(p.id),
    unlocks: db.prepare('SELECT un.*, v.title FROM unlocks un JOIN videos v ON v.id=un.video_id WHERE un.user_id=?').all(p.id),
    claims: db.prepare('SELECT * FROM payment_claims WHERE user_id=? ORDER BY id DESC').all(p.id),
    watch_time_sec: db.prepare('SELECT COALESCE(SUM(watch_sec),0) s FROM plays WHERE user_id=?').get(p.id).s,
    history_count: db.prepare('SELECT COUNT(*) n FROM watch_history WHERE user_id=?').get(p.id).n
  });
});
route('POST', '/api/admin/users/:id/pro', async (req, res, p) => {
  const a = authAdmin(req, res, ROLE_WRITE.users.concat(['super_admin'])); if (!a) return;
  const b = await readBody(req);
  if (!b.reason) return err(res, 400, 'reason is mandatory');
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(p.id);
  if (!u) return err(res, 404, 'user not found');
  if (b.action === 'grant') {
    const days = Number(b.days || 30);
    const base = u.pro_expiry && u.pro_expiry > now() ? new Date(u.pro_expiry) : new Date();
    const expiry = new Date(base.getTime() + days * 864e5).toISOString();
    db.prepare('UPDATE users SET is_pro=1, pro_plan_id=?, pro_expiry=? WHERE id=?').run(b.plan_id || null, expiry, p.id);
    audit(a.id, 'pro_grant', 'user', p.id, b.reason, { expiry, days });
    return send(res, 200, { ok: true, pro_expiry: expiry });
  }
  if (b.action === 'revoke') {
    db.prepare('UPDATE users SET is_pro=0, pro_expiry=NULL WHERE id=?').run(p.id);
    audit(a.id, 'pro_revoke', 'user', p.id, b.reason, { previous_expiry: u.pro_expiry });
    return send(res, 200, { ok: true });
  }
  err(res, 400, 'action must be grant or revoke');
});
route('POST', '/api/admin/users/:id/coins', async (req, res, p) => {
  const a = authAdmin(req, res, ROLE_WRITE.users.concat(['super_admin'])); if (!a) return;
  const b = await readBody(req);
  const amount = Number(b.amount || 0);
  if (!amount || !Number.isInteger(amount)) return err(res, 400, 'integer amount required');
  if (!b.reason) return err(res, 400, 'reason is mandatory');
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(p.id);
  if (!u) return err(res, 404, 'user not found');
  if (u.coins_cached + amount < 0) return err(res, 400, 'adjustment would make balance negative');
  const r = tx(() => ledger(u.id, 'admin_adjust', amount, 'admin', a.id, 'admin-panel', null));
  audit(a.id, 'coin_adjust', 'user', p.id, b.reason, { amount, balance_before: r.balance - amount, balance_after: r.balance });
  send(res, 200, { ok: true, balance: r.balance });
});
route('POST', '/api/admin/users/:id/suspend', async (req, res, p) => {
  const a = authAdmin(req, res, ROLE_WRITE.users.concat(['super_admin'])); if (!a) return;
  const b = await readBody(req);
  if (!b.reason) return err(res, 400, 'reason is mandatory');
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(p.id);
  if (!u) return err(res, 404, 'user not found');
  db.prepare('UPDATE users SET status=? WHERE id=?').run(b.suspended ? 'suspended' : 'active', p.id);
  if (b.suspended) db.prepare("DELETE FROM sessions WHERE kind='user' AND subject_id=?").run(p.id);
  audit(a.id, b.suspended ? 'user_suspend' : 'user_restore', 'user', p.id, b.reason, null);
  send(res, 200, { ok: true, status: b.suspended ? 'suspended' : 'active' });
});
route('GET', '/api/admin/claims', (req, res, p, query) => {
  const a = authAdmin(req, res); if (!a) return;
  const where = query.status ? 'WHERE c.status=?' : '';
  const args = query.status ? [query.status] : [];
  send(res, 200, db.prepare(`SELECT c.*, u.name AS user_name, u.email AS user_email, pk.name AS package_name, pl.name AS plan_name FROM payment_claims c JOIN users u ON u.id=c.user_id LEFT JOIN coin_packages pk ON pk.id=c.package_id LEFT JOIN plans pl ON pl.id=c.plan_id ${where} ORDER BY c.id DESC LIMIT 500`).all(...args));
});
route('POST', '/api/admin/claims/:id/approve', async (req, res, p) => {
  const a = authAdmin(req, res, ROLE_WRITE.claims); if (!a) return;
  const b = await readBody(req).catch(() => ({}));
  try {
    const out = tx(() => {
      const claim = db.prepare('SELECT * FROM payment_claims WHERE id=?').get(p.id);
      if (!claim) { const e = new Error('claim not found'); e.status = 404; throw e; }
      if (claim.status !== 'pending') { const e = new Error('claim already ' + claim.status + '; no double credit possible'); e.status = 409; throw e; }
      let credited = 0, proExpiry = null;
      if (claim.package_id) {
        const pkg = db.prepare('SELECT * FROM coin_packages WHERE id=?').get(claim.package_id);
        credited = pkg.total_coins;
        ledger(claim.user_id, 'purchase', credited, 'payment_claim', claim.id, 'admin-approved:' + claim.method, 'claim-' + claim.id);
      } else if (claim.plan_id) {
        const plan = db.prepare('SELECT * FROM plans WHERE id=?').get(claim.plan_id);
        const u = db.prepare('SELECT * FROM users WHERE id=?').get(claim.user_id);
        const base = u.pro_expiry && u.pro_expiry > now() ? new Date(u.pro_expiry) : new Date();
        proExpiry = new Date(base.getTime() + plan.duration_days * 864e5).toISOString();
        db.prepare('UPDATE users SET is_pro=1, pro_plan_id=?, pro_expiry=? WHERE id=?').run(plan.id, proExpiry, claim.user_id);
      }
      db.prepare("UPDATE payment_claims SET status='approved', reviewer_id=?, review_reason=?, reviewed_at=? WHERE id=? AND status='pending'")
        .run(a.id, b.note || 'verified', now(), p.id);
      return { credited, proExpiry };
    });
    audit(a.id, 'claim_approve', 'payment_claim', p.id, b.note || null, out);
    send(res, 200, { ok: true, credited_coins: out.credited, pro_expiry: out.proExpiry });
  } catch (e) { err(res, e.status || 500, e.message); }
});
route('POST', '/api/admin/claims/:id/reject', async (req, res, p) => {
  const a = authAdmin(req, res, ROLE_WRITE.claims); if (!a) return;
  const b = await readBody(req);
  if (!b.reason) return err(res, 400, 'rejection reason is mandatory');
  const claim = db.prepare('SELECT * FROM payment_claims WHERE id=?').get(p.id);
  if (!claim) return err(res, 404, 'claim not found');
  if (claim.status !== 'pending') return err(res, 409, 'claim already ' + claim.status);
  db.prepare("UPDATE payment_claims SET status='rejected', reviewer_id=?, review_reason=?, reviewed_at=? WHERE id=?").run(a.id, b.reason, now(), p.id);
  audit(a.id, 'claim_reject', 'payment_claim', p.id, b.reason, null);
  send(res, 200, { ok: true });
});
route('GET', '/api/admin/ledger', (req, res, p, query) => {
  const a = authAdmin(req, res); if (!a) return;
  let where = '1=1'; const args = [];
  if (query.user_id) { where += ' AND user_id=?'; args.push(query.user_id); }
  if (query.type) { where += ' AND type=?'; args.push(query.type); }
  send(res, 200, db.prepare(`SELECT * FROM coin_ledger WHERE ${where} ORDER BY id DESC LIMIT 500`).all(...args));
});
route('GET', '/api/admin/rewards-config', (req, res) => {
  const a = authAdmin(req, res); if (!a) return;
  send(res, 200, JSON.parse(db.prepare("SELECT value FROM reward_config WHERE key='config'").get().value));
});
route('PUT', '/api/admin/rewards-config', async (req, res) => {
  const a = authAdmin(req, res, ROLE_WRITE.rewards); if (!a) return;
  const b = await readBody(req);
  const cur = JSON.parse(db.prepare("SELECT value FROM reward_config WHERE key='config'").get().value);
  const merged = Object.assign({}, cur, b);
  db.prepare("UPDATE reward_config SET value=? WHERE key='config'").run(JSON.stringify(merged));
  audit(a.id, 'rewards_config_update', 'reward_config', null, b.reason || null, null);
  send(res, 200, merged);
});
function kvGet(table) { const o = {}; db.prepare(`SELECT key,value FROM ${table}`).all().forEach(r => o[r.key] = r.value); return o; }
route('GET', '/api/admin/settings', (req, res) => { const a = authAdmin(req, res); if (a) send(res, 200, getSettings()); });
route('PUT', '/api/admin/settings', async (req, res) => {
  const a = authAdmin(req, res, ['super_admin']); if (!a) return;
  const b = await readBody(req);
  const up = db.prepare('INSERT INTO app_settings(key,value,updated_by,updated_at) VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_by=excluded.updated_by, updated_at=excluded.updated_at');
  tx(() => { for (const [k, v] of Object.entries(b)) if (k !== 'reason') up.run(k, String(v), a.id, now()); });
  audit(a.id, 'settings_update', 'app_settings', null, b.reason || null, { keys: Object.keys(b) });
  send(res, 200, getSettings());
});
route('GET', '/api/admin/version', (req, res) => { const a = authAdmin(req, res); if (a) send(res, 200, db.prepare('SELECT * FROM app_version WHERE id=1').get()); });
route('PUT', '/api/admin/version', async (req, res) => {
  const a = authAdmin(req, res, ['super_admin']); if (!a) return;
  const b = await readBody(req);
  const cur = db.prepare('SELECT * FROM app_version WHERE id=1').get();
  db.prepare('UPDATE app_version SET latest_name=?,latest_code=?,min_code=?,force_update=?,store_url=?,release_notes=? WHERE id=1')
    .run(b.latest_name != null ? b.latest_name : cur.latest_name, b.latest_code != null ? Number(b.latest_code) : cur.latest_code, b.min_code != null ? Number(b.min_code) : cur.min_code, b.force_update != null ? (b.force_update ? 1 : 0) : cur.force_update, b.store_url != null ? b.store_url : cur.store_url, b.release_notes != null ? b.release_notes : cur.release_notes);
  audit(a.id, 'version_update', 'app_version', 1, b.reason || null, null);
  send(res, 200, db.prepare('SELECT * FROM app_version WHERE id=1').get());
});
route('GET', '/api/admin/branding', (req, res) => { const a = authAdmin(req, res); if (a) send(res, 200, getBranding()); });
route('PUT', '/api/admin/branding', async (req, res) => {
  const a = authAdmin(req, res, ['super_admin', 'content_manager']); if (!a) return;
  const b = await readBody(req);
  const up = db.prepare('INSERT INTO branding(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
  tx(() => { for (const [k, v] of Object.entries(b)) if (k !== 'reason') up.run(k, String(v)); });
  audit(a.id, 'branding_update', 'branding', null, b.reason || null, { keys: Object.keys(b) });
  send(res, 200, getBranding());
});
route('GET', '/api/admin/ad-networks', (req, res) => { const a = authAdmin(req, res); if (a) send(res, 200, getAdNetworks()); });
route('PUT', '/api/admin/ad-networks', async (req, res) => {
  const a = authAdmin(req, res, ['super_admin', 'content_manager']); if (!a) return;
  const b = await readBody(req);
  if (!b || typeof b !== 'object' || Array.isArray(b)) return err(res, 400, 'JSON object required');
  const out = JSON.parse(JSON.stringify(AD_NETWORKS_DEFAULT));
  for (const net of Object.keys(AD_NETWORKS_DEFAULT)) {
    if (b[net] === undefined) continue;
    if (!b[net] || typeof b[net] !== 'object' || Array.isArray(b[net])) return err(res, 400, net + ' must be an object');
    for (const k of Object.keys(AD_NETWORKS_DEFAULT[net])) {
      if (b[net][k] === undefined) continue;
      if (k === 'enabled') {
        if (typeof b[net][k] !== 'boolean') return err(res, 400, net + '.enabled must be a boolean');
        out[net][k] = b[net][k];
      } else {
        if (typeof b[net][k] !== 'string') return err(res, 400, net + '.' + k + ' must be a string');
        const v = b[net][k].trim();
        if (v.length > 500) return err(res, 400, net + '.' + k + ' is too long (max 500 chars)');
        out[net][k] = v;
      }
    }
  }
  db.prepare('INSERT INTO ad_networks(id,json) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET json=excluded.json').run(JSON.stringify(out));
  audit(a.id, 'ad_networks_update', 'ad_networks', 1, b.reason || null, { monetag_enabled: out.monetag.enabled, adsterra_enabled: out.adsterra.enabled });
  send(res, 200, out);
});
const SECRET_KEYS = ['paypal_secret', 'paytm_key', 'onesignal_api_key'];
route('GET', '/api/admin/payment-config', (req, res) => {
  const a = authAdmin(req, res); if (!a) return;
  const o = kvGet('payment_config');
  SECRET_KEYS.forEach(k => { if (o[k]) o[k] = '********'; });
  send(res, 200, o);
});
route('PUT', '/api/admin/payment-config', async (req, res) => {
  const a = authAdmin(req, res, ['super_admin']); if (!a) return;
  const b = await readBody(req);
  const up = db.prepare('INSERT INTO payment_config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
  tx(() => { for (const [k, v] of Object.entries(b)) { if (k === 'reason') continue; if (v === '********') continue; up.run(k, String(v)); } });
  audit(a.id, 'payment_config_update', 'payment_config', null, b.reason || null, { keys: Object.keys(b).filter(k => k !== 'reason') });
  send(res, 200, { ok: true });
});
route('GET', '/api/admin/notifications', (req, res) => { const a = authAdmin(req, res); if (a) send(res, 200, db.prepare('SELECT * FROM notifications ORDER BY id DESC LIMIT 200').all()); });
route('POST', '/api/admin/notifications', async (req, res) => {
  const a = authAdmin(req, res, ROLE_WRITE.notifications); if (!a) return;
  const b = await readBody(req);
  if (!b.title || !b.body) return err(res, 400, 'title and body required');
  const AUDIENCES = ['all', 'free', 'pro', 'expired_pro', 'pending_claims', 'category', 'user'];
  const audience = b.audience || 'all';
  if (!AUDIENCES.includes(audience)) return err(res, 400, 'invalid audience: ' + AUDIENCES.join(' | '));
  if (audience === 'user' && !b.target_user_id) return err(res, 400, 'target_user_id is required when audience is "user" (individual targeting)');
  if (audience === 'user' && !db.prepare('SELECT id FROM users WHERE id=?').get(b.target_user_id)) return err(res, 404, 'target user not found');
  // No fake sends: without a OneSignal key the campaign is recorded as awaiting_provider.
  // With a key configured it is marked provider_configured_pending_send (dispatch worker activates at deployment).
  const pc = kvGet('payment_config');
  const hasProvider = !!(pc.onesignal_api_key && pc.onesignal_app_id);
  const status = b.scheduled_at ? 'scheduled' : (hasProvider ? 'provider_configured_pending_send' : 'awaiting_provider');
  const info = db.prepare('INSERT INTO notifications(title,body,image_url,deep_link,audience,target_user_id,status,scheduled_at,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)')
    .run(b.title, b.body, b.image_url || null, b.deep_link || null, audience, b.target_user_id || null, status, b.scheduled_at || null, a.id, now());
  audit(a.id, 'notification_create', 'notification', info.lastInsertRowid, null, { audience, target_user_id: b.target_user_id || null, status });
  send(res, 201, { ok: true, id: Number(info.lastInsertRowid), status, note: hasProvider ? 'Recorded. OneSignal is configured; dispatch runs via the deployment worker (no send is faked here).' : 'Recorded as awaiting_provider — add OneSignal App ID + API key in Payment/Provider Config to enable sending.' });
});
route('GET', '/api/admin/reports', (req, res) => {
  const a = authAdmin(req, res); if (!a) return;
  send(res, 200, db.prepare('SELECT r.*, v.title AS video_title FROM reports r LEFT JOIN videos v ON v.id=r.video_id ORDER BY r.id DESC LIMIT 200').all());
});
route('POST', '/api/admin/reports/:id/resolve', async (req, res, p) => {
  const a = authAdmin(req, res, ROLE_WRITE.reports); if (!a) return;
  const b = await readBody(req);
  const r = db.prepare('SELECT * FROM reports WHERE id=?').get(p.id);
  if (!r) return err(res, 404, 'report not found');
  if (b.action === 'hide_video' && r.video_id) db.prepare("UPDATE videos SET status='archived' WHERE id=?").run(r.video_id);
  if (b.action === 'restore' && r.video_id) db.prepare("UPDATE videos SET status='published' WHERE id=?").run(r.video_id);
  db.prepare("UPDATE reports SET status='resolved', resolved_by=?, resolution=? WHERE id=?").run(a.id, (b.action || 'dismiss') + (b.reason ? ': ' + b.reason : ''), p.id);
  audit(a.id, 'report_resolve', 'report', p.id, b.reason || null, { action: b.action });
  send(res, 200, { ok: true });
});
route('GET', '/api/admin/audit', (req, res) => {
  const a = authAdmin(req, res, ['super_admin', 'auditor']); if (!a) return;
  send(res, 200, db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 500').all());
});
route('GET', '/api/admin/analytics', (req, res) => {
  const a = authAdmin(req, res); if (!a) return;
  const usersByDay = db.prepare("SELECT substr(created_at,1,10) day, COUNT(*) n FROM users GROUP BY day ORDER BY day DESC LIMIT 14").all().reverse();
  const viewsByDay = db.prepare("SELECT substr(at,1,10) day, COUNT(*) n, COALESCE(SUM(watch_sec),0) watch_sec FROM plays GROUP BY day ORDER BY day DESC LIMIT 14").all().reverse();
  const coinsByType = db.prepare('SELECT type, COUNT(*) n, COALESCE(SUM(amount),0) total FROM coin_ledger GROUP BY type').all();
  const claimsByStatus = db.prepare('SELECT status, COUNT(*) n FROM payment_claims GROUP BY status').all();
  const catPerf = db.prepare('SELECT c.name, COUNT(v.id) videos, COALESCE(SUM(v.views),0) views FROM categories c LEFT JOIN videos v ON v.category_id=c.id GROUP BY c.id ORDER BY views DESC').all();
  send(res, 200, { users_by_day: usersByDay, views_by_day: viewsByDay, coins_by_type: coinsByType, claims_by_status: claimsByStatus, category_performance: catPerf });
});

/* ================= SQL EXPORT / IMPORT ================= */
const EXPORT_TABLES = ['categories', 'videos', 'home_sections', 'feed_collections', 'feed_items', 'users', 'plans', 'coin_packages', 'coin_ledger', 'unlocks', 'payment_claims', 'reward_config', 'reward_claims', 'watch_history', 'app_settings', 'app_version', 'branding', 'notifications', 'reports', 'ad_networks'];
function sqlVal(v) {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'number') return String(v);
  return "'" + String(v).replace(/'/g, "''") + "'";
}
function buildExport() {
  const lines = [];
  lines.push('-- Raaz database export  ' + now());
  lines.push('-- NOTE: password hashes, admin accounts, sessions and payment secrets are intentionally EXCLUDED.');
  lines.push('-- Placeholder: create admin/user passwords again after restore; users are imported with password_hash NULL (must reset).');
  for (const t of EXPORT_TABLES) {
    const ddl = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name=?").get(t);
    if (ddl && ddl.sql) lines.push(ddl.sql + ';');
    let rows = [];
    try { rows = db.prepare('SELECT * FROM ' + t).all(); } catch (_) { continue; }
    for (const row of rows) {
      const cols = Object.keys(row);
      const vals = cols.map(c => {
        if (t === 'users' && c === 'password_hash') return 'NULL';
        if (t === 'app_settings' && /secret|key/i.test(c)) return sqlVal(row[c]);
        return sqlVal(row[c]);
      });
      lines.push(`INSERT INTO ${t} (${cols.join(',')}) VALUES (${vals.join(',')});`);
    }
  }
  return lines.join('\n') + '\n';
}
route('GET', '/api/admin/db/export.sql', (req, res) => {
  const a = authAdmin(req, res, ['super_admin']); if (!a) return;
  audit(a.id, 'db_export', 'database', null, null, null);
  res.writeHead(200, { 'Content-Type': 'text/sql; charset=utf-8', 'Content-Disposition': 'attachment; filename="raaz-export.sql"', 'Access-Control-Allow-Origin': '*' });
  res.end(buildExport());
});
route('POST', '/api/admin/db/import', async (req, res) => {
  const a = authAdmin(req, res, ['super_admin']); if (!a) return;
  const b = await readBody(req);
  if (b.confirm !== true) return err(res, 400, 'explicit confirm:true is required');
  if (!b.sql || typeof b.sql !== 'string') return err(res, 400, 'sql string required');
  const mode = b.mode === 'restore' ? 'restore' : 'merge';
  // Validate: ONLY INSERT statements into known tables are accepted. No arbitrary SQL.
  const statements = b.sql.split(/;\s*\n|;\s*$/).map(s => s.trim()).filter(s => s && !s.startsWith('--'));
  const clean = [];
  for (const st of statements) {
    if (/^--/.test(st)) continue;
    const body = st.split('\n').filter(l => !l.trim().startsWith('--')).join('\n').trim();
    if (!body) continue;
    const m = body.match(/^INSERT\s+INTO\s+([a-z_]+)\s*\(/i);
    if (!m) return err(res, 400, 'validation failed: only INSERT statements are allowed in import files');
    if (!EXPORT_TABLES.includes(m[1])) return err(res, 400, 'validation failed: unknown table ' + m[1]);
    clean.push(body);
  }
  if (!clean.length) return err(res, 400, 'no valid INSERT statements found');
  // Mandatory pre-import backup (file + record)
  const backupName = 'raaz.db.pre-import-' + Date.now() + '.bak';
  fs.copyFileSync(DB_PATH, path.join(DIR, backupName));
  fs.writeFileSync(path.join(DIR, 'pre-import-' + Date.now() + '.sql'), buildExport());
  db.prepare('INSERT INTO db_backups(filename,created_at,note) VALUES(?,?,?)').run(backupName, now(), 'pre-import backup (' + mode + ')');
  let inserted = 0, skipped = 0;
  try {
    tx(() => {
      if (mode === 'restore') {
        for (const t of [...EXPORT_TABLES].reverse()) { try { db.exec('DELETE FROM ' + t); } catch (_) {} }
      }
      for (const st of clean) {
        const sql = mode === 'merge' ? st.replace(/^INSERT\s+INTO/i, 'INSERT OR IGNORE INTO') : st;
        try { db.exec(sql + ';'); inserted++; } catch (e) { if (mode === 'merge') skipped++; else throw e; }
      }
      // Integrity check
      const bad = db.prepare('PRAGMA foreign_key_check').all();
      if (bad.length) throw new Error('foreign key integrity check failed');
    });
  } catch (e) {
    audit(a.id, 'db_import_failed', 'database', null, null, { error: e.message, backup: backupName });
    return err(res, 500, 'import failed and was rolled back: ' + e.message + ' (pre-import backup: ' + backupName + ')');
  }
  audit(a.id, 'db_import', 'database', null, null, { mode, inserted, skipped, backup: backupName });
  send(res, 200, { ok: true, mode, inserted, skipped, backup: backupName, note: 'Import applied transactionally. Recovery: restore the backup .db file or re-import the pre-import .sql snapshot.' });
});
route('GET', '/api/admin/db/backups', (req, res) => {
  const a = authAdmin(req, res, ['super_admin', 'auditor']); if (!a) return;
  send(res, 200, db.prepare('SELECT * FROM db_backups ORDER BY id DESC').all());
});

/* ================= DOCS + STATIC ================= */
const DOCS_HTML = `<!doctype html><html><head><meta charset="utf-8"><title>Raaz API Docs</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem;max-width:900px;color:#2b2b30}h1{color:#e0245e}code{background:#fdf0f3;padding:2px 6px;border-radius:6px}li{margin:4px 0}.m{font-weight:700;color:#e0245e}</style></head><body>
<h1>Raaz API v1</h1><p>Base: same origin. Auth: <code>Authorization: Bearer &lt;token&gt;</code>. Android package: <code>com.raazindia.raaz</code>. Admin UI: <a href="/admin">/admin</a>.</p>
<h2>App API</h2><ul>
<li><span class="m">GET</span> <code>/api/config</code> — remote settings, version, branding, plus <code>adNetworks</code> (Monetag/Adsterra public config)</li>
<li><span class="m">GET</span> <code>/watch/:id</code> — public share landing page for a published video (title, description, thumbnail, category + Open Graph tags; no source URL)</li>
<li><span class="m">GET</span> <code>/api/home</code> — featured, sections, categories</li>
<li><span class="m">GET</span> <code>/api/feeds</code> — feed collections</li>
<li><span class="m">GET</span> <code>/api/categories</code></li>
<li><span class="m">GET</span> <code>/api/videos/:id</code> — detail + related + unlock state</li>
<li><span class="m">GET</span> <code>/api/search?q=</code></li>
<li><span class="m">GET</span> <code>/api/shorts</code></li>
<li><span class="m">POST</span> <code>/api/auth/register</code> {name,email,password}</li>
<li><span class="m">POST</span> <code>/api/auth/login</code> {email,password}</li>
<li><span class="m">POST</span> <code>/api/auth/guest</code> {device_id}</li>
<li><span class="m">GET</span> <code>/api/me</code> (auth)</li>
<li><span class="m">POST</span> <code>/api/unlock</code> (auth) {videoId} — atomic, idempotent</li>
<li><span class="m">GET</span> <code>/api/wallet</code> (auth)</li>
<li><span class="m">POST</span> <code>/api/rewards/checkin</code> (auth)</li>
<li><span class="m">GET</span> <code>/api/coins/packages</code> · <code>/api/plans</code></li>
<li><span class="m">POST</span> <code>/api/payments/claim</code> (auth) {packageId|planId, method, utr} · <span class="m">GET</span> <code>/api/payments/claims</code></li>
<li><span class="m">POST</span> <code>/api/history</code> · <span class="m">GET</span> <code>/api/library</code> · <span class="m">POST</span> <code>/api/watchlater</code> · <code>/api/like</code></li>
<li><span class="m">POST</span> <code>/api/report</code> · <code>/api/plays</code></li></ul>
<h2>Admin API</h2><ul>
<li><span class="m">POST</span> <code>/api/admin/login</code> (rate-limited, history recorded)</li>
<li><span class="m">GET</span> <code>/api/admin/dashboard</code> · <code>/api/admin/analytics</code> · <code>/api/admin/audit</code></li>
<li>CRUD <code>/api/admin/videos</code> (+ <code>/:id/duplicate</code>), <code>/api/admin/categories</code>, <code>/api/admin/feeds</code>, <code>/api/admin/plans</code>, <code>/api/admin/packages</code></li>
<li><span class="m">GET/PUT</span> <code>/api/admin/home-sections</code>, <code>settings</code>, <code>version</code>, <code>branding</code>, <code>payment-config</code>, <code>rewards-config</code>, <code>ad-networks</code> (Monetag/Adsterra config JSON; AdMob stays in settings + per-video rules)</li>
<li><code>/api/admin/users</code>, <code>/api/admin/users/:id</code>, POST <code>.../pro</code> · <code>.../coins</code> · <code>.../suspend</code> (reason mandatory, audited)</li>
<li><code>/api/admin/claims</code>, POST <code>/api/admin/claims/:id/approve</code> (credits exactly once) · <code>/reject</code></li>
<li><code>/api/admin/ledger</code> · <code>/api/admin/notifications</code> · <code>/api/admin/reports</code> (+ resolve)</li>
<li><span class="m">GET</span> <code>/api/admin/db/export.sql</code> (super admin; no password hashes/secrets) · <span class="m">POST</span> <code>/api/admin/db/import</code> {sql, mode: merge|restore, confirm:true}</li></ul>
<p>Roles: super_admin, content_manager, payment_manager, support_manager, auditor (read-only). Money moves only on the server; coin deductions and claim approvals are atomic and idempotent.</p>
</body></html>`;

/* --- image upload (admin): thumbnails, banners, QR, branding — stored on server, served at /uploads/ --- */
route('POST', '/api/admin/upload', async (req, res) => {
  const a = authAdmin(req, res); if (!a) return;
  const b = await readBody(req);
  const m = /^data:(image\/(?:png|jpeg|webp|gif));base64,(.+)$/.exec(b.data || '');
  if (!m) return err(res, 400, 'send {data: "data:image/<png|jpeg|webp|gif>;base64,..."} — images only');
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length > 6 * 1024 * 1024) return err(res, 400, 'image too large (max 6MB)');
  const ext = { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/webp': '.webp', 'image/gif': '.gif' }[m[1]];
  const dir = UPLOAD_DIR;
  fs.mkdirSync(dir, { recursive: true });
  const safe = String(b.name || 'image').replace(/[^a-zA-Z0-9_-]+/g, '_').slice(0, 40) || 'image';
  const fname = Date.now() + '-' + safe + ext;
  fs.writeFileSync(path.join(dir, fname), buf);
  audit(a.id, 'image_upload', 'file', fname, '', m[1] + ' ' + buf.length + ' bytes');
  send(res, 201, { url: '/uploads/' + fname });
});
/* --- Public share landing page: /watch/:id (app shares these links) ---
   Exposes ONLY public fields of a PUBLISHED video (title, description, thumbnail,
   category) plus Open Graph tags for WhatsApp/social previews. Never source_url. */
route('GET', '/watch/:id', (req, res, p) => {
  const b = getBranding();
  const appName = b.app_name || 'Raaz';
  const page = inner => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${inner.title ? escHtml(inner.title) + ' · ' : ''}${escHtml(appName)}</title><style>body{font-family:system-ui,sans-serif;margin:0;background:#fff;color:#23232b}main{max-width:640px;margin:0 auto;padding:20px}img.poster{width:100%;border-radius:14px;display:block}h1{font-size:24px;margin:16px 0 6px}.cat{display:inline-block;background:#fdf0f3;color:#e0245e;border-radius:999px;padding:3px 12px;font-size:13px;font-weight:600}.desc{color:#55555f;line-height:1.55;white-space:pre-wrap}.cta{display:block;text-align:center;background:#fa3e55;color:#fff;text-decoration:none;font-weight:700;padding:14px;border-radius:12px;margin-top:22px}.note{text-align:center;color:#8a8a94;font-size:13px;margin-top:10px}</style>${inner.head || ''}</head><body><main>${inner.body}</main></body></html>`;
  const id = Number(p.id);
  const t = now();
  const v = Number.isInteger(id) && id > 0
    ? db.prepare(`SELECT * FROM videos WHERE id=? AND ${visibleVideoSQL}`).get(id, t, t)
    : null;
  if (!v) {
    return send(res, 404, page({ body: `<h1>Video not found</h1><p class="desc">This video is not available. It may have been removed, or the link is incorrect.</p><p class="note">Open the ${escHtml(appName)} app to browse the latest videos.</p>` }), { 'Content-Type': 'text/html; charset=utf-8' });
  }
  const cat = v.category_id ? db.prepare('SELECT name FROM categories WHERE id=?').get(v.category_id) : null;
  const ver = db.prepare('SELECT store_url FROM app_version WHERE id=1').get();
  const storeUrl = ver && ver.store_url ? ver.store_url : '';
  const title = v.title || 'Video';
  const desc = v.description || '';
  const og = `<meta property="og:type" content="video.other"><meta property="og:site_name" content="${escHtml(appName)}"><meta property="og:title" content="${escHtml(title)}"><meta property="og:description" content="${escHtml(desc)}">${v.thumb_url ? `<meta property="og:image" content="${escHtml(v.thumb_url)}">` : ''}<meta name="twitter:card" content="summary_large_image">`;
  const cta = storeUrl
    ? `<a class="cta" href="${escHtml(storeUrl)}">▶ Watch in the ${escHtml(appName)} app</a>`
    : `<p class="note">▶ Watch this video in the ${escHtml(appName)} app</p>`;
  const body = `${v.thumb_url ? `<img class="poster" src="${escHtml(v.thumb_url)}" alt="${escHtml(title)}">` : ''}
  <h1>${escHtml(title)}</h1>
  ${cat ? `<span class="cat">${escHtml(cat.name)}</span>` : ''}
  ${desc ? `<p class="desc">${escHtml(desc)}</p>` : ''}
  ${cta}
  <p class="note">This video plays inside the ${escHtml(appName)} app.</p>`;
  send(res, 200, page({ head: og, body, title }), { 'Content-Type': 'text/html; charset=utf-8' });
});
route('GET', '/api/docs', (req, res) => { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(DOCS_HTML); });

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.gif': 'image/gif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
function serveStatic(req, res, urlPath) {
  let file = null;
  if (urlPath === '/admin' || urlPath === '/admin/') file = path.join(PUBLIC_DIR, 'admin.html');
  else if (urlPath.startsWith('/admin/')) file = path.join(PUBLIC_DIR, urlPath.slice('/admin/'.length));
  else if (urlPath.startsWith('/uploads/')) file = path.join(UPLOAD_DIR, urlPath.slice('/uploads/'.length));
  if (!file) return false;
  const safe = path.normalize(file);
  if (!(safe.startsWith(PUBLIC_DIR) || safe.startsWith(UPLOAD_DIR)) || !fs.existsSync(safe) || fs.statSync(safe).isDirectory()) return false;
  res.writeHead(200, { 'Content-Type': MIME[path.extname(safe)] || 'application/octet-stream' });
  res.end(fs.readFileSync(safe));
  return true;
}

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://localhost');
    const query = Object.fromEntries(u.searchParams.entries());
    if (req.method === 'OPTIONS') return send(res, 204, '');
    if (serveStatic(req, res, u.pathname)) return;
    for (const r of routes) {
      if (r.method !== req.method) continue;
      const m = r.rx.exec(u.pathname);
      if (!m) continue;
      const params = {};
      r.keys.forEach((k, i) => params[k] = decodeURIComponent(m[i + 1]));
      return await r.handler(req, res, params, query);
    }
    if (u.pathname === '/') return send(res, 200, { name: 'Raaz API', status: 'ok', docs: '/api/docs', admin: '/admin' });
    err(res, 404, 'not found');
  } catch (e) {
    console.error('ERR', req.method, req.url, e.message);
    if (!res.headersSent) err(res, 500, 'server error: ' + e.message);
  }
});
server.listen(PORT, () => console.log('Raaz server listening on port ' + PORT + '  (admin: /admin, docs: /api/docs)'));
