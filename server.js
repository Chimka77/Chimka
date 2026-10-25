/* ============================================================================
   Buggy Rush — backend server
   ----------------------------------------------------------------------------
   Node.js 18+  ·  Express  ·  SQLite (better-sqlite3)  ·  tonweb

   What this does:
     • TON Connect "ton-proof" authentication (real wallet signature checks)
     • G$ ledger (1 G$ = 1 USD, stored in cents) — SQLite, single source of truth
     • TON deposits: verifies incoming treasury transactions ON CHAIN, credits G$
     • TON withdrawals: pays players from the treasury wallet
     • Rooms: entry-fee charging, refunds, host-only prize settlement with the
       same payout splits as the client, 1% platform fee to OWNER_ADDRESS
     • Shop: engines, paint, service, upgrades — prices decided by THE SERVER

   SECURITY RULE: the client never tells the server an amount to credit.
   It only says "this happened" (a tx, a room join, a race result) and the
   server recomputes everything itself.
   ========================================================================== */
'use strict';
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const TonWeb = require('tonweb');
const tonMnemonic = require('tonweb-mnemonic');
const crypto = require('crypto');

/* ------------------------------ config ---------------------------------- */
const CFG = {
  port:            +(process.env.PORT || 3000),
  dbFile:          process.env.DB_FILE || './buggyrush.db',
  owner:           process.env.OWNER_ADDRESS || '',        // receives the 1% fee (ledger credit)
  treasury:        process.env.TREASURY_ADDRESS || '',     // receives deposits / sends withdrawals
  treasuryMnemonic:process.env.TREASURY_MNEMONIC || '',    // 24 words, space separated
  toncenter:       process.env.TONCENTER_BASE || 'https://toncenter.com/api/v2',
  toncenterKey:    process.env.TONCENTER_API_KEY || '',    // raises toncenter rate limits
  origin:          process.env.ALLOWED_ORIGIN || '*',
  domain:          process.env.APP_DOMAIN || '',           // e.g. api.yourdomain.com — must equal the signed Host
  fee:             +(process.env.PLATFORM_FEE || 0.01),
  minCents:        +(process.env.MIN_TX_CENTS || 100),     // $1
  maxWdCents:      +(process.env.MAX_WITHDRAW_CENTS || 1000000),
  devAuth:         process.env.INSECURE_DEV_AUTH === '1',  // NEVER enable in production
};
if (!CFG.domain && !CFG.devAuth)
  console.warn('[warn] APP_DOMAIN not set — ton-proof domain check disabled (insecure).');
if (CFG.devAuth)
  console.warn('[warn] INSECURE_DEV_AUTH=1 — any address can log in WITHOUT a signature!');

/* -------------------------------- db ------------------------------------ */
const db = new Database(CFG.dbFile);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  address       TEXT PRIMARY KEY,
  balance_cents INTEGER NOT NULL DEFAULT 0,
  upgrades      TEXT NOT NULL DEFAULT '{"speed":0,"stamina":0}',
  eg            INTEGER NOT NULL DEFAULT 0,   -- engine index 0..4
  wear          INTEGER NOT NULL DEFAULT 0,
  rc            INTEGER NOT NULL DEFAULT 0,
  owned         TEXT NOT NULL DEFAULT '{}',
  created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token      TEXT PRIMARY KEY,
  address    TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges(
  payload    TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS deposits(                       -- idempotency: one credit per on-chain tx
  tx_hash    TEXT PRIMARY KEY,
  address    TEXT NOT NULL,
  nano       TEXT NOT NULL,
  cents      INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS withdrawals(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  address    TEXT NOT NULL,
  cents      INTEGER NOT NULL,
  nano       TEXT NOT NULL,
  to_address TEXT NOT NULL,
  status     TEXT NOT NULL,                  -- pending | sent | failed | refunded
  tx_hash    TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rooms(
  code         TEXT PRIMARY KEY,
  host_address TEXT NOT NULL,
  track        INTEGER NOT NULL DEFAULT 0,
  fee_cents    INTEGER NOT NULL DEFAULT 0,
  fair         INTEGER NOT NULL DEFAULT 0,
  max_players  INTEGER NOT NULL DEFAULT 6,
  status       TEXT NOT NULL DEFAULT 'open', -- open | settled | closed
  created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS room_players(
  code       TEXT NOT NULL,
  address    TEXT NOT NULL,
  cents_paid INTEGER NOT NULL DEFAULT 0,
  joined_at  INTEGER NOT NULL,
  PRIMARY KEY(code, address)
);
CREATE TABLE IF NOT EXISTS ledger(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  address    TEXT NOT NULL,
  kind       TEXT NOT NULL,                  -- dep|wd|entry|refund|prize|fee_owner|shop
  cents      INTEGER NOT NULL,               -- signed
  ref        TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_addr ON ledger(address);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);
`);

const now = () => Date.now();

/* --------------------------- ledger helpers ------------------------------ */
const getUser = a => db.prepare('SELECT * FROM users WHERE address=?').get(a);
function ensureUser(a) {
  db.prepare('INSERT OR IGNORE INTO users(address, created_at) VALUES(?,?)').run(a, now());
  return getUser(a);
}
function ledger(address, kind, cents, ref) {
  db.prepare('INSERT INTO ledger(address,kind,cents,ref,created_at) VALUES(?,?,?,?,?)')
    .run(address, kind, cents, ref || '', now());
}
const creditStmt = db.prepare(`
  INSERT INTO users(address,balance_cents,created_at) VALUES(?,?,?)
  ON CONFLICT(address) DO UPDATE SET balance_cents = balance_cents + excluded.balance_cents`);
function credit(address, cents, kind, ref) {
  creditStmt.run(address, cents, now());          // insert path credits `cents` as the balance
  ledger(address, kind, cents, ref);
}
function debit(address, cents, kind, ref) {       // atomic guard: no negative balances, no race
  const r = db.prepare(
    'UPDATE users SET balance_cents = balance_cents - ? WHERE address=? AND balance_cents >= ?'
  ).run(cents, address, cents);
  if (!r.changes) return false;
  ledger(address, kind, -cents, ref);
  return true;
}
const bal = a => (getUser(a) || { balance_cents: 0 }).balance_cents;

/* ------------------------------ toncenter -------------------------------- */
async function tcGet(path, params) {
  const u = new URL(CFG.toncenter + path);
  Object.entries(params || {}).forEach(([k, v]) => u.searchParams.set(k, v));
  const headers = {};
  if (CFG.toncenterKey) { u.searchParams.set('api_key', CFG.toncenterKey); headers['X-API-Key'] = CFG.toncenterKey; }
  const r = await fetch(u, { headers });
  if (!r.ok) throw new Error('toncenter HTTP ' + r.status);
  return r.json();
}
const normAddr = a => new TonWeb.utils.Address(a).toString(false);   // "wc:hex"
const short = a => a && a.length > 14 ? a.slice(0, 6) + '…' + a.slice(-4) : a;

/* ------------------------------ TON price -------------------------------- */
let priceCache = { v: 0, t: 0 };
async function tonPrice() {
  if (Date.now() - priceCache.t < 60_000) return priceCache.v;
  try {
    const r = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=the-open-network&vs_currencies=usd');
    const j = await r.json();
    priceCache = { v: +(j['the-open-network'] && j['the-open-network'].usd) || 0, t: Date.now() };
  } catch { /* keep last known */ }
  return priceCache.v;
}

/* ------------------------- ton-proof verification ------------------------ */
function le32(n) { const b = Buffer.alloc(4); b.writeInt32LE(n); return b; }
function le64(n) { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(n)); return b; }

async function walletPubkey(address) {
  const j = await tcGet('/runGetMethod', { address, method: 'get_public_key', stack: [] });
  if (!j.ok || j.result.exit_code !== 0) throw new Error('get_public_key failed — unsupported wallet contract');
  const cell = j.result.stack[0];
  const num = Array.isArray(cell) ? cell[1] : cell;      // ["num","<decimal or hex>"]
  return BigInt(num).toString(16).padStart(64, '0');
}

async function verifyTonProof(address, proof) {
  try {
    if (!proof || typeof proof.payload !== 'string') return false;
    if (CFG.domain && (!proof.domain || proof.domain.value !== CFG.domain)) {
      console.warn('[auth] bad domain:', proof.domain && proof.domain.value);
      return false;
    }
    const ts = +proof.timestamp;
    if (!ts || Math.abs(now() / 1000 - ts) > 600) return false;    // 10 min window
    const addr = new TonWeb.utils.Address(address);
    const domain = (proof.domain && proof.domain.value) || '';
    const msg = Buffer.concat([
      Buffer.from('ton-connect/sign', 'utf8'),
      le32(addr.wc),
      Buffer.from(addr.hashPart),
      le32(Buffer.byteLength(domain)),
      Buffer.from(domain, 'utf8'),
      le64(ts),
      Buffer.from(proof.payload, 'utf8'),
    ]);
    const pubHex = await walletPubkey(address);
    return TonWeb.utils.nacl.sign.detached.verify(
      msg, Buffer.from(proof.signature, 'base64'), Buffer.from(pubHex, 'hex'));
  } catch (e) {
    console.error('[auth] proof verify failed:', e.message);
    return false;
  }
}

/* --------------------------- treasury wallet ----------------------------- */
const tonweb = new TonWeb();
let twallet = null;
async function treasuryWallet() {
  if (twallet) return twallet;
  if (!CFG.treasuryMnemonic) return null;
  const words = CFG.treasuryMnemonic.trim().split(/\s+/);
  if (words.length !== 24) throw new Error('TREASURY_MNEMONIC must be 24 words');
  const seed = await tonMnemonic.mnemonicToSeed(words);
  const keyPair = TonWeb.utils.nacl.sign.keyPair.fromSeed(seed);
  const wc = CFG.treasury.includes(':') ? +CFG.treasury.split(':')[0] : 0;
  twallet = { w: tonweb.wallet.all.v4R2.create({ publicKey: keyPair.publicKey, wc }), keyPair };
  return twallet;
}
async function sendTon(toAddress, nano, comment) {
  const { w, keyPair } = await treasuryWallet();
  const seqno = (await w.methods.seqno().call()) || 0;
  await w.methods.transfer({
    secretKey: keyPair.secretKey,
    toAddress,
    amount: nano.toString(),
    seqno,
    payload: comment,
    sendMode: 3,
  }).send();
}

/* ------------------------------ rate limit ------------------------------- */
const buckets = new Map();
const rl = (tag, max, ms) => (req, res, next) => {
  const k = tag + ':' + req.ip;
  const b = buckets.get(k) || { n: 0, t: now() };
  if (now() - b.t > ms) { b.n = 0; b.t = now(); }
  b.n++;
  buckets.set(k, b);
  if (b.n > max) return res.status(429).json({ error: 'Too many requests, slow down.' });
  next();
};
setInterval(() => { const t = now(); for (const [k, v] of buckets) if (t - v.t > 600_000) buckets.delete(k); }, 60_000).unref();

/* -------------------------------- app ------------------------------------ */
const app = express();
app.use(express.json({ limit: '64kb' }));
app.use(cors({ origin: CFG.origin === '*' ? true : CFG.origin.split(','), credentials: false }));

/* auth middleware: Bearer session token */
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const s = token && db.prepare('SELECT * FROM sessions WHERE token=?').get(token);
  if (!s || s.expires_at < now()) return res.status(401).json({ error: 'Not signed in' });
  req.user = { address: s.address, token };
  next();
}

/* ------------------------- price tables (server-owned) ------------------- */
const ENG = [
  { n: 'Stock Engine',  p: 0,  k: 225 },
  { n: 'Engine Unit 1', p: 25, k: 235 },
  { n: 'Engine Unit 2', p: 45, k: 245 },
  { n: 'Engine Unit 3', p: 80, k: 255 },
  { n: 'Engine Unit 4', p: 134, k: 265 },
];
const UP_PRICE = [7, 10, 10, 20, 20, 20, 30, 30, 30, 30];     // level 0->1 is UP_PRICE[0], etc.
const svcCost = eg => (eg ? Math.round(ENG[eg].p * 30) : 500); // cents; mirrors svcC()
const splits = n => (n < 4 ? [1] : n < 10 ? [.5, .3, .2] : [.404, .212, .152, .121, .111]);
function payouts(feeCents, n) {
  const pool = feeCents * n;
  const fee = Math.round(pool * CFG.fee);
  const net = pool - fee;
  const a = splits(n).map(x => Math.floor(net * x));
  a[0] += net - a.reduce((x, y) => x + y, 0);                  // dust to 1st place
  return { pool, fee, net, a };
}

/* ================================ ROUTES ================================= */

app.get('/api/health', (req, res) => res.json({ ok: true, ts: now() }));

/* ---- auth: challenge → verify (ton-proof) ---- */
app.post('/api/auth/challenge', rl('ch', 30, 60_000), (req, res) => {
  const payload = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO challenges(payload,created_at) VALUES(?,?)').run(payload, now());
  db.prepare('DELETE FROM challenges WHERE created_at<?').run(now() - 600_000);
  res.json({ payload });
});

app.post('/api/auth/verify', rl('vf', 30, 60_000), async (req, res) => {
  const { address, proof } = req.body || {};
  let ok = false;
  try { new TonWeb.utils.Address(address); } catch { return res.status(400).json({ error: 'Bad address' }); }

  if (CFG.devAuth) {
    console.warn('[auth] DEV login for', short(address));
    ok = true;
  } else {
    if (!proof) return res.status(400).json({ error: 'Missing ton-proof' });
    const ch = db.prepare('SELECT * FROM challenges WHERE payload=?').get(proof.payload);
    if (ch) db.prepare('DELETE FROM challenges WHERE payload=?').run(proof.payload);  // one-time use
    else return res.status(401).json({ error: 'Unknown or expired challenge' });
    ok = await verifyTonProof(address, proof);
  }
  if (!ok) return res.status(401).json({ error: 'Signature verification failed' });

  ensureUser(address);
  const token = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions(token,address,created_at,expires_at) VALUES(?,?,?,?)')
    .run(token, address, now(), now() + 7 * 86400_000);
  res.json({ token, address, balance: bal(address) });
});

/* ---- account ---- */
app.get('/api/me', auth, (req, res) => {
  const u = ensureUser(req.user.address);
  res.json({
    address: u.address, balance: u.balance_cents,
    upgrades: JSON.parse(u.upgrades), eg: u.eg, wear: u.wear, rc: u.rc,
    owned: JSON.parse(u.owned),
  });
});
app.get('/api/txlog', auth, (req, res) => {
  const rows = db.prepare('SELECT kind,cents,ref,created_at FROM ledger WHERE address=? ORDER BY id DESC LIMIT 12')
    .all(req.user.address);
  res.json({ tx: rows.map(r => ({ k: r.kind, c: r.cents, t: r.created_at, ref: r.ref })) });
});

/* ---- deposit: client sends TON to treasury with comment = session token,
       then calls this. Server finds the tx ON CHAIN and credits the USD
       value at the current rate. Idempotent per tx hash. ---- */
app.post('/api/wallet/deposit', auth, rl('dep', 12, 60_000), async (req, res) => {
  const price = await tonPrice();
  if (!price) return res.status(503).json({ error: 'Could not get the TON price, try again' });
  let txs;
  try {
    const j = await tcGet('/getTransactions', { address: CFG.treasury, limit: 100 });
    if (!j.ok) throw new Error(j.error || 'toncenter error');
    txs = j.result || [];
  } catch (e) {
    return res.status(502).json({ error: 'Blockchain lookup failed: ' + e.message });
  }
  const myAddr = normAddr(req.user.address);
  let credited = 0;
  for (const tx of txs) {
    const msg = tx.in_msg;
    if (!msg || !msg.message) continue;                       // comment must equal the session token
    if (msg.message !== req.user.token) continue;
    let src; try { src = normAddr(msg.source); } catch { continue; }
    if (src !== myAddr) continue;
    const nano = BigInt(msg.value || 0);
    const cents = Math.floor(Number(nano) * price / 1e7);     // nano × USD/TON × 100 / 1e9
    if (cents < CFG.minCents) continue;                       // ignore dust under $1
    const ins = db.prepare('INSERT OR IGNORE INTO deposits(tx_hash,address,nano,cents,created_at) VALUES(?,?,?,?,?)')
      .run(tx.transaction_id.hash, req.user.address, nano.toString(), cents, now());
    if (ins.changes) { credit(req.user.address, cents, 'dep', tx.transaction_id.hash); credited += cents; }
  }
  res.json({ credited, balance: bal(req.user.address) });
});

/* ---- withdrawal: server pays TON from the treasury wallet ---- */
app.post('/api/wallet/withdraw', auth, rl('wd', 6, 60_000), async (req, res) => {
  const cents = Math.round(+((req.body || {}).cents) || 0);
  if (!(cents >= CFG.minCents)) return res.status(400).json({ error: 'Minimum withdrawal is $1' });
  if (cents > CFG.maxWdCents) return res.status(400).json({ error: 'Maximum withdrawal is $' + (CFG.maxWdCents / 100) });
  if (!CFG.treasuryMnemonic) return res.status(503).json({ error: 'Withdrawals are not configured' });
  const price = await tonPrice();
  if (!price) return res.status(503).json({ error: 'Could not get the TON price, try again' });
  const nano = BigInt(Math.max(1, Math.round(cents / 100 / price * 1e9)));

  let id;
  try {
    db.transaction(() => {
      if (!debit(req.user.address, cents, 'wd', 'pending')) throw Object.assign(new Error('Insufficient balance'), { code: 402 });
      id = db.prepare(`INSERT INTO withdrawals(address,cents,nano,to_address,status,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?)`)
        .run(req.user.address, cents, nano.toString(), req.user.address, 'pending', now(), now()).lastInsertRowid;
    })();
  } catch (e) {
    if (e.code === 402) return res.status(402).json({ error: 'Insufficient balance' });
    throw e;
  }
  try {
    await sendTon(req.user.address, nano, 'Buggy Rush withdrawal #' + id);
    db.prepare("UPDATE withdrawals SET status='sent', tx_hash='', updated_at=? WHERE id=?").run(now(), id);
    res.json({ ok: true, cents, nano: nano.toString(), balance: bal(req.user.address) });
  } catch (e) {
    console.error('[withdraw] send failed:', e.message);
    db.transaction(() => {
      db.prepare("UPDATE withdrawals SET status='refunded', updated_at=? WHERE id=?").run(now(), id);
      credit(req.user.address, cents, 'refund', 'wd#' + id);
    })();
    res.status(502).json({ error: 'Payment failed, your G$ were refunded' });
  }
});

/* ---- rooms ---- */
const CODE_RE = /^[A-HJ-NP-Z2-9]{5}$/;   // same charset the client generates

app.post('/api/room/create', auth, rl('room', 20, 60_000), (req, res) => {
  const { code, track = 0, fee = 0, fair = false, maxPlayers = 6 } = req.body || {};
  if (!CODE_RE.test(code || '')) return res.status(400).json({ error: 'Bad room code' });
  const feeC = Math.round((+fee || 0) * 100);
  if (feeC < 0 || feeC > 100_000) return res.status(400).json({ error: 'Fee must be $0–$1000' });
  if (db.prepare('SELECT 1 FROM rooms WHERE code=?').get(code)) return res.status(409).json({ error: 'Code taken, regenerate' });
  try {
    db.transaction(() => {
      db.prepare('INSERT INTO rooms(code,host_address,track,fee_cents,fair,max_players,status,created_at) VALUES(?,?,?,?,?,?,?,?)')
        .run(code, req.user.address, track | 0, feeC, fair ? 1 : 0, Math.min(20, Math.max(2, maxPlayers | 0)), 'open', now());
      if (feeC > 0) {
        if (!debit(req.user.address, feeC, 'entry', 'room:' + code)) throw Object.assign(new Error('Insufficient balance'), { code: 402 });
        db.prepare('INSERT INTO room_players(code,address,cents_paid,joined_at) VALUES(?,?,?,?)').run(code, req.user.address, feeC, now());
      }
    })();
  } catch (e) {
    if (e.code === 402) { db.prepare('DELETE FROM rooms WHERE code=?').run(code); return res.status(402).json({ error: 'Insufficient balance' }); }
    throw e;
  }
  res.json({ ok: true, fee: feeC, balance: bal(req.user.address) });
});

app.post('/api/room/join', auth, rl('room', 30, 60_000), (req, res) => {
  const code = String((req.body || {}).code || '').toUpperCase();
  const room = db.prepare('SELECT * FROM rooms WHERE code=?').get(code);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  if (room.status !== 'open') return res.status(409).json({ error: 'Room is closed' });
  if (db.prepare('SELECT 1 FROM room_players WHERE code=? AND address=?').get(code, req.user.address))
    return res.status(409).json({ error: 'Already joined' });
  const count = db.prepare('SELECT COUNT(*) c FROM room_players WHERE code=?').get(code).c;
  if (count >= room.max_players) return res.status(409).json({ error: 'Room is full' });
  try {
    db.transaction(() => {
      if (room.fee_cents > 0) {
        if (!debit(req.user.address, room.fee_cents, 'entry', 'room:' + code)) throw Object.assign(new Error('Insufficient balance'), { code: 402 });
      }
      db.prepare('INSERT INTO room_players(code,address,cents_paid,joined_at) VALUES(?,?,?,?)')
        .run(code, req.user.address, room.fee_cents, now());
    })();
  } catch (e) {
    if (e.code === 402) return res.status(402).json({ error: 'Insufficient balance' });
    throw e;
  }
  res.json({ ok: true, balance: bal(req.user.address) });
});

app.post('/api/room/leave', auth, (req, res) => {
  const code = String((req.body || {}).code || '').toUpperCase();
  const room = db.prepare('SELECT * FROM rooms WHERE code=?').get(code);
  if (!room || room.status !== 'open') return res.status(409).json({ error: 'Cannot leave now' });
  const row = db.prepare('SELECT * FROM room_players WHERE code=? AND address=?').get(code, req.user.address);
  if (!row) return res.status(404).json({ error: 'Not in this room' });
  db.transaction(() => {
    db.prepare('DELETE FROM room_players WHERE code=? AND address=?').run(code, req.user.address);
    if (row.cents_paid > 0) credit(req.user.address, row.cents_paid, 'refund', 'room:' + code);
  })();
  res.json({ ok: true, balance: bal(req.user.address) });
});

/* ---- settlement: HOST ONLY, once, results must cover exactly the paid players.
       Payouts recomputed server-side. Front-end 'fin' is race seconds. ---- */
app.post('/api/race/settle', auth, rl('settle', 20, 60_000), (req, res) => {
  const { code, results } = req.body || {};
  const room = db.prepare('SELECT * FROM rooms WHERE code=?').get(String(code || '').toUpperCase());
  if (!room) return res.status(404).json({ error: 'Room not found' });
  if (room.host_address !== req.user.address) return res.status(403).json({ error: 'Only the host can settle' });
  if (room.status !== 'open') return res.status(409).json({ error: 'Already settled' });
  if (now() - room.created_at < 30_000) return res.status(429).json({ error: 'Race too short to be real' });

  const paid = db.prepare('SELECT * FROM room_players WHERE code=? AND cents_paid>0').all(room.code);
  let P = null;
  if (paid.length) {
    if (!Array.isArray(results) || results.length !== paid.length)
      return res.status(400).json({ error: 'Results must list exactly the ' + paid.length + ' paid players' });
    const byAddr = new Map();
    for (const r of results) {
      let a; try { a = normAddr(r.address); } catch { return res.status(400).json({ error: 'Bad address in results' }); }
      if (byAddr.has(a)) return res.status(400).json({ error: 'Duplicate address in results' });
      byAddr.set(a, { fin: +r.fin || 0, d: +r.d || 0 });
    }
    const ranked = paid.map(p => {
      const r = byAddr.get(normAddr(p.address));
      if (!r) return res && null;                       // caught below
      return { address: p.address, fin: r.fin, d: r.d };
    });
    if (ranked.some(x => !x)) return res.status(400).json({ error: 'Results missing a paid player' });
    ranked.sort((a, b) =>
      a.fin && b.fin ? a.fin - b.fin :
      a.fin ? -1 : b.fin ? 1 : b.d - a.d);              // same ordering as the client's rank()

    P = payouts(room.fee_cents, paid.length);
    db.transaction(() => {
      ranked.forEach((p, i) => {
        if (i < P.a.length && P.a[i] > 0) credit(p.address, P.a[i], 'prize', 'room:' + room.code);
      });
      if (P.fee > 0 && CFG.owner) credit(CFG.owner, P.fee, 'fee_owner', 'room:' + room.code);
      db.prepare("UPDATE rooms SET status='settled' WHERE code=?").run(room.code);
    })();
  } else {
    db.prepare("UPDATE rooms SET status='settled' WHERE code=?").run(room.code);
  }
  res.json({ payouts: P ? P.a : [], fee: P ? P.fee : 0, balance: bal(req.user.address) });
});

/* ---- shop: server decides every price ---- */
app.post('/api/shop/buy', auth, rl('shop', 40, 60_000), (req, res) => {
  const item = String((req.body || {}).item || '');
  const u = ensureUser(req.user.address);
  const up = JSON.parse(u.upgrades), owned = JSON.parse(u.owned);
  let cost = 0, eg = u.eg, wear = u.wear, rc = u.rc;
  const apply = [];

  let m = /^engine:([1-4])$/.exec(item);
  if (m) { const i = +m[1]; cost = ENG[i].p * 100; eg = i; wear = 0; rc = 0; apply.push(`engine=${i}`); }
  else if ((m = /^paint:(\d{1,2})$/.exec(item))) { cost = 300; owned['pc'] = +m[1]; apply.push('paint'); }
  else if (item === 'service') { cost = svcCost(u.eg); wear = 0; rc = 0; apply.push('service'); }
  else if ((m = /^upgrade:(speed|stamina)$/.exec(item))) {
    const lv = up[m[1]] || 0;
    if (lv >= 10) return res.status(400).json({ error: 'Already max level' });
    cost = UP_PRICE[lv] * 100;
    up[m[1]] = lv + 1;
  } else return res.status(400).json({ error: 'Unknown item' });

  if (cost <= 0) return res.status(400).json({ error: 'Nothing to buy' });
  try {
    db.transaction(() => {
      if (!debit(req.user.address, cost, 'shop', item)) throw Object.assign(new Error('Insufficient balance'), { code: 402 });
      db.prepare('UPDATE users SET upgrades=?, eg=?, wear=?, rc=?, owned=? WHERE address=?')
        .run(JSON.stringify(up), eg, wear, rc, JSON.stringify(owned), req.user.address);
    })();
  } catch (e) {
    if (e.code === 402) return res.status(402).json({ error: 'Insufficient balance' });
    throw e;
  }
  res.json({ ok: true, balance: bal(req.user.address), upgrades: up, eg, wear, rc, owned });
});

/* error handler + boot */
app.use((err, req, res, next) => {
  console.error('[error]', err.message);
  if (err.code === 402) return res.status(402).json({ error: 'Insufficient balance' });
  res.status(500).json({ error: 'Server error' });
});

app.listen(CFG.port, async () => {
  console.log(`Buggy Rush backend on :${CFG.port}`);
  console.log(`  owner:    ${short(CFG.owner) || '(not set)'}`);
  console.log(`  treasury: ${short(CFG.treasury) || '(not set)'}`);
  if (CFG.treasuryMnemonic) {
    try {
      const { w } = await treasuryWallet();
      console.log('  treasury derived address:', (await w.getAddress()).toString(true, true, false),
        '— fund & deploy it before accepting deposits');
    } catch (e) { console.error('  treasury init failed:', e.message); }
  }
});
