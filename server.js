"use strict";
/* Views backend: accounts + email OTP, AI generation, Stripe card billing.
   Serves public/index.html so the page and the API share one origin (cookies just work). */
const express = require("express");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const Stripe = require("stripe");

const env = process.env;
const PROD = env.NODE_ENV === "production";
const PORT = env.PORT || 3000;
const APP_URL = (env.APP_URL || "http://localhost:" + PORT).replace(/\/$/, "");
const OTP_SECRET = env.OTP_SECRET || "dev-only-secret";
if (PROD && !env.OTP_SECRET) { console.error("Set OTP_SECRET before running in production."); process.exit(1); }

/* Plan limits. Edit freely. These also feed the numbers shown on your Plans tab. */
const LIMITS = {
  free: { perDay: 2, perMonth: 20 },
  plus: { perDay: 3, perMonth: 90 },
  pro: { perDay: 50, perMonth: 1000 }
};
const GLOBAL_DAILY_CAP = +env.GLOBAL_DAILY_CAP || 300;

/* ---------- storage ---------- */
const DATA_DIR = path.resolve(env.DATA_DIR || path.join(__dirname, "data"));
const MEDIA_DIR = path.join(DATA_DIR, "media");
fs.mkdirSync(MEDIA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, "views.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0, plan TEXT NOT NULL DEFAULT 'free',
  stripe_customer TEXT, stripe_sub TEXT, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS otps(
  email TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, last_sent INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, mode TEXT NOT NULL, prompt TEXT NOT NULL,
  status TEXT NOT NULL, provider_id TEXT, url TEXT, error TEXT, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS jobs_user ON jobs(user_id, created_at);
`);
setInterval(() => {
  db.prepare("DELETE FROM sessions WHERE expires_at<?").run(Date.now());
  db.prepare("DELETE FROM otps WHERE expires_at<?").run(Date.now() - 3600e3);
}, 3600e3).unref();

/* ---------- helpers ---------- */
const httpErr = (status, message, extra) => Object.assign(new Error(message), { status, extra });
const ah = fn => (req, res, next) => fn(req, res, next).catch(next);
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const hmac = s => crypto.createHmac("sha256", OTP_SECRET).update(s).digest("hex");
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const normEmail = e => String(e || "").trim().toLowerCase();
const validEmail = e => e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const getUser = email => db.prepare("SELECT * FROM users WHERE email=?").get(email);
const DUMMY_HASH = bcrypt.hashSync("not-a-real-password", 10);

/* ---------- email (Resend) ---------- */
async function sendMail(to, subject, html) {
  if (!env.RESEND_API_KEY) {
    if (PROD) throw httpErr(503, "Email isn't set up yet.");
    console.log("\n[dev email] to=" + to + "\n" + html.replace(/<[^>]+>/g, " ") + "\n");
    return;
  }
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: "Bearer " + env.RESEND_API_KEY, "Content-Type": "application/json" },
    body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject, html })
  });
  if (!r.ok) { console.error("Resend error", r.status, await r.text()); throw httpErr(502, "We couldn't send the email. Try again shortly."); }
}

/* ---------- OTP ---------- */
async function issueOtp(email) {
  const row = db.prepare("SELECT last_sent FROM otps WHERE email=?").get(email);
  if (row && Date.now() - row.last_sent < 60e3) throw httpErr(429, "Please wait a minute before asking for another code.");
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  db.prepare(`INSERT INTO otps(email,code_hash,expires_at,attempts,last_sent) VALUES(?,?,?,0,?)
    ON CONFLICT(email) DO UPDATE SET code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0,last_sent=excluded.last_sent`)
    .run(email, hmac(email + ":" + code), Date.now() + 10 * 60e3, Date.now());
  await sendMail(email, "Your Views verification code",
    `<div style="font-family:system-ui,sans-serif"><p>Your verification code is:</p>
     <p style="font-size:32px;font-weight:800;letter-spacing:6px">${code}</p>
     <p>It expires in 10 minutes. If you didn't ask for it, you can ignore this email.</p></div>`);
}
function checkOtp(email, code) {
  const row = db.prepare("SELECT * FROM otps WHERE email=?").get(email);
  if (!row || row.expires_at < Date.now()) throw httpErr(400, "That code has expired. Ask for a new one.");
  if (row.attempts >= 5) throw httpErr(429, "Too many wrong tries. Ask for a new code.");
  db.prepare("UPDATE otps SET attempts=attempts+1 WHERE email=?").run(email);
  if (!/^\d{6}$/.test(code) || !safeEq(row.code_hash, hmac(email + ":" + code))) throw httpErr(400, "That code isn't right.");
  db.prepare("DELETE FROM otps WHERE email=?").run(email);
}

/* ---------- sessions ---------- */
function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString("hex"), ttl = 30 * 86400e3;
  db.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").run(sha(token), userId, Date.now() + ttl);
  res.cookie("sid", token, { httpOnly: true, sameSite: "lax", secure: PROD, maxAge: ttl, path: "/" });
}
function requireAuth(req, res, next) {
  const t = req.cookies && req.cookies.sid;
  const row = t && db.prepare(`SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.expires_at>? AND u.verified=1`).get(sha(t), Date.now());
  if (!row) return res.status(401).json({ error: "Please log in." });
  req.user = row; next();
}

/* ---------- app ---------- */
const app = express();
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

const stripe = env.STRIPE_SECRET_KEY ? new Stripe(env.STRIPE_SECRET_KEY) : null;
const PRICES = { plus: env.STRIPE_PRICE_PLUS, pro: env.STRIPE_PRICE_PRO };
const planFromPrice = id => Object.keys(PRICES).find(k => PRICES[k] && PRICES[k] === id) || null;
const setPlan = (uid, plan) => db.prepare("UPDATE users SET plan=? WHERE id=?").run(plan, uid);

/* Stripe webhook: must read the raw body, so it goes BEFORE express.json() */
app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), (req, res) => {
  if (!stripe || !env.STRIPE_WEBHOOK_SECRET) return res.sendStatus(503);
  let ev;
  try { ev = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], env.STRIPE_WEBHOOK_SECRET); }
  catch (e) { return res.status(400).send("Bad signature"); }
  if (ev.type.startsWith("customer.subscription.")) {
    const sub = ev.data.object;
    const user = db.prepare("SELECT * FROM users WHERE stripe_customer=?").get(String(sub.customer));
    if (user && user.stripe_sub === sub.id) {
      if (["active", "trialing"].includes(sub.status)) {
        const p = planFromPrice(sub.items && sub.items.data[0] && sub.items.data[0].price.id);
        if (p) setPlan(user.id, p);
      } else if (["canceled", "unpaid", "incomplete_expired"].includes(sub.status)) {
        setPlan(user.id, "free");
        db.prepare("UPDATE users SET stripe_sub=NULL WHERE id=?").run(user.id);
      }
    }
  }
  res.json({ received: true });
});

app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());
app.use("/media", express.static(MEDIA_DIR, { maxAge: "1d", index: false }));

const authLimiter = rateLimit({ windowMs: 15 * 60e3, limit: 30, standardHeaders: true, legacyHeaders: false, message: { error: "Too many attempts. Try again in a few minutes." } });
const genLimiter = rateLimit({ windowMs: 60e3, limit: 20, standardHeaders: true, legacyHeaders: false, message: { error: "Slow down a little." } });

/* ---------- accounts ---------- */
function readCreds(body) {
  const email = normEmail(body && body.email), password = String((body && body.password) || "");
  if (!validEmail(email)) throw httpErr(400, "Enter a valid email address.");
  return { email, password };
}
app.post("/api/signup", authLimiter, ah(async (req, res) => {
  const { email, password } = readCreds(req.body);
  if (password.length < 8 || password.length > 128) throw httpErr(400, "Use a password of 8 to 128 characters.");
  const existing = getUser(email);
  if (existing && existing.verified) throw httpErr(409, "An account with this email already exists. Log in instead.");
  const hash = await bcrypt.hash(password, 11);
  if (existing) db.prepare("UPDATE users SET pass_hash=? WHERE id=?").run(hash, existing.id);
  else db.prepare("INSERT INTO users(email,pass_hash,created_at) VALUES(?,?,?)").run(email, hash, Date.now());
  await issueOtp(email);
  res.json({ needsOtp: true });
}));
app.post("/api/verify-otp", authLimiter, ah(async (req, res) => {
  const email = normEmail(req.body && req.body.email), code = String((req.body && req.body.code) || "").trim();
  const user = getUser(email);
  if (!user) throw httpErr(400, "That code isn't right.");
  checkOtp(email, code);
  db.prepare("UPDATE users SET verified=1 WHERE id=?").run(user.id);
  startSession(res, user.id);
  res.json({ ok: true });
}));
app.post("/api/resend-otp", authLimiter, ah(async (req, res) => {
  const email = normEmail(req.body && req.body.email), user = getUser(email);
  if (user && !user.verified) await issueOtp(email);
  res.json({ ok: true });
}));
app.post("/api/login", authLimiter, ah(async (req, res) => {
  const { email, password } = readCreds(req.body);
  const user = getUser(email);
  const ok = await bcrypt.compare(password, user ? user.pass_hash : DUMMY_HASH);
  if (!user || !ok) throw httpErr(401, "Wrong email or password.");
  if (!user.verified) {
    await issueOtp(email).catch(() => {});
    throw httpErr(403, "Please confirm your email with the 6-digit code.", { needsOtp: true });
  }
  startSession(res, user.id);
  res.json({ ok: true });
}));
app.post("/api/logout", ah(async (req, res) => {
  if (req.cookies && req.cookies.sid) db.prepare("DELETE FROM sessions WHERE token_hash=?").run(sha(req.cookies.sid));
  res.clearCookie("sid", { path: "/" });
  res.json({ ok: true });
}));

function usage(uid) {
  const d = new Date();
  const day = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()), mon = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
  const q = db.prepare("SELECT COUNT(*) n FROM jobs WHERE user_id=? AND status!='failed' AND created_at>=?");
  return { today: q.get(uid, day).n, month: q.get(uid, mon).n, day };
}
app.get("/api/me", requireAuth, (req, res) => {
  const u = usage(req.user.id);
  res.json({ email: req.user.email, plan: req.user.plan, usage: { today: u.today, month: u.month }, limits: LIMITS });
});

/* ---------- AI generation (Replicate) ---------- */
async function replicate(method, p, body) {
  const r = await fetch("https://api.replicate.com/v1" + p, {
    method, headers: { Authorization: "Bearer " + env.REPLICATE_API_TOKEN, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined
  });
  if (!r.ok) throw new Error("Replicate " + r.status + ": " + (await r.text()).slice(0, 300));
  return r.json();
}
const failJob = (id, msg) => { db.prepare("UPDATE jobs SET status='failed',error=? WHERE id=?").run(msg, id); return db.prepare("SELECT * FROM jobs WHERE id=?").get(id); };
function firstUrl(o) {
  if (typeof o === "string") return /^https?:\/\//.test(o) ? o : null;
  if (Array.isArray(o)) { for (const x of o) { const r = firstUrl(x); if (r) return r; } }
  else if (o && typeof o === "object") { for (const k of Object.keys(o)) { const r = firstUrl(o[k]); if (r) return r; } }
  return null;
}
async function startJob(id, model, input) {
  try {
    const p = await replicate("POST", "/models/" + model + "/predictions", { input });
    db.prepare("UPDATE jobs SET status='running',provider_id=? WHERE id=?").run(p.id, id);
  } catch (e) {
    console.error("start job failed", id, e.message);
    failJob(id, "The AI service couldn't start this one. You weren't charged a generation.");
  }
}
const finalizing = new Set();
async function refreshJob(job) {
  if (Date.now() - job.created_at > 20 * 60e3) return failJob(job.id, "This took too long. Please try again.");
  let p;
  try { p = await replicate("GET", "/predictions/" + job.provider_id); }
  catch (e) { console.error("poll error", e.message); return job; }
  if (p.status === "succeeded") {
    if (finalizing.has(job.id)) return job;
    finalizing.add(job.id);
    try {
      const src = firstUrl(p.output);
      if (!src) return failJob(job.id, "The AI finished but sent no file. Please try again.");
      const r = await fetch(src);
      if (!r.ok) throw new Error("download " + r.status);
      const m = new URL(src).pathname.match(/\.(mp4|webm|mov|glb|gltf|obj|fbx|usdz)$/i);
      const ext = m ? m[0].toLowerCase() : (job.mode === "3d" ? ".glb" : ".mp4");
      fs.writeFileSync(path.join(MEDIA_DIR, job.id + ext), Buffer.from(await r.arrayBuffer()));
      db.prepare("UPDATE jobs SET status='done',url=? WHERE id=?").run("/media/" + job.id + ext, job.id);
      return db.prepare("SELECT * FROM jobs WHERE id=?").get(job.id);
    } catch (e) {
      console.error("finalize failed", job.id, e.message);
      return failJob(job.id, "We couldn't save your result. Please try again.");
    } finally { finalizing.delete(job.id); }
  }
  if (p.status === "failed" || p.status === "canceled") {
    console.error("job failed", job.id, p.error);
    return failJob(job.id, "The AI couldn't make this one. Try rewording your idea. This didn't use up a generation.");
  }
  return job;
}

app.post("/api/generate", requireAuth, genLimiter, ah(async (req, res) => {
  const { mode, prompts, style, ratio } = req.body || {};
  if (!["video", "3d", "film"].includes(mode)) throw httpErr(400, "Unknown mode.");
  if (!Array.isArray(prompts) || !prompts.length || prompts.length > 24) throw httpErr(400, "Send between 1 and 24 scenes.");
  const clean = prompts.map(p => String(p || "").trim().slice(0, 2000)).filter(p => p.length >= 3);
  if (!clean.length) throw httpErr(400, "Describe what you want to see.");
  const model = mode === "3d" ? env.MODEL_3D : env.MODEL_VIDEO;
  if (!model || !env.REPLICATE_API_TOKEN) throw httpErr(503, mode === "3d" ? "3D generation isn't switched on yet." : "Video generation isn't switched on yet.");
  const lim = LIMITS[req.user.plan] || LIMITS.free;
  const styleTxt = String(style || "").slice(0, 60), ratioTxt = /^\d{1,2}:\d{1,2}$/.test(String(ratio)) ? String(ratio) : "16:9";

  const jobs = db.transaction(() => {
    const u = usage(req.user.id);
    const global = db.prepare("SELECT COUNT(*) n FROM jobs WHERE status!='failed' AND created_at>=?").get(u.day).n;
    if (global + clean.length > GLOBAL_DAILY_CAP) throw httpErr(503, "We're at capacity today. Please try again tomorrow.");
    if (u.today + clean.length > lim.perDay) throw httpErr(429, "That would pass your daily limit of " + lim.perDay + ". Try fewer scenes, wait until tomorrow, or upgrade.");
    if (u.month + clean.length > lim.perMonth) throw httpErr(429, "That would pass your monthly limit of " + lim.perMonth + ".");
    const ins = db.prepare("INSERT INTO jobs(id,user_id,mode,prompt,status,created_at) VALUES(?,?,?,?, 'queued', ?)");
    return clean.map(p => { const id = crypto.randomUUID(); ins.run(id, req.user.id, mode, p, Date.now()); return { id, p }; });
  })();

  await Promise.all(jobs.map(j => {
    const input = { prompt: styleTxt ? j.p + ". Style: " + styleTxt + "." : j.p };
    if (mode !== "3d") input.aspect_ratio = ratioTxt; /* input names differ per model: adjust to your MODEL_VIDEO */
    return startJob(j.id, model, input);
  }));
  res.json({ jobs: jobs.map(j => ({ id: j.id })) });
}));
app.get("/api/jobs/:id", requireAuth, ah(async (req, res) => {
  let job = db.prepare("SELECT * FROM jobs WHERE id=? AND user_id=?").get(req.params.id, req.user.id);
  if (!job) throw httpErr(404, "Job not found.");
  if (job.status === "running" && job.provider_id) job = await refreshJob(job);
  if (job.status === "done") return res.json({ status: "done", url: job.url });
  if (job.status === "failed") return res.json({ status: "failed", error: job.error || "Generation failed." });
  res.json({ status: "running" });
}));

/* ---------- billing (Stripe, card payments) ---------- */
const needStripe = (req, res, next) => stripe ? next() : next(httpErr(503, "Payments aren't switched on yet."));
async function ensureCustomer(user) {
  if (user.stripe_customer) return user.stripe_customer;
  const c = await stripe.customers.create({ email: user.email, metadata: { user_id: String(user.id) } });
  db.prepare("UPDATE users SET stripe_customer=? WHERE id=?").run(c.id, user.id);
  return c.id;
}
app.get("/api/billing", requireAuth, ah(async (req, res) => {
  if (!stripe || !req.user.stripe_sub) return res.json({ card: null, cancelling: false, renews: null });
  const sub = await stripe.subscriptions.retrieve(req.user.stripe_sub, { expand: ["default_payment_method"] });
  const pm = sub.default_payment_method;
  const end = (sub.items && sub.items.data[0] && sub.items.data[0].current_period_end) || sub.current_period_end;
  res.json({
    card: pm && pm.card ? { brand: pm.card.brand, last4: pm.card.last4 } : null,
    cancelling: !!sub.cancel_at_period_end,
    renews: end ? end * 1000 : null
  });
}));
app.post("/api/billing/subscribe", requireAuth, needStripe, ah(async (req, res) => {
  const plan = req.body && req.body.plan, user = req.user;
  if (!PRICES[plan]) throw httpErr(400, "Unknown plan.");
  if (user.plan === plan) throw httpErr(400, "You're already on this plan.");
  const customer = await ensureCustomer(user);
  if (user.stripe_sub) {
    const old = await stripe.subscriptions.retrieve(user.stripe_sub).catch(() => null);
    if (old && ["active", "trialing"].includes(old.status)) {
      await stripe.subscriptions.update(old.id, {
        items: [{ id: old.items.data[0].id, price: PRICES[plan] }],
        proration_behavior: "create_prorations", cancel_at_period_end: false
      });
      setPlan(user.id, plan);
      return res.json({ updated: true });
    }
    if (old && old.status === "incomplete") await stripe.subscriptions.cancel(old.id).catch(() => {});
  }
  const sub = await stripe.subscriptions.create({
    customer, items: [{ price: PRICES[plan] }],
    payment_behavior: "default_incomplete",
    payment_settings: { save_default_payment_method: "on_subscription" },
    expand: ["latest_invoice.confirmation_secret"],
    metadata: { user_id: String(user.id), plan }
  });
  db.prepare("UPDATE users SET stripe_sub=? WHERE id=?").run(sub.id, user.id);
  const cs = sub.latest_invoice && sub.latest_invoice.confirmation_secret && sub.latest_invoice.confirmation_secret.client_secret;
  if (!cs) throw httpErr(500, "Couldn't start the payment. Please try again.");
  res.json({ clientSecret: cs, publishableKey: env.STRIPE_PUBLISHABLE_KEY });
}));
const setCancel = flag => ah(async (req, res) => {
  if (!req.user.stripe_sub) throw httpErr(400, "You don't have a paid plan.");
  await stripe.subscriptions.update(req.user.stripe_sub, { cancel_at_period_end: flag });
  res.json({ ok: true });
});
app.post("/api/billing/cancel", requireAuth, needStripe, setCancel(true));
app.post("/api/billing/resume", requireAuth, needStripe, setCancel(false));
app.post("/api/billing/portal", requireAuth, needStripe, ah(async (req, res) => {
  const customer = await ensureCustomer(req.user);
  const s = await stripe.billingPortal.sessions.create({ customer, return_url: APP_URL + "/" });
  res.json({ url: s.url });
}));

/* ---------- static + errors ---------- */
app.use("/api", (req, res) => res.status(404).json({ error: "Not found." }));
app.use(express.static(path.join(__dirname, "public")));
app.use((err, req, res, next) => {
  if (!err.status) console.error(err);
  res.status(err.status || 500).json(Object.assign({ error: err.status ? err.message : "Something went wrong. Please try again." }, err.extra || {}));
});
app.listen(PORT, () => console.log("Views running on " + APP_URL));
