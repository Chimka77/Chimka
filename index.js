"use strict";
/* Views backend on Firebase: Cloud Functions + Firestore + Storage.
   Firebase Hosting sends every /api/** request to the `api` function below.
   NOTE: Hosting only forwards ONE cookie to functions, and it must be named __session. */
const { onRequest } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const Stripe = require("stripe");

admin.initializeApp();
const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;
const env = process.env;
const EMU = !!env.FUNCTIONS_EMULATOR;
const APP_URL = (env.APP_URL || "http://localhost:5000").replace(/\/$/, "");

/* Plan limits. Edit freely. */
const LIMITS = {
  free: { perDay: 2, perMonth: 20 },
  plus: { perDay: 3, perMonth: 90 },
  pro: { perDay: 50, perMonth: 1000 }
};
const GLOBAL_DAILY_CAP = +env.GLOBAL_DAILY_CAP || 300;
const TYPES = { mp4: "video/mp4", webm: "video/webm", mov: "video/quicktime", glb: "model/gltf-binary", gltf: "model/gltf+json", obj: "text/plain", fbx: "application/octet-stream", usdz: "model/vnd.usdz+zip" };

/* ---------- helpers ---------- */
const httpErr = (status, message, extra) => Object.assign(new Error(message), { status, extra });
const ah = fn => (req, res, next) => fn(req, res, next).catch(next);
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
function hmac(s) {
  if (!EMU && !env.OTP_SECRET) throw httpErr(500, "Server isn't set up yet (missing OTP_SECRET).");
  return crypto.createHmac("sha256", env.OTP_SECRET || "dev-only-secret").update(s).digest("hex");
}
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const normEmail = e => String(e || "").trim().toLowerCase();
const validEmail = e => e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const clientIp = req => String(req.headers["x-forwarded-for"] || req.ip || "unknown").split(",")[0].trim();
const dayKey = () => new Date().toISOString().slice(0, 10);
const monKey = () => dayKey().slice(0, 7);
const DUMMY_HASH = bcrypt.hashSync("not-a-real-password", 10);
async function getUser(email) {
  const s = await db.collection("users").doc(sha(email)).get();
  return s.exists ? { id: s.id, ...s.data() } : null;
}
/* Simple rate limiter stored in Firestore (works across all server instances). */
async function limit(key, max, windowMs) {
  const ref = db.collection("rl").doc(sha(key));
  const ok = await db.runTransaction(async t => {
    const s = await t.get(ref), now = Date.now(), d = s.exists ? s.data() : null;
    if (!d || d.reset < now) { t.set(ref, { n: 1, reset: now + windowMs, expireAt: new Date(now + windowMs + 3600e3) }); return true; }
    if (d.n >= max) return false;
    t.update(ref, { n: d.n + 1 });
    return true;
  });
  if (!ok) throw httpErr(429, "Too many attempts. Try again in a few minutes.");
}

/* ---------- email (Resend) ---------- */
async function sendMail(to, subject, html) {
  if (!env.RESEND_API_KEY) {
    if (!EMU) throw httpErr(503, "Email isn't set up yet.");
    console.log("[dev email] to=" + to + " " + html.replace(/<[^>]+>/g, " "));
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
  const ref = db.collection("otps").doc(sha(email)), s = await ref.get();
  if (s.exists && Date.now() - s.data().lastSent < 60e3) throw httpErr(429, "Please wait a minute before asking for another code.");
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  await ref.set({ codeHash: hmac(email + ":" + code), expiresAt: Date.now() + 10 * 60e3, attempts: 0, lastSent: Date.now(), expireAt: new Date(Date.now() + 3600e3) });
  await sendMail(email, "Your Views verification code",
    `<div style="font-family:system-ui,sans-serif"><p>Your verification code is:</p>
     <p style="font-size:32px;font-weight:800;letter-spacing:6px">${code}</p>
     <p>It expires in 10 minutes. If you didn't ask for it, you can ignore this email.</p></div>`);
}
async function checkOtp(email, code) {
  const ref = db.collection("otps").doc(sha(email));
  const result = await db.runTransaction(async t => {
    const s = await t.get(ref);
    if (!s.exists) return "expired";
    const d = s.data();
    if (d.expiresAt < Date.now()) return "expired";
    if (d.attempts >= 5) return "locked";
    if (/^\d{6}$/.test(code) && safeEq(d.codeHash, hmac(email + ":" + code))) { t.delete(ref); return "ok"; }
    t.update(ref, { attempts: d.attempts + 1 });
    return "bad";
  });
  if (result === "expired") throw httpErr(400, "That code has expired. Ask for a new one.");
  if (result === "locked") throw httpErr(429, "Too many wrong tries. Ask for a new code.");
  if (result === "bad") throw httpErr(400, "That code isn't right.");
}

/* ---------- sessions ---------- */
async function startSession(res, uid) {
  const token = crypto.randomBytes(32).toString("hex"), ttl = 30 * 86400e3;
  await db.collection("sessions").doc(sha(token)).set({ uid, expiresAt: Date.now() + ttl, expireAt: new Date(Date.now() + ttl) });
  res.cookie("__session", token, { httpOnly: true, sameSite: "lax", secure: !EMU, maxAge: ttl, path: "/" });
}
async function requireAuth(req, res, next) {
  try {
    const t = req.cookies && req.cookies.__session;
    if (!t) return res.status(401).json({ error: "Please log in." });
    const s = await db.collection("sessions").doc(sha(t)).get();
    if (!s.exists || s.data().expiresAt < Date.now()) return res.status(401).json({ error: "Please log in." });
    const u = await db.collection("users").doc(s.data().uid).get();
    if (!u.exists || !u.data().verified) return res.status(401).json({ error: "Please log in." });
    req.user = { id: u.id, ...u.data() };
    next();
  } catch (e) { next(e); }
}

/* ---------- app ---------- */
const app = express();
app.set("trust proxy", true);
app.disable("x-powered-by");
app.use((req, res, next) => { res.set({ "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" }); next(); });
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());
const authLimit = ah(async (req, res, next) => { await limit("auth:" + clientIp(req), 30, 15 * 60e3); next(); });

const stripe = env.STRIPE_SECRET_KEY ? new Stripe(env.STRIPE_SECRET_KEY) : null;
const PRICES = { plus: env.STRIPE_PRICE_PLUS, pro: env.STRIPE_PRICE_PRO };
const planFromPrice = id => Object.keys(PRICES).find(k => PRICES[k] && PRICES[k] === id) || null;

/* ---------- Stripe webhook ---------- */
app.post("/api/stripe/webhook", ah(async (req, res) => {
  if (!stripe || !env.STRIPE_WEBHOOK_SECRET) return res.sendStatus(503);
  let ev;
  try { ev = stripe.webhooks.constructEvent(req.rawBody, req.headers["stripe-signature"], env.STRIPE_WEBHOOK_SECRET); }
  catch (e) { return res.status(400).send("Bad signature"); }
  if (ev.type.startsWith("customer.subscription.")) {
    const sub = ev.data.object;
    const q = await db.collection("users").where("stripeCustomer", "==", String(sub.customer)).limit(1).get();
    if (!q.empty) {
      const ref = q.docs[0].ref, user = q.docs[0].data();
      if (user.stripeSub === sub.id) {
        if (["active", "trialing"].includes(sub.status)) {
          const p = planFromPrice(sub.items && sub.items.data[0] && sub.items.data[0].price.id);
          if (p) await ref.update({ plan: p });
        } else if (["canceled", "unpaid", "incomplete_expired"].includes(sub.status)) {
          await ref.update({ plan: "free", stripeSub: null });
        }
      }
    }
  }
  res.json({ received: true });
}));

/* ---------- accounts ---------- */
function readCreds(body) {
  const email = normEmail(body && body.email), password = String((body && body.password) || "");
  if (!validEmail(email)) throw httpErr(400, "Enter a valid email address.");
  return { email, password };
}
app.post("/api/signup", authLimit, ah(async (req, res) => {
  const { email, password } = readCreds(req.body);
  if (password.length < 8 || password.length > 128) throw httpErr(400, "Use a password of 8 to 128 characters.");
  const ref = db.collection("users").doc(sha(email)), ex = await ref.get();
  if (ex.exists && ex.data().verified) throw httpErr(409, "An account with this email already exists. Log in instead.");
  const hash = await bcrypt.hash(password, 11);
  if (ex.exists) await ref.update({ passHash: hash });
  else await ref.set({ email, passHash: hash, verified: false, plan: "free", stripeCustomer: null, stripeSub: null, createdAt: Date.now() });
  await issueOtp(email);
  res.json({ needsOtp: true });
}));
app.post("/api/verify-otp", authLimit, ah(async (req, res) => {
  const email = normEmail(req.body && req.body.email), code = String((req.body && req.body.code) || "").trim();
  const user = await getUser(email);
  if (!user) throw httpErr(400, "That code isn't right.");
  await checkOtp(email, code);
  await db.collection("users").doc(user.id).update({ verified: true });
  await startSession(res, user.id);
  res.json({ ok: true });
}));
app.post("/api/resend-otp", authLimit, ah(async (req, res) => {
  const email = normEmail(req.body && req.body.email), user = await getUser(email);
  if (user && !user.verified) await issueOtp(email);
  res.json({ ok: true });
}));
app.post("/api/login", authLimit, ah(async (req, res) => {
  const { email, password } = readCreds(req.body);
  await limit("login:" + email, 10, 15 * 60e3);
  const user = await getUser(email);
  const ok = await bcrypt.compare(password, user ? user.passHash : DUMMY_HASH);
  if (!user || !ok) throw httpErr(401, "Wrong email or password.");
  if (!user.verified) {
    await issueOtp(email).catch(() => {});
    throw httpErr(403, "Please confirm your email with the 6-digit code.", { needsOtp: true });
  }
  await startSession(res, user.id);
  res.json({ ok: true });
}));
app.post("/api/logout", ah(async (req, res) => {
  const t = req.cookies && req.cookies.__session;
  if (t) await db.collection("sessions").doc(sha(t)).delete().catch(() => {});
  res.clearCookie("__session", { path: "/" });
  res.json({ ok: true });
}));
app.get("/api/me", requireAuth, ah(async (req, res) => {
  const col = db.collection("usage");
  const [a, b] = await Promise.all([col.doc(req.user.id + "_d_" + dayKey()).get(), col.doc(req.user.id + "_m_" + monKey()).get()]);
  res.json({ email: req.user.email, plan: req.user.plan, usage: { today: a.exists ? a.data().n : 0, month: b.exists ? b.data().n : 0 }, limits: LIMITS });
}));

/* ---------- AI generation (Replicate) ---------- */
const bucket = () => admin.storage().bucket(env.STORAGE_BUCKET || undefined);
async function replicate(method, p, body) {
  const r = await fetch("https://api.replicate.com/v1" + p, {
    method, headers: { Authorization: "Bearer " + env.REPLICATE_API_TOKEN, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined
  });
  if (!r.ok) throw new Error("Replicate " + r.status + ": " + (await r.text()).slice(0, 300));
  return r.json();
}
function firstUrl(o) {
  if (typeof o === "string") return /^https?:\/\//.test(o) ? o : null;
  if (Array.isArray(o)) { for (const x of o) { const r = firstUrl(x); if (r) return r; } }
  else if (o && typeof o === "object") { for (const k of Object.keys(o)) { const r = firstUrl(o[k]); if (r) return r; } }
  return null;
}
async function reserve(uid, k, lim) {
  const d = dayKey(), m = monKey(), col = db.collection("usage");
  const rd = col.doc(uid + "_d_" + d), rm = col.doc(uid + "_m_" + m), rg = col.doc("global_d_" + d);
  await db.runTransaction(async t => {
    const [a, b, g] = await Promise.all([t.get(rd), t.get(rm), t.get(rg)]);
    const nd = a.exists ? a.data().n : 0, nm = b.exists ? b.data().n : 0, ng = g.exists ? g.data().n : 0;
    if (ng + k > GLOBAL_DAILY_CAP) throw httpErr(503, "We're at capacity today. Please try again tomorrow.");
    if (nd + k > lim.perDay) throw httpErr(429, "That would pass your daily limit of " + lim.perDay + ". Try fewer scenes, wait until tomorrow, or upgrade.");
    if (nm + k > lim.perMonth) throw httpErr(429, "That would pass your monthly limit of " + lim.perMonth + ".");
    const exp = new Date(Date.now() + 3 * 86400e3);
    t.set(rd, { n: nd + k, expireAt: exp }); t.set(rm, { n: nm + k }); t.set(rg, { n: ng + k, expireAt: exp });
  });
  return { d, m };
}
/* Marks a job failed AND gives the generation back to the user (once). */
async function failJob(id, msg) {
  const ref = db.collection("jobs").doc(id);
  return db.runTransaction(async t => {
    const s = await t.get(ref);
    if (!s.exists) return null;
    const j = s.data();
    if (j.status === "failed" || j.status === "done") return { id, ...j };
    const col = db.collection("usage");
    t.update(ref, { status: "failed", error: msg });
    t.set(col.doc(j.userId + "_d_" + j.usageDay), { n: FieldValue.increment(-1) }, { merge: true });
    t.set(col.doc(j.userId + "_m_" + j.usageMon), { n: FieldValue.increment(-1) }, { merge: true });
    t.set(col.doc("global_d_" + j.usageDay), { n: FieldValue.increment(-1) }, { merge: true });
    return { id, ...j, status: "failed", error: msg };
  });
}
async function startJob(id, model, input) {
  try {
    const p = await replicate("POST", "/models/" + model + "/predictions", { input });
    await db.collection("jobs").doc(id).update({ status: "running", providerId: p.id });
  } catch (e) {
    console.error("start job failed", id, e.message);
    await failJob(id, "The AI service couldn't start this one. You weren't charged a generation.");
  }
}
async function refreshJob(job) {
  if (Date.now() - job.createdAt > 20 * 60e3) return failJob(job.id, "This took too long. Please try again.");
  let p;
  try { p = await replicate("GET", "/predictions/" + job.providerId); }
  catch (e) { console.error("poll error", e.message); return job; }
  if (p.status === "succeeded") {
    try {
      const src = firstUrl(p.output);
      if (!src) return failJob(job.id, "The AI finished but sent no file. Please try again.");
      const r = await fetch(src);
      if (!r.ok) throw new Error("download " + r.status);
      const m = new URL(src).pathname.match(/\.(mp4|webm|mov|glb|gltf|obj|fbx|usdz)$/i);
      const ext = m ? m[1].toLowerCase() : (job.mode === "3d" ? "glb" : "mp4");
      const file = "media/" + job.id + "." + ext;
      await bucket().file(file).save(Buffer.from(await r.arrayBuffer()), { contentType: TYPES[ext], resumable: false });
      const upd = { status: "done", url: "/api/media/" + job.id + "." + ext, file };
      await db.collection("jobs").doc(job.id).update(upd);
      return { ...job, ...upd };
    } catch (e) {
      console.error("finalize failed", job.id, e.message);
      return failJob(job.id, "We couldn't save your result. Please try again.");
    }
  }
  if (p.status === "failed" || p.status === "canceled") {
    console.error("job failed", job.id, p.error);
    return failJob(job.id, "The AI couldn't make this one. Try rewording your idea. This didn't use up a generation.");
  }
  return job;
}
app.post("/api/generate", requireAuth, ah(async (req, res) => {
  await limit("gen:" + req.user.id, 20, 60e3);
  const { mode, prompts, style, ratio } = req.body || {};
  if (!["video", "3d", "film"].includes(mode)) throw httpErr(400, "Unknown mode.");
  if (!Array.isArray(prompts) || !prompts.length || prompts.length > 24) throw httpErr(400, "Send between 1 and 24 scenes.");
  const clean = prompts.map(p => String(p || "").trim().slice(0, 2000)).filter(p => p.length >= 3);
  if (!clean.length) throw httpErr(400, "Describe what you want to see.");
  const model = mode === "3d" ? env.MODEL_3D : env.MODEL_VIDEO;
  if (!model || !env.REPLICATE_API_TOKEN) throw httpErr(503, mode === "3d" ? "3D generation isn't switched on yet." : "Video generation isn't switched on yet.");
  const styleTxt = String(style || "").slice(0, 60), ratioTxt = /^\d{1,2}:\d{1,2}$/.test(String(ratio)) ? String(ratio) : "16:9";

  const keys = await reserve(req.user.id, clean.length, LIMITS[req.user.plan] || LIMITS.free);
  const jobs = clean.map(p => ({ id: crypto.randomUUID(), p }));
  const batch = db.batch();
  jobs.forEach(j => batch.set(db.collection("jobs").doc(j.id), {
    userId: req.user.id, mode, prompt: j.p, status: "queued", providerId: null, url: null, file: null, error: null,
    createdAt: Date.now(), usageDay: keys.d, usageMon: keys.m, expireAt: new Date(Date.now() + 30 * 86400e3)
  }));
  await batch.commit();
  await Promise.all(jobs.map(j => {
    const input = { prompt: styleTxt ? j.p + ". Style: " + styleTxt + "." : j.p };
    if (mode !== "3d") input.aspect_ratio = ratioTxt; /* input names differ per model: adjust to your MODEL_VIDEO */
    return startJob(j.id, model, input);
  }));
  res.json({ jobs: jobs.map(j => ({ id: j.id })) });
}));
app.get("/api/jobs/:id", requireAuth, ah(async (req, res) => {
  const s = await db.collection("jobs").doc(String(req.params.id)).get();
  if (!s.exists || s.data().userId !== req.user.id) throw httpErr(404, "Job not found.");
  let job = { id: s.id, ...s.data() };
  if (job.status === "running" && job.providerId) job = await refreshJob(job);
  if (job.status === "done") return res.json({ status: "done", url: job.url });
  if (job.status === "failed") return res.json({ status: "failed", error: job.error || "Generation failed." });
  res.json({ status: "running" });
}));
app.get("/api/media/:name", requireAuth, ah(async (req, res) => {
  const m = /^([0-9a-f-]{36})\.(mp4|webm|mov|glb|gltf|obj|fbx|usdz)$/i.exec(req.params.name);
  if (!m) throw httpErr(404, "Not found.");
  const s = await db.collection("jobs").doc(m[1]).get();
  const j = s.exists && s.data();
  if (!j || j.userId !== req.user.id || j.status !== "done" || !j.file || !j.file.endsWith("." + m[2].toLowerCase())) throw httpErr(404, "Not found.");
  res.set({ "Content-Type": TYPES[m[2].toLowerCase()], "Cache-Control": "private, max-age=3600" });
  bucket().file(j.file).createReadStream().on("error", () => res.destroy()).pipe(res);
}));

/* ---------- billing (Stripe, card payments) ---------- */
const needStripe = (req, res, next) => stripe ? next() : next(httpErr(503, "Payments aren't switched on yet."));
async function ensureCustomer(user) {
  if (user.stripeCustomer) return user.stripeCustomer;
  const c = await stripe.customers.create({ email: user.email, metadata: { user_id: user.id } });
  await db.collection("users").doc(user.id).update({ stripeCustomer: c.id });
  return c.id;
}
app.get("/api/billing", requireAuth, ah(async (req, res) => {
  if (!stripe || !req.user.stripeSub) return res.json({ card: null, cancelling: false, renews: null });
  const sub = await stripe.subscriptions.retrieve(req.user.stripeSub, { expand: ["default_payment_method"] });
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
  const customer = await ensureCustomer(user), users = db.collection("users").doc(user.id);
  if (user.stripeSub) {
    const old = await stripe.subscriptions.retrieve(user.stripeSub).catch(() => null);
    if (old && ["active", "trialing"].includes(old.status)) {
      await stripe.subscriptions.update(old.id, {
        items: [{ id: old.items.data[0].id, price: PRICES[plan] }],
        proration_behavior: "create_prorations", cancel_at_period_end: false
      });
      await users.update({ plan });
      return res.json({ updated: true });
    }
    if (old && old.status === "incomplete") await stripe.subscriptions.cancel(old.id).catch(() => {});
  }
  const sub = await stripe.subscriptions.create({
    customer, items: [{ price: PRICES[plan] }],
    payment_behavior: "default_incomplete",
    payment_settings: { save_default_payment_method: "on_subscription" },
    expand: ["latest_invoice.confirmation_secret"],
    metadata: { user_id: user.id, plan }
  });
  await users.update({ stripeSub: sub.id });
  const cs = sub.latest_invoice && sub.latest_invoice.confirmation_secret && sub.latest_invoice.confirmation_secret.client_secret;
  if (!cs) throw httpErr(500, "Couldn't start the payment. Please try again.");
  res.json({ clientSecret: cs, publishableKey: env.STRIPE_PUBLISHABLE_KEY });
}));
const setCancel = flag => ah(async (req, res) => {
  if (!req.user.stripeSub) throw httpErr(400, "You don't have a paid plan.");
  await stripe.subscriptions.update(req.user.stripeSub, { cancel_at_period_end: flag });
  res.json({ ok: true });
});
app.post("/api/billing/cancel", requireAuth, needStripe, setCancel(true));
app.post("/api/billing/resume", requireAuth, needStripe, setCancel(false));
app.post("/api/billing/portal", requireAuth, needStripe, ah(async (req, res) => {
  const customer = await ensureCustomer(req.user);
  const s = await stripe.billingPortal.sessions.create({ customer, return_url: APP_URL + "/" });
  res.json({ url: s.url });
}));

/* ---------- errors ---------- */
app.use((req, res) => res.status(404).json({ error: "Not found." }));
app.use((err, req, res, next) => {
  if (!err.status) console.error(err);
  res.status(err.status || 500).json(Object.assign({ error: err.status ? err.message : "Something went wrong. Please try again." }, err.extra || {}));
});

exports.api = onRequest({ region: "us-central1", memory: "512MiB", timeoutSeconds: 120, maxInstances: 10 }, app);
