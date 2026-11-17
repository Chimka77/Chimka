require("dotenv").config();
const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET;
const TOKEN = process.env.REPLICATE_API_TOKEN;
const PROD = process.env.NODE_ENV === "production";
if (!SECRET || !TOKEN) {
  console.error("Missing JWT_SECRET or REPLICATE_API_TOKEN. Copy .env.example to .env and fill them in.");
  process.exit(1);
}

/* ---- Plan limits. Every video costs you money, so set these from your real cost per video. ---- */
const LIMITS = {
  free: { perDay: 1, perMonth: 3, maxScenes: 2 },
  plus: { perDay: 2, perMonth: 12, maxScenes: 6 },
  pro: { perDay: 10, perMonth: 60, maxScenes: 12 },
};
const BLOCKED = ["porn", "nude", "naked", "sex scene", "gore", "beheading", "child abuse"]; // starter list only
const DAY = 864e5;
const now = () => Date.now();
const json = (s) => { try { return JSON.parse(s || "{}"); } catch (e) { return {}; } };

/* ---- storage ---- */
const DATA = process.env.DATA_DIR || path.join(__dirname, "data");
const MEDIA = path.join(DATA, "media");
fs.mkdirSync(MEDIA, { recursive: true });
const db = new Database(path.join(DATA, "views.db"));
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, hash TEXT, plan TEXT DEFAULT 'free', created INTEGER);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, user_id INTEGER, mode TEXT, prompt TEXT, pred TEXT, status TEXT, file TEXT, error TEXT, created INTEGER);
CREATE INDEX IF NOT EXISTS jobs_user ON jobs(user_id, created);
`);

function usage(uid) {
  const count = (since) => db.prepare("SELECT COUNT(*) n FROM jobs WHERE user_id=? AND created>=? AND status!='failed'").get(uid, since).n;
  const d = new Date(); d.setUTCHours(0, 0, 0, 0);
  return { today: count(d.getTime()), month: count(now() - 30 * DAY) };
}

/* ---- AI provider (Replicate). To use another provider, change only these functions. ---- */
function pickModel(mode, plan) {
  if (mode === "3d") return plan === "free" ? null : process.env.MODEL_3D || null;
  if (plan === "free") return process.env.MODEL_VIDEO_FREE || process.env.MODEL_VIDEO || null;
  return process.env.MODEL_VIDEO || null;
}
function extraInput(mode) { return json(mode === "3d" ? process.env.MODEL_3D_INPUT : process.env.MODEL_VIDEO_INPUT); }
async function replicate(model, input) {
  const r = await fetch("https://api.replicate.com/v1/predictions", {
    method: "POST",
    headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify({ version: model, input }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.detail || "AI service error " + r.status);
  return j;
}
async function getPrediction(id) {
  const r = await fetch("https://api.replicate.com/v1/predictions/" + id, { headers: { Authorization: "Bearer " + TOKEN } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.detail || "AI service error " + r.status);
  return j;
}
async function saveResult(url, id) {
  if (typeof url !== "string") throw new Error("No file in result");
  const r = await fetch(url);
  if (!r.ok) throw new Error("Download failed");
  const m = new URL(url).pathname.match(/\.(\w+)$/);
  const ext = m && ["mp4", "webm", "mov", "glb", "gltf", "obj", "fbx", "usdz"].includes(m[1].toLowerCase()) ? m[1].toLowerCase() : "mp4";
  const file = id + "." + ext;
  fs.writeFileSync(path.join(MEDIA, file), Buffer.from(await r.arrayBuffer()));
  return file;
}

/* ---- app ---- */
const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "20kb" }));
app.use(cookieParser());
app.use("/api/", rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false }));
const authLimit = rateLimit({ windowMs: 60 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false, message: { error: "Too many attempts. Try again later." } });
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });

function sign(res, id) {
  const t = jwt.sign({ id }, SECRET, { expiresIn: "30d" });
  res.cookie("token", t, { httpOnly: true, sameSite: "lax", secure: PROD, maxAge: 30 * DAY });
}
function auth(req, res, next) {
  try {
    const p = jwt.verify(req.cookies.token, SECRET);
    const u = db.prepare("SELECT * FROM users WHERE id=?").get(p.id);
    if (!u) throw new Error("no user");
    req.user = u; next();
  } catch (e) { bad(res, "Please log in.", 401); }
}

app.post("/api/signup", authLimit, (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase(), pw = String(req.body.password || "");
  if (!/^\S+@\S+\.\S+$/.test(email)) return bad(res, "Enter a valid email.");
  if (pw.length < 8) return bad(res, "Password must be at least 8 characters.");
  if (db.prepare("SELECT 1 FROM users WHERE email=?").get(email)) return bad(res, "That email already has an account.", 409);
  const r = db.prepare("INSERT INTO users(email,hash,plan,created) VALUES(?,?,?,?)").run(email, bcrypt.hashSync(pw, 10), "free", now());
  sign(res, Number(r.lastInsertRowid)); res.json({ ok: true });
});
app.post("/api/login", authLimit, (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase(), pw = String(req.body.password || "");
  const u = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!u || !bcrypt.compareSync(pw, u.hash)) return bad(res, "Wrong email or password.", 401);
  sign(res, u.id); res.json({ ok: true });
});
app.post("/api/logout", (req, res) => { res.clearCookie("token"); res.json({ ok: true }); });
app.get("/api/me", auth, (req, res) => res.json({ email: req.user.email, plan: req.user.plan, usage: usage(req.user.id), limits: LIMITS }));

app.post("/api/generate", auth, ah(async (req, res) => {
  const u = req.user, L = LIMITS[u.plan] || LIMITS.free, mode = req.body.mode;
  if (!["video", "3d", "film"].includes(mode)) return bad(res, "Unknown mode.");
  let prompts = req.body.prompts;
  if (!Array.isArray(prompts) || !prompts.length) return bad(res, "Write a prompt first.");
  prompts = prompts.map((p) => String(p).trim());
  if (prompts.some((p) => p.length < 10 || p.length > 600)) return bad(res, "Each prompt must be 10 to 600 characters.");
  if (prompts.length > L.maxScenes) return bad(res, "Your plan allows up to " + L.maxScenes + " scenes at once.", 403);
  if (prompts.some((p) => BLOCKED.some((w) => p.toLowerCase().includes(w)))) return bad(res, "That prompt isn’t allowed.");
  const model = pickModel(mode, u.plan);
  if (!model) return bad(res, mode === "3d" ? "Text to 3D is for Plus and Pro, and needs MODEL_3D set on the server." : "No video model is set on the server.", mode === "3d" && u.plan === "free" ? 403 : 501);
  const us = usage(u.id);
  if (us.today + prompts.length > L.perDay) return bad(res, "That would pass your daily limit of " + L.perDay + ". It resets at midnight UTC.", 429);
  if (us.month + prompts.length > L.perMonth) return bad(res, "That would pass your monthly limit of " + L.perMonth + ".", 429);

  const style = String(req.body.style || "").replace(/[^\w\s-]/g, "").slice(0, 30).trim();
  const jobs = []; let failure = null;
  for (const p of prompts) {
    const id = crypto.randomBytes(16).toString("hex");
    db.prepare("INSERT INTO jobs(id,user_id,mode,prompt,status,created) VALUES(?,?,?,?,?,?)").run(id, u.id, mode, p, "processing", now());
    try {
      const input = Object.assign({ prompt: (style ? style + " style. " : "") + p }, extraInput(mode));
      const pr = await replicate(model, input);
      db.prepare("UPDATE jobs SET pred=? WHERE id=?").run(pr.id, id);
      jobs.push({ id });
    } catch (e) {
      console.error("generate failed:", e.message);
      db.prepare("UPDATE jobs SET status='failed', error=? WHERE id=?").run(e.message.slice(0, 200), id);
      failure = e; break;
    }
  }
  if (!jobs.length) return bad(res, "The AI service couldn’t start your video. Nothing was counted. Try again.", 502);
  res.json({ jobs });
}));

const saving = new Set();
app.get("/api/jobs/:id", auth, ah(async (req, res) => {
  const j = db.prepare("SELECT * FROM jobs WHERE id=? AND user_id=?").get(req.params.id, req.user.id);
  if (!j) return bad(res, "Not found.", 404);
  if (j.status === "done") return res.json({ status: "done", url: "/media/" + j.file });
  if (j.status === "failed") return res.json({ status: "failed", error: "The AI couldn’t make that video. It wasn’t counted against your limit." });
  const pr = await getPrediction(j.pred);
  if (pr.status === "succeeded") {
    if (saving.has(j.id)) return res.json({ status: "processing" });
    saving.add(j.id);
    try {
      const file = await saveResult(Array.isArray(pr.output) ? pr.output[0] : pr.output, j.id);
      db.prepare("UPDATE jobs SET status='done', file=? WHERE id=?").run(file, j.id);
      return res.json({ status: "done", url: "/media/" + file });
    } catch (e) {
      console.error("save failed:", e.message);
      db.prepare("UPDATE jobs SET status='failed', error=? WHERE id=?").run("save failed", j.id);
      return res.json({ status: "failed", error: "Couldn’t save the result. It wasn’t counted against your limit." });
    } finally { saving.delete(j.id); }
  }
  if (pr.status === "failed" || pr.status === "canceled") {
    db.prepare("UPDATE jobs SET status='failed', error=? WHERE id=?").run(String(pr.error || "failed").slice(0, 200), j.id);
    return res.json({ status: "failed", error: "The AI couldn’t make that video. It wasn’t counted against your limit." });
  }
  res.json({ status: "processing" });
}));

/* Testing only: lets you switch your own plan until Stripe is connected. Disabled in production. */
if (!PROD) {
  app.post("/api/dev/plan", auth, (req, res) => {
    const p = String(req.body.plan);
    if (!LIMITS[p]) return bad(res, "Unknown plan.");
    db.prepare("UPDATE users SET plan=? WHERE id=?").run(p, req.user.id); res.json({ ok: true, plan: p });
  });
}

app.use("/media", express.static(MEDIA, { maxAge: "1h" }));
app.use(express.static(path.join(__dirname, "public")));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: "Server error. Try again." }); });
app.listen(PORT, () => console.log("Views is running on http://localhost:" + PORT));
