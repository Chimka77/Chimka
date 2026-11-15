import os, re, time, json, hmac, hashlib, sqlite3, threading
from collections import defaultdict
import bcrypt, jwt, httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

load_dotenv()
E = os.environ
PROD = E.get("NODE_ENV", "production") == "production"
for k in ("JWT_SECRET", "RID_PEPPER", "ADMIN_TOKEN"):
    if not E.get(k) or E[k].startswith("change-me"):
        raise SystemExit(f"Set {k} in .env")

USD_PER_GS = float(E.get("USD_PER_GS", 1))
MIN_W = round(float(E.get("MIN_WITHDRAW", 5)) * 100)
MAX_DAY = round(float(E.get("MAX_WITHDRAW_PER_DAY", 500)) * 100)
NEED_EMAIL = E.get("REQUIRE_EMAIL_FOR_WITHDRAW", "true") != "false"

PAY_CODE = {
    "USDT|Tron (TRC20)": "usdttrc20", "USDT|TON": "usdtton", "USDT|BNB Chain (BEP20)": "usdtbsc",
    "USDT|Ethereum (ERC20)": "usdterc20", "USDT|Solana": "usdtsol", "BTC|Bitcoin": "btc",
    "ETH|Ethereum (ERC20)": "eth", "BNB|BNB Chain (BEP20)": "bnbbsc", "SOL|Solana": "sol",
    "TON|TON": "ton", "TRX|Tron (TRC20)": "trx",
}
B58 = "[1-9A-HJ-NP-Za-km-z]"
EVM = r"^0x[a-fA-F0-9]{40}$"
ADDR = {"Tron (TRC20)": rf"^T{B58}{{33}}$", "TON": r"^(EQ|UQ)[A-Za-z0-9_-]{46}$", "BNB Chain (BEP20)": EVM,
        "Ethereum (ERC20)": EVM, "Solana": rf"^{B58}{{32,44}}$",
        "Bitcoin": r"^(bc1[a-z0-9]{20,70}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$"}

# ---------------- database ----------------
os.makedirs(os.path.dirname(E.get("DB_FILE", "./data/hub.db")) or ".", exist_ok=True)
db = sqlite3.connect(E.get("DB_FILE", "./data/hub.db"), check_same_thread=False, isolation_level=None)
db.row_factory = sqlite3.Row
LOCK = threading.RLock()
db.executescript("""
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, pw_hash TEXT,
  rid_hash TEXT UNIQUE, balance INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, delta INTEGER NOT NULL,
  reason TEXT NOT NULL, ref TEXT UNIQUE, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS deposits(payment_id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, asset TEXT, network TEXT,
  pay_address TEXT, amount_usd REAL NOT NULL, status TEXT NOT NULL DEFAULT 'waiting', credited INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS withdrawals(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, asset TEXT NOT NULL,
  network TEXT NOT NULL, address TEXT NOT NULL, amount INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
  tx_hash TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
""")

class Insufficient(Exception): pass

def adjust(uid, delta, reason, ref=None):
    """Atomic balance change + ledger line. Returns False if this ref was already applied."""
    with LOCK:
        db.execute("BEGIN IMMEDIATE")
        try:
            if ref and db.execute("SELECT 1 FROM ledger WHERE ref=?", (ref,)).fetchone():
                db.execute("ROLLBACK"); return False
            u = db.execute("SELECT balance FROM users WHERE id=?", (uid,)).fetchone()
            if not u or u["balance"] + delta < 0:
                raise Insufficient()
            db.execute("UPDATE users SET balance=balance+? WHERE id=?", (delta, uid))
            db.execute("INSERT INTO ledger(user_id,delta,reason,ref) VALUES(?,?,?,?)", (uid, delta, reason, ref))
            db.execute("COMMIT"); return True
        except Exception:
            db.execute("ROLLBACK"); raise

# ---------------- app ----------------
app = FastAPI(docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in E.get("ALLOWED_ORIGINS", "").split(",") if o.strip()],
                   allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

@app.exception_handler(HTTPException)
async def http_err(_, e): return JSONResponse({"error": e.detail}, status_code=e.status_code)
@app.exception_handler(RequestValidationError)
async def bad_req(_, e): return JSONResponse({"error": "Bad request."}, status_code=400)
@app.exception_handler(Exception)
async def boom(_, e):
    print("ERROR", repr(e)); return JSONResponse({"error": "Server error. Try again."}, status_code=500)

HITS = defaultdict(list)
def limit(req: Request, name: str, n=20, secs=900):
    ip = (req.headers.get("x-forwarded-for") or (req.client.host if req.client else "x")).split(",")[0].strip()
    now = time.time(); k = (name, ip)
    HITS[k] = [t for t in HITS[k] if now - t < secs]
    if len(HITS[k]) >= n: raise HTTPException(429, "Too many tries. Wait a few minutes.")
    HITS[k].append(now)

def rid_hash(rid): return hashlib.sha256((E["RID_PEPPER"] + rid).encode()).hexdigest()
def ok_rid(r): return isinstance(r, str) and re.fullmatch(r"[a-f0-9]{32}", r) is not None
def ok_email(e): return isinstance(e, str) and len(e) < 255 and re.fullmatch(r"\S+@\S+\.\S+", e) is not None

def set_session(res: Response, uid):
    tok = jwt.encode({"uid": uid, "exp": int(time.time()) + 30 * 86400}, E["JWT_SECRET"], algorithm="HS256")
    res.set_cookie("sid", tok, httponly=True, secure=PROD, samesite=(E.get("COOKIE_SAMESITE", "none") if PROD else "lax"), max_age=30 * 86400)

def me(req: Request):
    try:
        uid = jwt.decode(req.cookies.get("sid", ""), E["JWT_SECRET"], algorithms=["HS256"])["uid"]
        with LOCK: return db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    except Exception:
        return None

def need(req: Request):
    u = me(req)
    if not u: raise HTTPException(401, "Please log in again.")
    return u

# ---------------- auth ----------------
@app.post("/auth/phrase")
def phrase(req: Request, res: Response, body: dict):
    limit(req, "auth"); rid = body.get("rid")
    if not ok_rid(rid): raise HTTPException(400, "Bad request.")
    h, cur = rid_hash(rid), me(req)
    with LOCK:
        owner = db.execute("SELECT id FROM users WHERE rid_hash=?", (h,)).fetchone()
        if cur:
            if owner and owner["id"] != cur["id"]: raise HTTPException(409, "This phrase belongs to another account.")
            db.execute("UPDATE users SET rid_hash=? WHERE id=?", (h, cur["id"])); uid = cur["id"]
        else:
            uid = owner["id"] if owner else db.execute("INSERT INTO users(rid_hash) VALUES(?)", (h,)).lastrowid
    set_session(res, uid); return {"ok": True}

@app.post("/auth/restore")
def restore(req: Request, res: Response, body: dict):
    limit(req, "auth"); rid = body.get("rid")
    if not ok_rid(rid): raise HTTPException(400, "Bad request.")
    with LOCK: u = db.execute("SELECT id FROM users WHERE rid_hash=?", (rid_hash(rid),)).fetchone()
    if not u: raise HTTPException(404, "No account found for this phrase.")
    set_session(res, u["id"]); return {"ok": True}

@app.post("/auth/signup")
def signup(req: Request, res: Response, body: dict):
    limit(req, "auth"); email, pw = body.get("email"), body.get("password")
    if not ok_email(email): raise HTTPException(400, "Enter a valid email.")
    if not isinstance(pw, str) or not 8 <= len(pw) <= 72: raise HTTPException(400, "Password needs 8 to 72 characters.")
    e = email.strip().lower(); cur = me(req)
    hashed = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(12)).decode()
    with LOCK:
        if db.execute("SELECT 1 FROM users WHERE email=?", (e,)).fetchone(): raise HTTPException(409, "That email is already used. Try Log in.")
        if cur:
            if cur["email"]: raise HTTPException(409, "This account already has an email.")
            db.execute("UPDATE users SET email=?,pw_hash=? WHERE id=?", (e, hashed, cur["id"])); uid = cur["id"]
        else:
            uid = db.execute("INSERT INTO users(email,pw_hash) VALUES(?,?)", (e, hashed)).lastrowid
    set_session(res, uid); return {"ok": True}

DUMMY = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt(12))
@app.post("/auth/login")
def login(req: Request, res: Response, body: dict):
    limit(req, "auth"); email, pw = body.get("email"), str(body.get("password") or "")[:72]
    u = None
    if ok_email(email):
        with LOCK: u = db.execute("SELECT * FROM users WHERE email=?", (email.strip().lower(),)).fetchone()
    good = bcrypt.checkpw(pw.encode(), u["pw_hash"].encode() if u else DUMMY)
    if not u or not good: raise HTTPException(401, "Wrong email or password.")
    set_session(res, u["id"]); return {"ok": True}

@app.post("/auth/logout")
def logout(res: Response): res.delete_cookie("sid"); return {"ok": True}

@app.get("/me")
def whoami(req: Request):
    u = need(req); return {"email": u["email"], "hasPhrase": bool(u["rid_hash"]), "balance": u["balance"] / 100}

# ---------------- deposits (address from the gateway, no private keys here) ----------------
@app.post("/deposit/create")
def deposit(req: Request, body: dict):
    u = need(req); asset, network = body.get("asset"), body.get("network")
    try: usd = min(max(float(body.get("amount") or 10), 1), 10000)
    except (TypeError, ValueError): usd = 10
    code = PAY_CODE.get(f"{asset}|{network}")
    if not code: raise HTTPException(400, "That coin or network is not supported.")
    if not E.get("NOWPAYMENTS_API_KEY"): raise HTTPException(503, "Deposits are not set up yet.")
    r = httpx.post("https://api.nowpayments.io/v1/payment", timeout=20,
                   headers={"x-api-key": E["NOWPAYMENTS_API_KEY"]},
                   json={"price_amount": usd, "price_currency": "usd", "pay_currency": code,
                         "order_id": f"u{u['id']}-{int(time.time())}",
                         "ipn_callback_url": f"{E.get('PUBLIC_URL', '')}/webhooks/nowpayments"})
    p = r.json() if r.content else {}
    if r.status_code >= 400: raise HTTPException(502, p.get("message", "Payment provider error"))
    with LOCK:
        db.execute("INSERT INTO deposits(payment_id,user_id,asset,network,pay_address,amount_usd) VALUES(?,?,?,?,?,?)",
                   (str(p["payment_id"]), u["id"], asset, network, p["pay_address"], usd))
    return {"address": p["pay_address"], "memo": p.get("payin_extra_id"), "payAmount": p.get("pay_amount"), "paymentId": p["payment_id"]}

def sort_keys(o):
    if isinstance(o, dict): return {k: sort_keys(o[k]) for k in sorted(o)}
    if isinstance(o, list): return [sort_keys(x) for x in o]
    return o

@app.post("/webhooks/nowpayments")
def webhook(req: Request, body: dict):
    secret, sig = E.get("NOWPAYMENTS_IPN_SECRET", ""), req.headers.get("x-nowpayments-sig", "")
    mine = hmac.new(secret.encode(), json.dumps(sort_keys(body), separators=(",", ":"), ensure_ascii=False).encode(), hashlib.sha512).hexdigest()
    if not secret or not hmac.compare_digest(mine, sig): raise HTTPException(401, "bad signature")
    pid, status = str(body.get("payment_id")), str(body.get("payment_status"))
    with LOCK:
        d = db.execute("SELECT * FROM deposits WHERE payment_id=?", (pid,)).fetchone()
        if not d: return {"ok": True}
        db.execute("UPDATE deposits SET status=? WHERE payment_id=?", (status, pid))
    if status == "finished" and not d["credited"]:   # partial or late payments are NOT credited; check them by hand
        if adjust(d["user_id"], round(d["amount_usd"] / USD_PER_GS * 100), "deposit", f"dep:{pid}"):
            with LOCK: db.execute("UPDATE deposits SET credited=1 WHERE payment_id=?", (pid,))
    return {"ok": True}

# ---------------- withdrawals (queued for your approval) ----------------
@app.post("/withdraw/request")
def withdraw(req: Request, body: dict):
    u = need(req); limit(req, "wd")
    asset, network, address = body.get("asset"), body.get("network"), body.get("address")
    try: amount = round(float(body.get("amount")) * 100)
    except (TypeError, ValueError): raise HTTPException(400, f"Minimum withdrawal is {MIN_W / 100} G$.")
    if f"{asset}|{network}" not in PAY_CODE: raise HTTPException(400, "That coin or network is not supported.")
    if not isinstance(address, str) or not re.fullmatch(ADDR[network], address.strip()): raise HTTPException(400, "That address looks wrong for this network.")
    if amount < MIN_W: raise HTTPException(400, f"Minimum withdrawal is {MIN_W / 100} G$.")
    if NEED_EMAIL and not u["email"]: raise HTTPException(403, "Save your email and password in Settings first.")
    with LOCK:
        today = db.execute("SELECT COALESCE(SUM(amount),0) s FROM withdrawals WHERE user_id=? AND status!='rejected' AND created_at>datetime('now','-1 day')", (u["id"],)).fetchone()["s"]
    if today + amount > MAX_DAY: raise HTTPException(429, f"Daily limit is {MAX_DAY / 100} G$.")
    try: adjust(u["id"], -amount, "withdraw")
    except Insufficient: raise HTTPException(400, "Not enough balance.")
    with LOCK:
        db.execute("INSERT INTO withdrawals(user_id,asset,network,address,amount) VALUES(?,?,?,?,?)", (u["id"], asset, network, address.strip(), amount))
    return {"ok": True, "message": "Request received. It will be reviewed before sending."}

# ---------------- admin (send header x-admin-token) ----------------
def admin(req: Request):
    if not hmac.compare_digest(req.headers.get("x-admin-token", ""), E["ADMIN_TOKEN"]): raise HTTPException(401, "no")

@app.get("/admin/withdrawals")
def adm_list(req: Request, status: str = "pending"):
    admin(req)
    with LOCK: return [dict(r) for r in db.execute("SELECT * FROM withdrawals WHERE status=? ORDER BY id", (status,))]

@app.post("/admin/withdrawals/{wid}/approve")
def adm_ok(wid: int, req: Request, body: dict):
    admin(req)
    with LOCK:
        c = db.execute("UPDATE withdrawals SET status='approved',tx_hash=? WHERE id=? AND status='pending'", (str(body.get("txHash", "")), wid))
    return {"ok": c.rowcount == 1}

@app.post("/admin/withdrawals/{wid}/reject")
def adm_no(wid: int, req: Request):
    admin(req)
    with LOCK:
        w = db.execute("SELECT * FROM withdrawals WHERE id=? AND status='pending'", (wid,)).fetchone()
        if not w: return {"ok": False}
        db.execute("UPDATE withdrawals SET status='rejected' WHERE id=?", (wid,))
    adjust(w["user_id"], w["amount"], "withdraw-refund", f"wr:{wid}")   # refund
    return {"ok": True}

@app.get("/health")
def health(): return {"ok": True}
