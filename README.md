Buggy Rush — Backend

Server-side economy for the Buggy Rush frontend (`Buggy_Rush.html`): G ledger,
TON deposits & withdrawals, room entry fees, prize settlement, and the shop.
Everything money-related is decided here — the client only reports events.

Stack
Node.js 18+ · Express · better-sqlite3 (embedded DB, zero setup) · tonweb (TON)

Setup

```bash
git clone <your-repo> && cd buggy-rush-backend
npm install
cp .env.example .env        # fill in the TON section
npm start                   # http://localhost:3000
```

1. Treasury wallet (one-time)

```bash
npm run deploy-treasury         # prints your treasury address — send it 1+ TON
npm run deploy-treasury -- --deploy
# copy the printed address into TREASURY_ADDRESS in .env
```

2. Owner fee wallet
Set `OWNER_ADDRESS` to any wallet. Every settled race credits it the 1% fee
in the ledger (`kind=fee_owner`); pay yourself out periodically from the treasury.

3. Host it somewhere with HTTPS (Railway, Render, Fly, a VPS + Caddy)
TON Connect proofs sign the Host the wallet talked to, so set
`APP_DOMAIN=api.yourdomain.com` to the exact public host and add the frontend
origin to `ALLOWED_ORIGIN`.

API

Method	Route	What it does	
GET	`/api/health`	ping	
POST	`/api/auth/challenge`	one-time `tonProof` payload	
POST	`/api/auth/verify`	verifies the wallet signature, returns `{token, balance}`	
GET	`/api/me`	balance + upgrades/engine state	
GET	`/api/txlog`	last 12 ledger entries (frontend `E.tx` shape)	
POST	`/api/wallet/deposit`	scans treasury txs on chain, credits USD value of payments whose comment = session token	
POST	`/api/wallet/withdraw`	`{cents}` → pays TON from treasury, auto-refund on failure	
POST	`/api/room/create`	`{code, track, fee, fair, maxPlayers}` — host pays entry	
POST	`/api/room/join`	`{code}` — charges the room fee	
POST	`/api/room/leave`	refunds if the race hasn't started/settled	
POST	`/api/race/settle`	host-only, once; `{code, results:[{address, d, fin}]}`	
POST	`/api/shop/buy`	`{item}` — `engine:1..4`, `paint:n`, `service`, `upgrade:speed	

Auth: `Authorization: Bearer <token>` from `/api/auth/verify`.

Wiring the frontend

a) Config + fetch helper (top of the `<script>`)

```js
const API_URL = 'https://api.yourdomain.com';
let brToken = localStorage.getItem('br_token') || '';
async function api(path, body) {
  const r = await fetch(API_URL + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(brToken ? { Authorization: 'Bearer ' + brToken } : {}) },
    body: JSON.stringify(body || {}),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || 'Server error');
  return j;
}
```

b) Replace the local `API` object

```js
const API = {
  async deposit()   { const j = await api('/api/wallet/deposit');   E.bal = j.balance; logTx('dep', j.credited); return true; },
  async withdraw(c) { const j = await api('/api/wallet/withdraw', { cents: c }); E.bal = j.balance; return true; },
  async charge()    { return true; },  // real charging happens inside /api/room/join & /api/shop/buy
  async credit()    { return true; },  // real credits come from /api/wallet/deposit & /api/race/settle
};
```

c) Auth in `initTon()` — request the proof before connecting:

```js
const { payload } = await (await fetch(API_URL + '/api/auth/challenge')).json();
tc.setConnectRequestParameters({ forceRetry: true, value: { tonProof: payload } });
```

and in `onStatusChange`:

```js
if (w && w.account) {
  E.addr = w.account.address;
  const proof = w.connectItems && w.connectItems.tonProof;
  if (proof && proof.proof) {
    const j = await api('/api/auth/verify', { address: w.account.address, proof: proof.proof });
    brToken = j.token;
    localStorage.setItem('br_token', brToken);
    E.bal = j.balance;   // server balance wins
  }
  ld(); E.demo = false; sv(); topbar(); if (ST === 'menu') home();
}
```

Replace `E.demo=true` paths so a missing backend still allows bot races (no wallet, no G).

d) Deposit — attach the session token as the TON comment
Add `@ton/core` to the page and build the comment payload (wallet transfer body):

```js
import { beginCell } from '@ton/core';
// inside dep(): add to the message:
payload: beginCell().storeUint(0, 32).storeStringTail(brToken).endCell().toBoc().toString('base64')
```

Then call `API.deposit()` as before — the server finds the tx by that comment.

e) Rooms
- `host(pr)`: after generating `code`, replace `API.charge(ROOM.fee,'entry')` with
  `await api('/api/room/create', { code, track: tk, fee: RS.fee, fair: RS.fair, maxPlayers: size })`.
- In `join()`: when the client is admitted to the lobby, call `await api('/api/room/join', { code: cd0 })`
  instead of `payJoin()` charging locally. Have each client send its wallet address too
  (add `addr: E.addr` to the `{t:'hi',...}` message and keep it on the lobby entry) —
  the host needs it for settlement.
- `leaveRoom()`: replace the local refund with `await api('/api/room/leave', { code })`.
- `settle()`: host posts the results:
  
```js
  await api('/api/race/settle', {
    code,
    results: rank().filter(r => !r.bot).map(r => ({ address: r.addr, d: r.d, fin: r.fin }))
  });
  ```

  The server pays winners — never trust client-computed prizes.

f) Shop
Route `mEng`, `mPaint`, `mSvc`, `up()` through `await api('/api/shop/buy', { item: 'engine:'+i })` etc.,
then apply the returned `{balance, upgrades, eg, wear, rc}` to `E`.

Honest security notes
- Race results are host-reported. Payouts are recomputed server-side, but the
  results themselves are trusted. Real anti-cheat needs either server-simulated
  physics or a commitment scheme — fine for a friendly game, not for high stakes.
- Deposits are credited at the server's current TON price; users see the rate
  quoted before they confirm.
- Keep `buggyrush.db` and `.env` out of git (both are in `.gitignore` below).
- `INSECURE_DEV_AUTH=1` skips signature checks for local testing only.

`.gitignore`

```
node_modules/
.env
*.db
*.db-wal
*.db-shm
```
