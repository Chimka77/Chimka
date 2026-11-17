# Views – backend

Files: `server.js` (API), `public/index.html` (the app), `package.json`, `.env.example`.

## Run it
1. Install Node 18 or newer.
2. In this folder run `npm install`.
3. Copy `.env.example` to `.env` and fill in `REPLICATE_API_TOKEN` and `JWT_SECRET`.
4. Run `npm start` and open http://localhost:3000.
5. Sign up in the app, then press Generate.

## Test paid plans before Stripe exists
Log in, open the browser console, and run:
`fetch('/api/dev/plan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({plan:'plus'})})`
This route is switched off when `NODE_ENV=production`.

## Stripe setup (payments)
1. Create a Stripe account and stay in test mode.
2. Product catalog: create a product with a monthly price of $10 (Plus) and another of $50 (Pro). Copy each price ID into `.env`.
3. Developers > API keys: copy the secret and publishable keys into `.env`.
4. Webhook: in production add an endpoint `https://YOUR-DOMAIN/api/stripe/webhook` with the events `customer.subscription.created`, `customer.subscription.updated` and `customer.subscription.deleted`, then copy its signing secret into `STRIPE_WEBHOOK_SECRET`. For local testing install the Stripe CLI and run `stripe listen --forward-to localhost:3000/api/stripe/webhook`, which prints a signing secret to use.
5. Settings > Billing > Customer portal: turn it on and save, otherwise "Update or remove card" will fail.
6. Test with card 4242 4242 4242 4242, any future expiry and any CVC.
7. Only switch to live keys after you have tested upgrading, cancelling, resuming and a failed card.

The plan prices shown in the app ($10 and $50) must match the prices you create in Stripe.

## Costs (read this)
Each video costs you money, and the cost depends on the model. Check the price on the model page, then set `LIMITS` at the top of `server.js` so that a user on each plan can never cost more than they pay. The defaults are conservative on purpose.

## Going live
- Use a host that keeps files on disk between restarts (the `data` folder holds the database and the videos), or point `DATA_DIR` at a persistent disk.
- Serve over HTTPS and set `NODE_ENV=production`.
- Keep `.env` private. Never put the Replicate token in `index.html`.
- Next steps: connect Stripe so the server sets `users.plan`, replace the starter prompt blocklist with real moderation, and delete old videos on a schedule.
