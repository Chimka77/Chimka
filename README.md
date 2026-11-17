# Views backend

One Node server that serves your page (`public/index.html`) and the API it calls.

## What it does
- **Accounts:** sign up with email + password, a 6-digit code is emailed (Resend), the account only works after the code is entered. Login, logout, sessions (httpOnly cookie), rate limits.
- **AI generation:** `/api/generate` checks the plan limits, starts the job on Replicate, `/api/jobs/:id` reports progress and saves the finished file on your server. Failed jobs don't count against the user's limit.
- **Card payments:** Stripe subscriptions for Plus and Pro, plan upgrades, cancel/resume, update card (Stripe's portal).
- **Editing:** the CapCut-style editor lives in the page itself (runs in the user's browser), so the server doesn't need to do anything for it.

## Run it locally
1. Install Node 20 or newer.
2. `npm install`
3. `cp .env.example .env`, fill it in, then: `node --env-file=.env server.js`
4. Open http://localhost:3000. With no email key set (and NODE_ENV not production) the OTP code prints in the terminal.

## Set up the services
**Email (Resend):** create an account, verify your domain, create an API key, set `RESEND_API_KEY` and `MAIL_FROM`.

**AI (Replicate):** create a token, set `REPLICATE_API_TOKEN`. Pick a text-to-video model and set `MODEL_VIDEO=owner/name`. Open that model's API tab and check its input names: the server sends `prompt` and `aspect_ratio`; change them in `/api/generate` if your model differs. Set `MODEL_3D` the same way, or leave blank to disable 3D. Watch `GLOBAL_DAILY_CAP`, it protects your wallet.

**Stripe (test mode first):**
1. Create two monthly products, Plus $10 and Pro $50. Put their price IDs in `STRIPE_PRICE_PLUS` and `STRIPE_PRICE_PRO`.
2. Set `STRIPE_SECRET_KEY` and `STRIPE_PUBLISHABLE_KEY`.
3. Add a webhook to `https://yourdomain.com/api/stripe/webhook` for `customer.subscription.created`, `.updated` and `.deleted`. Put its signing secret in `STRIPE_WEBHOOK_SECRET`. **Without this, paying users stay on Free.**
4. Turn on the Customer Portal in the Stripe dashboard (Settings > Billing > Customer portal).
5. Test with card 4242 4242 4242 4242 before going live.

## Deploy
Use a host with a persistent disk (Render, Railway, Fly.io, a VPS). Set `DATA_DIR` to the disk path, `NODE_ENV=production`, `APP_URL` to your https address, and all the keys above. Start command: `npm start`.

## Not included yet
Forgot-password email, server-side watermarking/export, and moving generated videos to S3-style storage for big scale.
