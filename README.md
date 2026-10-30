# Portfolio demo: Vercel + Cloudflare + Firestore

```
Browser ──► Cloudflare Worker (your public URL)
              ├─ /api/messages      validate + rate-limit ──► Firestore (service account)
              ├─ /admin, /api/admin cookie check ──► admin.html served FROM the Worker
              └─ everything else    proxied ──► Vercel (public index.html only)
```

**Why this fixes the redirect problem:** `admin.html` is never deployed to Vercel. It lives inside the Worker
and is only returned after the signed cookie checks out, so unauthorised visitors get a 302 and never receive the page.
Firestore rules deny all client access, so the only path to your data is through the Worker.

## Setup

**1. Firebase**: create a project, enable Firestore, paste `firebase/firestore.rules` into Rules and publish.
Project settings > Service accounts > Generate new private key (keep the JSON private).

**2. Vercel**: deploy the `web/` folder (`cd web && npx vercel --prod`). Put the URL in `ORIGIN_URL` in `edge/wrangler.toml`.

**3. Cloudflare**:
```bash
cd edge
npx wrangler secret put ADMIN_PASSWORD
npx wrangler secret put SESSION_SECRET            # any long random string
npx wrangler secret put FIREBASE_SERVICE_ACCOUNT < /path/to/serviceAccount.json
npx wrangler deploy
```
Open the `*.workers.dev` URL. That is your public site (a custom domain routed to the Worker works too).
Send a message, then visit `/admin`.

## Local dev
```bash
npx serve web -l 3000                       # terminal 1
cd edge && cp .dev.vars.example .dev.vars   # fill it in
npx wrangler dev                            # terminal 2 -> http://localhost:8787
```

## Notes
- Always share the Worker URL, not the `vercel.app` one (that one has no `/api`).
- Change the name popup behaviour with `ASK_NAME_EVERY_TIME` in `web/index.html`.
- A public form can't be fully bot-proof. Next step: add Cloudflare Turnstile to `/api/messages`.
- For a stronger admin gate, put Cloudflare Access (free, up to 50 users) in front of `/admin*` and drop the password login.
