# Raaz — Backend API + Admin Control Center

One backend + one database shared by the **Raaz Android app** (`com.raazindia.raaz`) and the **web admin panel**.
Stack: Node.js (built-in `http`, `crypto`, `node:sqlite` only — **zero npm dependencies**), single relational
SQLite database (`raaz.db`, created automatically on first run next to `server.js`). The schema is standard
relational SQL and migrates to **PostgreSQL** at deployment (same tables/columns; swap the data layer).

## Run

```bash
cd ~/workspace/raaz_server
node server.js            # listens on PORT (default 8080)
PORT=9000 node server.js  # custom port
```

- Admin panel: `http://localhost:8080/admin`
- API docs: `http://localhost:8080/api/docs`
- App API base: `http://localhost:8080/api/...`

## Default credentials — ⚠️ CHANGE AFTER DEPLOYMENT

| Role | Email | Password |
|---|---|---|
| Super Admin | `admin@raaz.app` | `RaazAdmin@123` |
| Demo user (app) | `demo@raaz.app` | `demo1234` (seeded with 100 coins) |

Change the admin password immediately after first deployment (create a new super admin / update the hash in the DB).
Seed content (categories, 7 sample videos with public sample streams, Pro plans ₹149/₹999, coin packages
1K/3K/12K/15K/20K, reward config, default settings, one feed collection) is created automatically on first run
and is fully editable from the admin panel.

## Self-test

```bash
./test.sh   # starts a throwaway server on port 18080 with a fresh temp DB, runs 27 checks, prints PASS/FAIL
```

Covers: admin login, dashboard counts, app home, per-video coin prices (10 vs 50) charged exactly on unlock,
double-unlock idempotency, coin-price-required validation, MKV source type, payment claim → duplicate-UTR
rejection → admin approve credits exactly once → second approve rejected, individual notification targeting
(`awaiting_provider`, no fake sends), AdMob global-off precedence, SQL export without password hashes.

## What is implemented

- **App API**: config (remote settings + version + branding + resolved AdMob config), home sections, feeds,
  categories, video detail/search/shorts, register/login/guest auth (pbkdf2-hashed passwords, bearer session
  tokens), atomic coin unlock with ledger + idempotency keys, wallet/ledger, daily check-in rewards, coin
  packages, Pro plans, manual payment claims (UTR, duplicate-rejected), watch history/library, watch-later/like
  toggles, content reports, play tracking.
- **Admin API + UI**: role-based access (super_admin, content_manager, payment_manager, support_manager,
  auditor read-only) enforced server-side on every endpoint; login rate-limiting + login history; dashboard with
  real DB counts (AdMob revenue shown as "not connected" — never invented); full video CRUD with per-video
  Access Control (access type + **own coin price per video** + pro-free) and per-video Ad Configuration;
  categories with default ad policy; feeds collections; home sections CMS; user management with audited
  Pro grant/revoke, coin adjustments (mandatory reason + ledger) and suspend; payment claim approve/reject that
  credits **exactly once**; immutable coin ledger; rewards config; notification composer with audience targeting
  (all / free / pro / expired pro / pending claims / category / **individual user**); remote app settings;
  version/force-update control; branding; payment/provider config (secrets masked, server-side only);
  moderation reports; append-only audit log; **SQL export/import** (super admin; export excludes password
  hashes/secrets; import validates INSERT-only into known tables, takes a mandatory pre-import backup, applies
  transactionally, merge/restore modes).

## AdMob precedence (server-side)

`legal/consent restrictions > global AdMob OFF > individual video override (incl. ad-free override) > category default_ads > global defaults`

Resolved in `resolveAds()` when composing app-facing video payloads, and exposed via `/api/config` (`ads` object
incl. independent Feeds ad config: `feeds_ads_enabled`, `feeds_native_ads`, `feeds_ad_frequency`).

## Deployment notes

- Put the server behind an **HTTPS reverse proxy** (nginx/Caddy) — admin auth and tokens must never travel over plain HTTP in production.
- Set a strong admin password, restrict `/admin` by IP if possible, and back up `raaz.db` regularly (the panel also offers SQL export).
- For PostgreSQL: create the same tables (see `server.js` schema block / export.sql DDL), point a Postgres data layer at it; API contract is unchanged.
- Environment: `PORT`, `RAAZ_DB` (override DB path).

## Awaiting credentials (structure built, honestly marked — nothing faked)

| Integration | What's needed | Current state |
|---|---|---|
| OneSignal push sending | App ID + API key in Admin → Payment/Provider Config | Campaigns recorded with status `awaiting_provider`; with a key set they become `provider_configured_pending_send` (dispatch worker activates at deployment). No send is ever faked. |
| PayPal / Paytm live payments | Merchant credentials + webhook verification | Config pages + manual QR/UTR flow fully working; providers stay disabled until credentials + server-side verification are completed. A claim is credited only after admin approval. |
| AdMob SSV (rewarded ads) | AdMob app/ad-unit IDs + server-side verification callback | Reward config stored; rewarded coins must only be granted after verified callbacks. |
| Google sign-in | OAuth client config | Email/password + guest auth work now; `google_signin_enabled` toggle exists. |
| Email OTP / magic link delivery | SMTP or provider (e.g. SES/SendGrid) keys | Toggle exists (`email_signin_enabled`); delivery activates with provider credentials. |
