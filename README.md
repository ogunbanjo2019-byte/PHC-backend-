# PHC Supabase Backend

Standalone Node.js + Express API for the P10 Holding Company account dashboard. It uses Supabase Auth and Supabase PostgreSQL; MongoDB is not used. This package does not contain the website frontend.

## Requirements and setup

Use Node.js 20 or newer. Copy `.env.example` to `.env` and set the Supabase project URL and anon/public key. Never put a Supabase service-role key in this package or a browser. Install and run:

```sh
npm install
npm start
```

The health route is `GET /api/health`; configuration readiness is `GET /api/config`. When `public/` is placed beside this package's parent `backend/` folder in the website repository, the same Express process also serves the integrated frontend. The downloadable backend archive is API-only.

## Supabase initialization

1. Apply `schema.sql` in the Supabase SQL editor.
2. Create only authorized user accounts under Supabase Authentication; public self-registration is not implemented.
3. Add account, transaction, and outstanding-charge records through an authorized administrative process, setting each `owner_id` to the corresponding Supabase Auth user UUID.
4. Confirm the RLS policies are enabled and that each authenticated user can read only rows with their own `owner_id`.
5. For password recovery, configure the allowed redirect URL in Supabase and optionally set `PASSWORD_RESET_REDIRECT_URL`.

## API

- `GET /api/health` — unauthenticated service health.
- `GET /api/config` — whether Supabase environment values are present.
- `POST /api/auth/login` — email/password sign-in; tokens are stored in Secure, HttpOnly cookies.
- `POST /api/auth/forgot-password` — Supabase password recovery with generic response behavior.
- `POST /api/auth/logout` — clear local authentication cookies.
- `GET /api/auth/me` — current signed-in user.
- `GET /api/dashboard` — current user's accounts, transactions, and due charges, protected by Supabase Auth and RLS.

The backend exposes read-only financial data routes. It provides no payment, transfer, collection, or withdrawal endpoint. Cookies use `SameSite=None; Secure` for the hosted cross-site preview; use HTTPS when deploying. The auth rate limit and same-origin checks are enabled for sign-in and recovery requests.

## Environment variables

`SUPABASE_URL` and `SUPABASE_ANON_KEY` are required. `PORT` defaults to `3000`. `PASSWORD_RESET_REDIRECT_URL` is optional and must also be allowed in Supabase Auth URL settings. Keep actual environment files out of source control.
