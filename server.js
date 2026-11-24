'use strict';
const path = require('node:path');
const fs = require('node:fs');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const { z } = require('zod');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ACCESS_COOKIE = 'phc_access';
const REFRESH_COOKIE = 'phc_refresh';
const REMEMBER_COOKIE = 'phc_remember';
const WEEK = 7 * 24 * 60 * 60 * 1000;
const isConfigured = Boolean(process.env.SUPABASE_URL && process.env.SUPABASE_ANON_KEY);
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  xFrameOptions: false,
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ["'self'", 'https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], frameAncestors: ["'self'", 'https://*.manus.computer', 'https://*.manus.im']
  } }
}));
app.use(express.json({ limit: '24kb' }));
app.use(cookieParser());

function createSupabase(accessToken) {
  if (!isConfigured) return null;
  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    ...(accessToken ? { global: { headers: { Authorization: `Bearer ${accessToken}` } } } : {})
  });
}
function cookieOptions(remember) {
  return { httpOnly: true, secure: true, sameSite: 'none', path: '/', ...(remember ? { maxAge: WEEK } : {}) };
}
function writeSessionCookies(res, session, remember) {
  const options = cookieOptions(remember);
  res.cookie(ACCESS_COOKIE, session.access_token, options);
  res.cookie(REFRESH_COOKIE, session.refresh_token, options);
  res.cookie(REMEMBER_COOKIE, remember ? '1' : '0', options);
}
function clearSessionCookies(res) {
  const options = cookieOptions(false);
  res.clearCookie(ACCESS_COOKIE, options);
  res.clearCookie(REFRESH_COOKIE, options);
  res.clearCookie(REMEMBER_COOKIE, options);
}
function requireConfigured(_req, res, next) {
  if (!isConfigured) return res.status(503).json({ error: 'Supabase is not configured. Set SUPABASE_URL and SUPABASE_ANON_KEY in the backend environment.' });
  next();
}
function requireSameOrigin(req, res, next) {
  const fetchSite = req.get('sec-fetch-site');
  if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') return res.status(403).json({ error: 'Cross-origin requests are not allowed.' });
  const origin = req.get('origin');
  if (origin) {
    try {
      const expectedHost = (req.get('x-forwarded-host') || req.get('host') || '').split(',')[0].trim();
      if (new URL(origin).host !== expectedHost) return res.status(403).json({ error: 'Cross-origin requests are not allowed.' });
    } catch { return res.status(403).json({ error: 'Invalid request origin.' }); }
  }
  next();
}

async function authenticate(req, res, next) {
  if (!isConfigured) return res.status(503).json({ error: 'Supabase is not configured.' });
  const access = req.cookies[ACCESS_COOKIE];
  const refresh = req.cookies[REFRESH_COOKIE];
  if (!access) return res.status(401).json({ error: 'Please sign in to view account information.' });
  let authClient = createSupabase();
  let dataClient = createSupabase(access);
  let result = await authClient.auth.getUser(access);
  if (result.error && refresh) {
    const refreshed = await authClient.auth.refreshSession({ refresh_token: refresh });
    if (!refreshed.error && refreshed.data.session) {
      writeSessionCookies(res, refreshed.data.session, req.cookies[REMEMBER_COOKIE] === '1');
      authClient = createSupabase(refreshed.data.session.access_token);
      dataClient = authClient;
      result = { data: { user: refreshed.data.user }, error: null };
    }
  }
  if (result.error || !result.data.user) {
    clearSessionCookies(res);
    return res.status(401).json({ error: 'Your session has expired. Please sign in again.' });
  }
  req.user = result.data.user;
  req.supabase = dataClient;
  next();
}

const loginSchema = z.object({ email: z.string().trim().email().max(254), password: z.string().min(1).max(256), remember: z.boolean().optional().default(false) });
const emailSchema = z.object({ email: z.string().trim().email().max(254) });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many sign-in attempts. Please wait and try again.' } });
const resetLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 4, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Please wait before requesting another reset email.' } });

app.get('/api/health', (_req, res) => res.status(200).json({ status: 'ok' }));
app.get('/api/config', (_req, res) => res.json({ supabaseConfigured: isConfigured }));
app.get('/api/auth/me', requireConfigured, authenticate, (req, res) => res.json({ user: { id: req.user.id, email: req.user.email } }));
app.post('/api/auth/login', requireSameOrigin, loginLimiter, requireConfigured, async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Enter a valid email address and password.' });
  const client = createSupabase();
  const { data, error } = await client.auth.signInWithPassword({ email: parsed.data.email, password: parsed.data.password });
  if (error || !data.session) return res.status(401).json({ error: 'Invalid login credentials.' });
  writeSessionCookies(res, data.session, parsed.data.remember);
  res.json({ user: { id: data.user.id, email: data.user.email } });
});
app.post('/api/auth/forgot-password', requireSameOrigin, resetLimiter, requireConfigured, async (req, res) => {
  const parsed = emailSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Enter a valid email address.' });
  const options = process.env.PASSWORD_RESET_REDIRECT_URL ? { redirectTo: process.env.PASSWORD_RESET_REDIRECT_URL } : undefined;
  await createSupabase().auth.resetPasswordForEmail(parsed.data.email, options);
  res.json({ ok: true });
});
app.post('/api/auth/logout', requireSameOrigin, (req, res) => {
  const token = req.cookies[ACCESS_COOKIE];
  if (token && isConfigured) createSupabase(token).auth.signOut({ scope: 'local' }).catch(() => {});
  clearSessionCookies(res);
  res.json({ ok: true });
});

app.get('/api/dashboard', requireConfigured, authenticate, async (req, res) => {
  const [accountsResult, transactionsResult, chargesResult] = await Promise.all([
    req.supabase.from('accounts').select('id,name,account_type,account_number_last4,status,currency,balance,available_balance,created_at').order('created_at', { ascending: true }),
    req.supabase.from('transactions').select('id,description,transaction_date,category,amount,currency,status').order('transaction_date', { ascending: false }).limit(20),
    req.supabase.from('outstanding_charges').select('id,description,amount,currency,status,created_at').in('status', ['due', 'pending', 'outstanding']).order('created_at', { ascending: false })
  ]);
  const failure = accountsResult.error || transactionsResult.error || chargesResult.error;
  if (failure) return res.status(500).json({ error: 'Unable to load account information. Confirm the Supabase schema is installed.' });
  const accounts = (accountsResult.data || []).map((row) => ({ name: row.name, type: row.account_type, masked: row.account_number_last4 ? `•••• ${row.account_number_last4}` : '', status: row.status, currency: row.currency, balance: row.balance, available_balance: row.available_balance }));
  const transactions = (transactionsResult.data || []).map((row) => ({ description: row.description, date: row.transaction_date, category: row.category, amount: row.amount, currency: row.currency, status: row.status }));
  res.json({ accounts, transactions, charges: chargesResult.data || [] });
});

app.use('/api', (_req, res) => res.status(404).json({ error: 'API endpoint not found.' }));

// In the integrated project, Express also serves the adjacent vanilla frontend. The backend ZIP remains a standalone API package.
const publicDir = path.resolve(__dirname, '../public');
if (fs.existsSync(path.join(publicDir, 'index.html'))) {
  app.use(express.static(publicDir, { index: 'index.html', etag: true, maxAge: 0 }));
  app.get('*', (_req, res) => res.sendFile(path.join(publicDir, 'index.html')));
}
app.use((error, _req, res, _next) => {
  console.error('Request failed:', error?.message || 'unknown error');
  res.status(500).json({ error: 'An unexpected server error occurred.' });
});

app.listen(PORT, '0.0.0.0', () => console.log(`PHC account service listening on port ${PORT}`));
