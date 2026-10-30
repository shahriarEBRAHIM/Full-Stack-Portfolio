// Edge router. It is the ONLY thing that (1) talks to Firestore and (2) can serve admin.html.
import { addMessage, listMessages } from './firestore.js';

const enc = new TextEncoder();
const TTL = 60 * 60 * 12; // admin session length: 12h

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers } });
const cookie = (v, age, url) =>
  `session=${v}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${url.protocol === 'https:' ? '; Secure' : ''}`;
const ip = req => req.headers.get('CF-Connecting-IP') || 'local';
const allow = async (env, key) => !env.LIMITER || (await env.LIMITER.limit({ key })).success;

export default {
  async fetch(req, env) {
    const url = new URL(req.url), path = url.pathname, m = req.method;
    try {
      if (path === '/api/messages' && m === 'POST') return await sendMessage(req, env, url);
      if (path === '/api/login' && m === 'POST') return await login(req, env, url);
      if (path === '/api/logout' && m === 'POST') return json({ ok: true }, 200, { 'Set-Cookie': cookie('', 0, url) });
      if (path === '/login') return asset(req, env, '/login.html');

      if (path === '/api/admin/messages' && m === 'GET') {
        if (!(await authed(req, env))) return json({ error: 'unauthorized' }, 401);
        return json({ messages: await listMessages(env) });
      }
      if (path === '/admin' || path === '/admin.html') {
        // Unauthenticated visitors get a redirect and never receive a byte of admin.html.
        if (!(await authed(req, env))) return Response.redirect(url.origin + '/login', 302);
        return asset(req, env, '/admin.html');
      }
      if (path.startsWith('/api/')) return json({ error: 'not_found' }, 404);
      return await proxy(req, env, url); // public site from Vercel
    } catch (e) {
      console.error(e);
      return json({ error: 'server_error' }, 500);
    }
  },
};

async function sendMessage(req, env, url) {
  const origin = req.headers.get('Origin');
  if (origin && origin !== url.origin) return json({ error: 'forbidden' }, 403);
  if (Number(req.headers.get('Content-Length')) > 4096) return json({ error: 'too_large' }, 413);
  if (!(await allow(env, 'msg:' + ip(req)))) return json({ error: 'rate_limited' }, 429);
  const b = await req.json().catch(() => ({}));
  const str = (v, n) => (typeof v === 'string' ? v.trim().slice(0, n) : '');
  const name = str(b.name, 40), text = str(b.text, 1000), visitorId = str(b.visitorId, 64);
  if (!name || !text || !/^[\w-]{8,64}$/.test(visitorId)) return json({ error: 'invalid_input' }, 400);
  await addMessage(env, { name, text, visitorId });
  return json({ ok: true }, 201);
}

async function login(req, env, url) {
  if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) return json({ error: 'not_configured' }, 500);
  if (!(await allow(env, 'login:' + ip(req)))) return json({ error: 'rate_limited' }, 429);
  const b = await req.json().catch(() => ({}));
  if (!(await sameSecret(String(b.password ?? ''), env.ADMIN_PASSWORD))) return json({ error: 'invalid' }, 401);
  return json({ ok: true }, 200, { 'Set-Cookie': cookie(await makeSession(env), TTL, url) });
}

async function asset(req, env, path) {
  const res = await env.ASSETS.fetch(new Request(new URL(path, req.url)));
  const h = new Headers(res.headers);
  h.set('Cache-Control', 'no-store'); h.set('X-Robots-Tag', 'noindex, nofollow');
  return new Response(res.body, { status: res.status, headers: h });
}

async function proxy(req, env, url) {
  if (!['GET', 'HEAD'].includes(req.method)) return json({ error: 'method_not_allowed' }, 405);
  const target = new URL(url.pathname + url.search, env.ORIGIN_URL);
  return fetch(target, { method: req.method, headers: req.headers, redirect: 'follow' });
}

// --- signed session cookie: "<expiry>.<hmac>" ---
const hmacKey = (env, use) => crypto.subtle.importKey('raw', enc.encode(env.SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, [use]);
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const unhex = h => Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16));

async function makeSession(env) {
  const exp = String(Math.floor(Date.now() / 1000) + TTL);
  return `${exp}.${hex(await crypto.subtle.sign('HMAC', await hmacKey(env, 'sign'), enc.encode(exp)))}`;
}
async function authed(req, env) {
  const t = /(?:^|;\s*)session=([^;]+)/.exec(req.headers.get('Cookie') || '')?.[1];
  const [exp, sig] = (t || '').split('.');
  if (!sig || !(Number(exp) > Date.now() / 1000)) return false;
  return crypto.subtle.verify('HMAC', await hmacKey(env, 'verify'), unhex(sig), enc.encode(exp));
}
async function sameSecret(a, b) {
  const [x, y] = await Promise.all([a, b].map(async s => new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)))));
  let d = 0; for (let i = 0; i < 32; i++) d |= x[i] ^ y[i];
  return d === 0;
}
