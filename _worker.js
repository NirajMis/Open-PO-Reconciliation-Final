/* ===========================================================================
   Edge login for the JI Open PO Reconciliation portal.
   Runs on Cloudflare before any file is served, so the portal is never
   handed to an unauthenticated visitor. Credentials live in the project's
   encrypted variables, never in this file.

   Set ONE of these in  Settings > Variables and secrets  (tick Encrypt):
     PORTAL_USERS      samay:somepassword,priya:anotherpassword
     PORTAL_PASSWORD   somepassword          (single shared password, user "ji")
   =========================================================================== */

const REALM = 'JI Open PO Reconciliation';

/* Comparison that does not leak the answer through how long it takes. */
function same(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const la = a.length, lb = b.length;
  let diff = la ^ lb;
  const n = Math.max(la, lb);
  for (let i = 0; i < n; i++) diff |= (a.charCodeAt(i % la || 0) || 0) ^ (b.charCodeAt(i % lb || 0) || 0);
  return diff === 0 && la === lb;
}

function credentials(env) {
  const map = new Map();
  const list = (env.PORTAL_USERS || '').trim();
  if (list) {
    for (const pair of list.split(',')) {
      const i = pair.indexOf(':');
      if (i <= 0) continue;
      const u = pair.slice(0, i).trim(), p = pair.slice(i + 1).trim();
      if (u && p) map.set(u, p);
    }
  }
  const single = (env.PORTAL_PASSWORD || '').trim();
  if (single) map.set('ji', single);
  return map;
}

const deny = () => new Response(
  '<!doctype html><meta charset=utf-8><title>Sign in required</title>' +
  '<style>body{font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;' +
  'max-width:30rem;margin:22vh auto;padding:0 1.5rem;color:#1b2430}h1{font-size:19px;margin:0 0 .4rem}' +
  'p{color:#5b6675}</style><h1>Sign in required</h1>' +
  '<p>This is the Jaisingh Innovations reconciliation portal. Enter the username and password you were given.</p>',
  { status: 401, headers: {
      'WWW-Authenticate': 'Basic realm="' + REALM + '", charset="UTF-8"',
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
  } });

const misconfigured = () => new Response(
  '<!doctype html><meta charset=utf-8><title>Not configured</title>' +
  '<style>body{font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;' +
  'max-width:34rem;margin:20vh auto;padding:0 1.5rem;color:#1b2430}code{background:#eef1f5;' +
  'padding:1px 5px;border-radius:4px}h1{font-size:19px}</style>' +
  '<h1>Portal is not configured yet</h1><p>No credentials are set, so the portal is refusing every request ' +
  'rather than serving itself to the public.</p><p>In the Cloudflare dashboard open this project, then ' +
  '<b>Settings &rsaquo; Variables and secrets &rsaquo; Add</b>, create <code>PORTAL_USERS</code> with a value like ' +
  '<code>samay:choose-a-password</code>, tick <b>Encrypt</b>, save, and redeploy.</p>',
  { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });

export default {
  async fetch(request, env) {
    const users = credentials(env);
    if (users.size === 0) return misconfigured();      // fail closed, never open

    const header = request.headers.get('Authorization') || '';
    if (!/^Basic /i.test(header)) return deny();

    let user, pass;
    try {
      const decoded = atob(header.slice(6).trim());
      const i = decoded.indexOf(':');
      if (i < 0) return deny();
      user = decoded.slice(0, i);
      pass = decoded.slice(i + 1);
    } catch { return deny(); }

    const expected = users.get(user);
    if (!expected || !same(pass, expected)) return deny();

    const res = await env.ASSETS.fetch(request);
    const out = new Response(res.body, res);
    out.headers.set('X-Content-Type-Options', 'nosniff');
    out.headers.set('X-Frame-Options', 'SAMEORIGIN');
    out.headers.set('Referrer-Policy', 'same-origin');
    out.headers.set('Cache-Control', 'private, max-age=0, must-revalidate');
    return out;
  },
};
