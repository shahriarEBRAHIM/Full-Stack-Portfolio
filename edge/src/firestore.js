// Minimal Firestore REST client using a service account (bypasses security rules via IAM).
const b64url = x => {
  const bytes = typeof x === 'string' ? new TextEncoder().encode(x) : new Uint8Array(x);
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
let sa, cached = { token: '', exp: 0 };

async function token(env) {
  const now = Math.floor(Date.now() / 1000);
  sa ??= JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  if (cached.exp > now + 60) return cached.token;
  const head = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = b64url(JSON.stringify({
    iss: sa.client_email, scope: 'https://www.googleapis.com/auth/datastore',
    aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600
  }));
  const der = Uint8Array.from(atob(sa.private_key.replace(/-----[^-]+-----|\s/g, '')), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(`${head}.${claim}`));
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${head}.${claim}.${b64url(sig)}` })
  });
  if (!res.ok) throw new Error('token: ' + await res.text());
  const j = await res.json();
  cached = { token: j.access_token, exp: now + j.expires_in };
  return cached.token;
}

async function fs(env, path, body) {
  const t = await token(env);
  const res = await fetch(`https://firestore.googleapis.com/v1/projects/${sa.project_id}/databases/(default)/documents${path}`, {
    method: 'POST', headers: { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error('firestore: ' + await res.text());
  return res.json();
}

export const addMessage = (env, { name, text, visitorId }) =>
  fs(env, '/messages', { fields: {
    name: { stringValue: name }, text: { stringValue: text }, visitorId: { stringValue: visitorId },
    createdAt: { timestampValue: new Date().toISOString() }
  } });

export async function listMessages(env) {
  const rows = await fs(env, ':runQuery', { structuredQuery: {
    from: [{ collectionId: 'messages' }],
    orderBy: [{ field: { fieldPath: 'createdAt' }, direction: 'DESCENDING' }],
    limit: 500
  } });
  return rows.filter(r => r.document).map(({ document: d }) => ({
    id: d.name.split('/').pop(),
    name: d.fields.name.stringValue, text: d.fields.text.stringValue,
    visitorId: d.fields.visitorId.stringValue, createdAt: d.fields.createdAt.timestampValue
  })).reverse(); // oldest -> newest
}
