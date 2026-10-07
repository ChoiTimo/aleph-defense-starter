import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
import { readFileSync } from 'node:fs';
import { findSecrets } from '../scripts/secret-scan.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  const step2 = deploymentIdentity(env, { ...config, step: 2 });
  assert.equal(step2.step, 2);
  assert.equal('sampleMarker' in step2, false);
  assert.throws(() => deploymentIdentity(env, { ...config, step: 3 }));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('first attack check reads public data.json without credentials', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1', notes: [{ title: '가상' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks(config);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/data.json');
    assert.equal(options.redirect, 'error');
    assert.match(result.observed, /확인 표시가 보임/u);
    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 200 });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /보이지 않음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 2 attack check records only status, counts, marker and key presence', async () => {
  const originalFetch = globalThis.fetch;
  const asked = [];
  let dataStatus = 404;
  const run = async (alephBody) => {
    globalThis.fetch = async (url) => {
      const path = new URL(String(url)).pathname;
      asked.push(path);
      if (path === '/data.json') return new Response('Not Found', { status: dataStatus });
      const body = path === '/aleph.json' ? alephBody
        : { notes: [{ title: '가상', content: '가상 본문' }] };
      return new Response(JSON.stringify(body), { status: 200 });
    };
    return runAttackChecks({ ...config, step: 2 });
  };
  try {
    const results = await run({ schema: 'aleph.defense.deployment.v1', step: 2 });
    assert.deepEqual(asked, ['/data.json', '/aleph.json', '/api/notes']);
    assert.deepEqual(results.map(item => item.attackId),
      ['public_data_json_no_notes', 'static_marker_absent', 'anonymous_api_notes_read']);
    assert.match(results[0].observed, /없음 \(HTTP 404\)/u);
    assert.match(results[1].observed, /확인 표시가 보이지 않음/u);
    assert.match(results[2].observed, /HTTP 200, 메모 1건, 키로 보이는 문자열 없음/u);
    assert.ok(results.every(item => !JSON.stringify(item).includes('가상 본문')));
    const leaked = await run({ step: 2, sampleMarker: 'SAMPLE_NOTE_1' });
    assert.match(leaked[1].observed, /확인 표시가 보임: \/aleph\.json/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('secret scan finds key-like values without printing them, and ignores explanations', () => {
  const fake = [
    ['a', `sb_secret_${'A'.repeat(20)}`],
    ['b', `eyJ${'a'.repeat(12)}.eyJ${'b'.repeat(12)}.${'c'.repeat(12)}`],
    ['c', `-----BEGIN ${'PRIVATE KEY'}-----`],
    ['d', `${'postgres'}://user:pw@host`],
  ];
  const found = findSecrets(fake);
  assert.equal(found.length, 4);
  assert.ok(found.every(line => !line.includes('AAAA') && !line.includes('aaaa')));
  assert.deepEqual(findSecrets([['ok', 'sb_secret_… 키는 Vercel에만 둡니다. eyJ로 시작하는 값도 적지 않습니다.']]), []);
});

test('vercel.json adds the nosniff security header to every response', () => {
  const rules = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url), 'utf8')).headers;
  const all = rules.find(rule => rule.source === '/(.*)');
  assert.ok(all.headers.some(h => h.key === 'X-Content-Type-Options' && h.value === 'nosniff'));
});

// ---- 3단계: /api/notes는 서버가 검증한 로그인 요청에만 답합니다 ----
const realConfig = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));

const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const fakeToken = payload => `${b64({ alg: 'ES256', typ: 'JWT' })}.${b64(payload)}.c2ln`;
const nowSec = () => Math.floor(Date.now() / 1000);
const studentClaims = (extra = {}) => ({
  iss: realConfig.identityProvider.issuer, aud: realConfig.identityProvider.audience,
  role: 'authenticated', sub: '11111111-1111-4111-8111-111111111111',
  exp: nowSec() + 600, ...extra,
});

function fakeNotesClient(rows) {
  const chain = { select: () => chain, order: () => chain,
    then: (resolve, reject) => Promise.resolve({ data: rows, error: null }).then(resolve, reject) };
  return { from: () => chain };
}

async function callNotes({ method = 'GET', authorization, claimsResult, configured = true } = {}) {
  const { createNotesHandler } = await import('../api/notes.js');
  const { createLoginVerifier } = await import('../src/verify-login.mjs');
  const rows = [{ title: '가상 제목', content: '가상 본문' }];
  const verify = createLoginVerifier({ config: realConfig, supabaseClient: {
    auth: { getClaims: async () => claimsResult ?? { data: null, error: new Error('bad') } } } });
  const handler = createNotesHandler({
    getVerifier: () => { if (!configured) throw new Error('missing_env'); return verify; },
    getSupabase: () => fakeNotesClient(rows),
  });
  const out = { headers: {} };
  const response = {
    setHeader: (name, value) => { out.headers[name] = value; },
    status: code => { out.status = code; return response; },
    json: body => { out.body = body; return response; },
  };
  await handler({ method, headers: authorization ? { authorization } : {} }, response);
  return out;
}

test('aleph.config.json names the student login issuer in the shape the verifier accepts', async () => {
  const { createLoginVerifier } = await import('../src/verify-login.mjs');
  assert.doesNotThrow(() => createLoginVerifier({ config: realConfig,
    supabaseClient: { auth: { getClaims: async () => ({}) } } }));
  assert.equal(realConfig.step, 2);
});

test('/api/notes refuses a request without a login token', async () => {
  const result = await callNotes();
  assert.equal(result.status, 401);
  assert.deepEqual(result.body, { error: 'LOGIN_REQUIRED' });
  assert.equal(result.headers['WWW-Authenticate'], 'Bearer');
});

test('/api/notes refuses forged, expired and other-service tokens', async () => {
  const authorization = `Bearer ${fakeToken(studentClaims())}`;
  const forged = await callNotes({ authorization }); // 서명 검증 실패
  assert.equal(forged.status, 401);
  const expired = await callNotes({ authorization,
    claimsResult: { data: { claims: studentClaims({ exp: nowSec() - 60 }) }, error: null } });
  assert.equal(expired.status, 401);
  const otherAudience = await callNotes({ authorization,
    claimsResult: { data: { claims: studentClaims({ aud: 'other-service' }) }, error: null } });
  assert.equal(otherAudience.status, 401);
  const otherIssuer = await callNotes({
    authorization: `Bearer ${fakeToken(studentClaims({ iss: 'https://other.supabase.co/auth/v1' }))}`,
    claimsResult: { data: { claims: studentClaims() }, error: null } });
  assert.equal(otherIssuer.status, 401);
  for (const result of [forged, expired, otherAudience, otherIssuer]) {
    assert.deepEqual(result.body, { error: 'LOGIN_REQUIRED' });
    assert.equal(JSON.stringify(result.body).includes('가상 본문'), false);
  }
});

test('/api/notes answers a verified student token with title and content only', async () => {
  const result = await callNotes({ authorization: `Bearer ${fakeToken(studentClaims())}`,
    claimsResult: { data: { claims: studentClaims() }, error: null } });
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, { notes: [{ title: '가상 제목', content: '가상 본문' }] });
});

test('/api/notes stays closed when the server is not configured or the method is not GET', async () => {
  const closed = await callNotes({ configured: false,
    authorization: `Bearer ${fakeToken(studentClaims())}` });
  assert.equal(closed.status, 500);
  assert.deepEqual(closed.body, { error: 'SERVER_NOT_CONFIGURED' });
  assert.equal((await callNotes({ method: 'POST' })).status, 405);
});

// ---- 3단계 화면: 공식 SDK로 로그인하고, 공개 키만 쓰며, 토큰은 서버(/api/notes)에만 보냅니다 ----
test('public page logs in through the official SDK with the public key only', () => {
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  const sdk = readFileSync(new URL('../public/vendor/supabase.js', import.meta.url), 'utf8');
  const sdkVersion = JSON.parse(readFileSync(
    new URL('../node_modules/@supabase/supabase-js/package.json', import.meta.url), 'utf8')).version;
  assert.deepEqual(findSecrets([['public/index.html', html], ['public/vendor/supabase.js', sdk]]), []);
  assert.equal(sdk, readFileSync(
    new URL('../node_modules/@supabase/supabase-js/dist/umd/supabase.js', import.meta.url), 'utf8'));
  assert.match(html, new RegExp(`@supabase/supabase-js ${sdkVersion.replaceAll('.', '\\.')}`, 'u'));
  assert.match(html, /<script src="\/vendor\/supabase\.js"><\/script>/u);
  assert.match(html, /signInWithPassword/u);
  assert.match(html, /auth\.signOut\(/u);
  assert.match(html, /sb_publishable_/u);
  assert.equal(/sb_secret_|service_role/u.test(html), false);
  assert.ok(html.includes(realConfig.identityProvider.issuer.replace('/auth/v1', '')));
  assert.match(html, /fetch\('\/api\/notes'[\s\S]*Authorization: `Bearer \$\{accessToken\}`/u);
  assert.equal(/innerHTML|\/data\.json|esm\.sh|cdn\./u.test(html), false);
});
