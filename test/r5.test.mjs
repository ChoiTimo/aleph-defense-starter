import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
import { readFileSync } from 'node:fs';
import { findSecrets } from '../scripts/secret-scan.mjs';
import { randomUUID } from 'node:crypto';
import { createNotesApi } from '../src/notes-api.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';

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
  const step3 = deploymentIdentity(env, { ...config, step: 3 });
  assert.equal(step3.step, 3);
  assert.equal('sampleMarker' in step3, false);
  assert.throws(() => deploymentIdentity(env, { ...config, step: 4 }));
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

// ---- 3단계: 메모 API는 서버가 검증한 로그인 요청에만 답하고, 추가는 확인된 사용자 ID로 저장합니다 ----
const realConfig = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));

const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const fakeToken = payload => `${b64({ alg: 'ES256', typ: 'JWT' })}.${b64(payload)}.c2ln`;
const nowSec = () => Math.floor(Date.now() / 1000);
const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const claimsOf = (sub, extra = {}) => ({
  iss: realConfig.identityProvider.issuer, aud: realConfig.identityProvider.audience,
  role: 'authenticated', sub, exp: nowSec() + 600, ...extra,
});
const bearer = (sub, extra) => `Bearer ${fakeToken(claimsOf(sub, extra))}`;

// 메모 표를 흉내 내는 가짜 DB입니다. eq·order·select·insert·update·delete만 지원합니다.
class FakeQuery {
  constructor(rows) { this.rows = rows; this.op = 'select'; this.filters = []; }
  select() { return this; }
  insert(payload) { this.op = 'insert'; this.payload = payload; return this; }
  update(payload) { this.op = 'update'; this.payload = payload; return this; }
  delete() { this.op = 'delete'; return this; }
  eq(column, value) { this.filters.push([column, value]); return this; }
  order() { return this; }
  single() { this.mode = 'single'; return this; }
  maybeSingle() { this.mode = 'maybe'; return this; }
  then(resolve, reject) { return Promise.resolve(this.run()).then(resolve, reject); }
  run() {
    const hit = () => this.rows.filter(row => this.filters.every(([c, v]) => row[c] === v));
    let data;
    if (this.op === 'insert') {
      if (this.payload.id && this.rows.some(row => row.id === this.payload.id)) {
        return { data: null, error: { code: '23505' } };
      }
      const row = { id: randomUUID(), ...this.payload };
      this.rows.push(row);
      data = [row];
    } else if (this.op === 'update') {
      data = hit();
      data.forEach(row => Object.assign(row, this.payload));
    } else if (this.op === 'delete') {
      data = hit();
      this.rows.splice(0, this.rows.length, ...this.rows.filter(row => !data.includes(row)));
    } else {
      data = hit();
    }
    if (this.mode === 'single') return { data: data[0] ?? null, error: null };
    if (this.mode === 'maybe') return { data: data[0] ?? null, error: null };
    return { data, error: null };
  }
}

function makeApi({ rows = [], configured = true } = {}) {
  const verify = createLoginVerifier({ config: realConfig, supabaseClient: { auth: {
    getClaims: async (token) => {
      const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
      return claims.forged ? { data: null, error: new Error('bad') } : { data: { claims }, error: null };
    } } } });
  const api = createNotesApi({
    getVerifier: () => { if (!configured) throw new Error('missing_env'); return verify; },
    getSupabase: () => ({ from: () => new FakeQuery(rows) }),
  });
  const call = async (handler, { method = 'GET', authorization, body, id } = {}) => {
    const out = { headers: {} };
    const response = {
      setHeader: (name, value) => { out.headers[name] = value; },
      status: code => { out.status = code; return response; },
      json: payload => { out.body = payload; return response; },
    };
    await handler({ method, headers: authorization ? { authorization } : {}, body,
      query: id === undefined ? {} : { id }, url: id === undefined ? '/api/notes' : `/api/notes/${id}` }, response);
    return out;
  };
  return { rows, list: o => call(api.collection, o), item: o => call(api.item, o) };
}

test('aleph.config.json is at step 3 and names the login issuer and the five real API routes', () => {
  assert.equal(realConfig.step, 3);
  assert.doesNotThrow(() => createLoginVerifier({ config: realConfig,
    supabaseClient: { auth: { getClaims: async () => ({}) } } }));
  assert.deepEqual(realConfig.allowedRoutes, ['GET /api/notes', 'POST /api/notes',
    'GET /api/notes/:id', 'PUT /api/notes/:id', 'DELETE /api/notes/:id']);
});

test('every notes route refuses a request without a login token and changes nothing', async () => {
  const api = makeApi({ rows: [{ id: A, owner_id: B, title: '가상 제목', content: '가상 본문' }] });
  const calls = [
    api.list({}), api.list({ method: 'POST', body: { title: 't', body: 'b' } }),
    api.item({ id: A }), api.item({ method: 'PUT', id: A, body: { title: 'x', body: 'y' } }),
    api.item({ method: 'DELETE', id: A }),
  ];
  for (const result of await Promise.all(calls)) {
    assert.equal(result.status, 401);
    assert.deepEqual(result.body, { error: 'LOGIN_REQUIRED' });
    assert.equal(result.headers['WWW-Authenticate'], 'Bearer');
  }
  assert.deepEqual(api.rows, [{ id: A, owner_id: B, title: '가상 제목', content: '가상 본문' }]);
});

test('forged, expired and other-service tokens are refused', async () => {
  const api = makeApi();
  const cases = [
    bearer(A, { forged: true }), bearer(A, { exp: nowSec() - 60 }),
    bearer(A, { aud: 'other-service' }), bearer(A, { iss: 'https://other.supabase.co/auth/v1' }),
  ];
  for (const authorization of cases) {
    const result = await api.list({ authorization });
    assert.equal(result.status, 401);
    assert.deepEqual(result.body, { error: 'LOGIN_REQUIRED' });
  }
});

test('A can add, read, edit and delete a note; owner_id comes from the verified token', async () => {
  const api = makeApi();
  const authorization = bearer(A);
  // 브라우저가 owner_id·userId·role을 보내도 서버는 무시합니다.
  const created = await api.list({ method: 'POST', authorization,
    body: { title: '  첫 메모  ', body: '가상 본문', owner_id: B, userId: B, role: 'admin' } });
  assert.equal(created.status, 201);
  const { id } = created.body;
  assert.deepEqual(Object.keys(created.body), ['id']);
  assert.match(id, /^[0-9a-f-]{36}$/u);
  assert.equal(api.rows[0].owner_id, A);
  assert.equal(api.rows[0].title, '첫 메모');
  assert.equal('role' in api.rows[0] || 'userId' in api.rows[0], false);

  const listed = await api.list({ authorization });
  assert.equal(listed.status, 200);
  assert.deepEqual(listed.body, [{ id, title: '첫 메모', body: '가상 본문' }]);

  const one = await api.item({ authorization, id });
  assert.deepEqual(one.body, { id, title: '첫 메모', body: '가상 본문' });

  const edited = await api.item({ method: 'PUT', authorization, id, body: { title: '고친 제목', body: '고친 본문' } });
  assert.equal(edited.status, 200);
  assert.deepEqual((await api.item({ authorization, id })).body, { id, title: '고친 제목', body: '고친 본문' });

  const removed = await api.item({ method: 'DELETE', authorization, id });
  assert.equal(removed.status, 200);
  assert.equal((await api.item({ authorization, id })).status, 404);
  assert.deepEqual((await api.list({ authorization })).body, []);
  assert.equal((await api.item({ method: 'DELETE', authorization, id })).status, 404);
  assert.equal((await api.item({ method: 'PUT', authorization, id, body: { title: 'x', body: 'y' } })).status, 404);
});

test('POST keeps a client UUID, refuses duplicates and malformed input; the list shows only my notes', async () => {
  const api = makeApi({ rows: [{ id: randomUUID(), owner_id: null, title: '시드', content: '가상' }] });
  const mine = randomUUID();
  const ok = await api.list({ method: 'POST', authorization: bearer(A), body: { id: mine, title: 't', body: 'b' } });
  assert.deepEqual([ok.status, ok.body], [201, { id: mine }]);
  assert.equal((await api.list({ method: 'POST', authorization: bearer(A), body: { id: mine, title: 't', body: 'b' } })).status, 409);
  for (const body of [{ id: 'not-a-uuid', title: 't', body: 'b' }, { title: '', body: 'b' }, { title: 't' },
    { title: 't', body: 5 }, { title: 'x'.repeat(201), body: 'b' }, { title: 't', body: 'x'.repeat(5001) }, 'x', null, [1]]) {
    assert.equal((await api.list({ method: 'POST', authorization: bearer(A), body })).status, 400);
  }
  assert.equal((await api.item({ authorization: bearer(A), id: 'not-a-uuid' })).status, 400);
  assert.deepEqual((await api.list({ authorization: bearer(A) })).body, [{ id: mine, title: 't', body: 'b' }]);
  assert.deepEqual((await api.list({ authorization: bearer(B) })).body, []);
});

test('wrong methods get 405 and a missing server configuration stays closed', async () => {
  const api = makeApi();
  assert.equal((await api.list({ method: 'DELETE', authorization: bearer(A) })).status, 405);
  assert.equal((await api.item({ method: 'POST', authorization: bearer(A), id: A })).status, 405);
  const closed = makeApi({ configured: false });
  const result = await closed.list({ authorization: bearer(A) });
  assert.equal(result.status, 500);
  assert.deepEqual(result.body, { error: 'SERVER_NOT_CONFIGURED' });
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
  assert.match(html, /Authorization: `Bearer \$\{token\}`/u);
  assert.match(html, /api\('GET', '\/api\/notes'\)/u);
  assert.match(html, /api\('POST', '\/api\/notes', \{ title: /u);
  assert.match(html, /api\('PUT', `\/api\/notes\/\$\{note\.id\}`/u);
  assert.match(html, /api\('DELETE', `\/api\/notes\/\$\{note\.id\}`\)/u);
  assert.equal(/owner_id|userId|role:/u.test(html.replace(/\/\/.*$/gmu, '')), false);
  assert.equal(/innerHTML|\/data\.json|esm\.sh|cdn\./u.test(html), false);
});

test('step 3 attack check sends only refusal probes and records status numbers, never bodies or tokens', async () => {
  const originalFetch = globalThis.fetch;
  const sent = [];
  const run = async (apiStatus) => {
    sent.length = 0;
    globalThis.fetch = async (url, init = {}) => {
      const path = new URL(String(url)).pathname;
      sent.push({ method: init.method ?? 'GET', path, auth: init.headers?.Authorization, body: init.body });
      if (path === '/data.json') return new Response('Not Found', { status: 404 });
      if (path === '/aleph.json') return new Response(JSON.stringify({ step: 3 }), { status: 200 });
      return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED', secret: '가상 본문' }), { status: apiStatus });
    };
    return runAttackChecks({ ...config, step: 3 });
  };
  try {
    const results = await run(401);
    assert.deepEqual(results.map(item => item.attackId), ['public_data_json_no_notes', 'static_marker_absent',
      'anonymous_notes_list_refused', 'anonymous_note_create_refused', 'anonymous_note_read_refused',
      'anonymous_note_update_refused', 'anonymous_note_delete_refused', 'forged_token_refused',
      'expired_token_refused', 'other_issuer_token_refused']);
    assert.ok(results.slice(2).every(item => item.observed === '거부됨 (HTTP 401)'));
    assert.ok(results.every(item => Object.keys(item).sort().join() === 'attackId,expected,observed'
      && item.expected.length <= 300 && item.observed.length <= 300));
    assert.equal(JSON.stringify(results).includes('가상 본문'), false);
    assert.equal(JSON.stringify(results).includes('Bearer'), false);
    // 쓰기 요청은 빈 본문이거나 존재하지 않는 id라서 로그인 확인이 뚫려도 자료가 생기거나 바뀌지 않습니다.
    const writes = sent.filter(item => ['POST', 'PUT', 'DELETE'].includes(item.method));
    assert.deepEqual(writes.map(item => item.method), ['POST', 'PUT', 'DELETE']);
    assert.ok(writes.filter(item => item.body !== undefined).every(item => item.body === '{}'));
    assert.ok(writes.slice(1).every(item => item.path === '/api/notes/00000000-0000-4000-8000-000000000000'));
    const open = await run(200);
    assert.ok(open.slice(2).every(item => item.observed === '거부되지 않음 (HTTP 200)'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
