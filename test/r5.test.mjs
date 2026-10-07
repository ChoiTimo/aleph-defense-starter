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
  const step4 = deploymentIdentity(env, { ...config, step: 4 });
  assert.equal(step4.step, 4);
  assert.equal('sampleMarker' in step4, false);
  const step5 = deploymentIdentity(env, { ...config, step: 5 });
  assert.equal(step5.step, 5);
  assert.equal('sampleMarker' in step5, false);
  assert.throws(() => deploymentIdentity(env, { ...config, step: 6 }));
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

test('aleph.config.json is at step 5 and names the login issuer and the seven real API routes', () => {
  assert.equal(realConfig.step, 5);
  assert.equal(realConfig.originalApiUrl, 'https://vskaxngivuhucmbnoagz.supabase.co/rest/v1/notes');
  assert.doesNotThrow(() => createLoginVerifier({ config: realConfig,
    supabaseClient: { auth: { getClaims: async () => ({}) } } }));
  assert.deepEqual(realConfig.allowedRoutes, ['GET /api/notes', 'POST /api/notes',
    'GET /api/notes/:id', 'PUT /api/notes/:id', 'DELETE /api/notes/:id', 'POST /api/login', 'POST /api/refresh']);
  for (const route of realConfig.allowedRoutes) {
    const [method, path] = route.split(' ');
    const file = path.replace('/api/', 'api/').replace('/:id', '/[id]') + '.js';
    const code = readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
    assert.match(code, /export default/u, `${route} needs ${file}`);
    assert.ok(['GET', 'POST', 'PUT', 'DELETE'].includes(method));
  }
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
test('public page has no Supabase key or SDK and only calls this site\'s server functions', () => {
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.deepEqual(findSecrets([['public/index.html', html]]), []);
  assert.equal(/sb_publishable_|sb_secret_|service_role|supabase|createClient|signInWithPassword|\banon\b/iu.test(html), false);
  assert.equal(/<script src=/u.test(html), false);
  assert.match(html, /post\('\/api\/login'/u);
  assert.match(html, /post\('\/api\/refresh'/u);
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
      if (apiStatus === 'proxy') return new Response('Host not in allowlist', { status: 403, headers: { 'content-type': 'text/plain' } });
      if (apiStatus === 401) return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED', secret: '가상 본문' }), { status: 401 });
      return new Response(JSON.stringify({ id: 'x' }), { status: apiStatus });
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
    // 앱이 아닌 곳(접속 허용 목록·방화벽)이 보낸 403은 거부됨으로 적지 않고 확인하지 못함으로 적습니다.
    const blocked = await run('proxy');
    assert.ok(blocked.slice(2).every(item => item.observed === '확인하지 못함 (HTTP 403, 앱의 응답으로 보이지 않음)'));
    // 앱이 401이 아닌 다른 오류 JSON(예: 로그인 확인 전에 입력 검사에서 400)을 주면 거부로 치지 않습니다.
    assert.ok(!JSON.stringify(blocked).includes('거부됨 ('));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

// ---- 4단계: 로그인해도 내 자료만 보입니다 (읽기·추가·수정·삭제 모두 소유자 검사) ----
const C = '33333333-3333-4333-8333-333333333333';
const seedRows = () => [
  { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1', owner_id: A, title: 'A의 메모', content: 'A 본문' },
  { id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1', owner_id: B, title: 'B의 메모', content: 'B 본문' },
  { id: 'cccccccc-cccc-4ccc-8ccc-ccccccccccc1', owner_id: null, title: '주인 없음', content: '비어 있음' },
];
const A_NOTE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';
const B_NOTE = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1';
const NO_OWNER = 'cccccccc-cccc-4ccc-8ccc-ccccccccccc1';

test('step 4: each user lists and reads only their own notes and keeps the {id,title,body} shape', async () => {
  const api = makeApi({ rows: seedRows() });
  assert.deepEqual((await api.list({ authorization: bearer(A) })).body, [{ id: A_NOTE, title: 'A의 메모', body: 'A 본문' }]);
  assert.deepEqual((await api.list({ authorization: bearer(B) })).body, [{ id: B_NOTE, title: 'B의 메모', body: 'B 본문' }]);
  assert.deepEqual((await api.item({ authorization: bearer(A), id: A_NOTE })).body, { id: A_NOTE, title: 'A의 메모', body: 'A 본문' });
  assert.deepEqual((await api.item({ authorization: bearer(B), id: B_NOTE })).body, { id: B_NOTE, title: 'B의 메모', body: 'B 본문' });
  // 다른 사람의 한 건 읽기와 주인 없는 메모 읽기는 403입니다. 제목·본문은 나가지 않습니다.
  for (const [user, id] of [[B, A_NOTE], [A, B_NOTE], [A, NO_OWNER], [B, NO_OWNER], [C, A_NOTE]]) {
    const result = await api.item({ authorization: bearer(user), id });
    assert.equal(result.status, 403);
    assert.deepEqual(result.body, { error: 'FORBIDDEN' });
  }
  const missing = await api.item({ authorization: bearer(A), id: randomUUID() });
  assert.deepEqual([missing.status, missing.body], [404, { error: 'NOT_FOUND' }]);
});

test('step 4: B gets 403 editing or deleting A\'s note, and nothing in the table changes', async () => {
  const rows = seedRows();
  const before = JSON.stringify(rows);
  const api = makeApi({ rows });
  const edit = await api.item({ method: 'PUT', authorization: bearer(B), id: A_NOTE,
    body: { title: '가로챔', body: '바뀜', owner_id: B, userId: B, role: 'admin' } });
  assert.deepEqual([edit.status, edit.body], [403, { error: 'FORBIDDEN' }]);
  const remove = await api.item({ method: 'DELETE', authorization: bearer(B), id: A_NOTE });
  assert.deepEqual([remove.status, remove.body], [403, { error: 'FORBIDDEN' }]);
  // 주인 없는 처음 메모도 누구나 고칠 수 없습니다.
  assert.equal((await api.item({ method: 'PUT', authorization: bearer(A), id: NO_OWNER, body: { title: 'x', body: 'y' } })).status, 403);
  assert.equal((await api.item({ method: 'DELETE', authorization: bearer(A), id: NO_OWNER })).status, 403);
  // 없는 id는 그대로 404입니다.
  assert.equal((await api.item({ method: 'DELETE', authorization: bearer(A), id: randomUUID() })).status, 404);
  assert.equal(JSON.stringify(rows), before);
});

test('step 4: an owner change in the body is ignored and the new row keeps the verified owner', async () => {
  const rows = seedRows();
  const api = makeApi({ rows });
  const edit = await api.item({ method: 'PUT', authorization: bearer(A), id: A_NOTE,
    body: { title: '고친 제목', body: '고친 본문', owner_id: B } });
  assert.deepEqual([edit.status, edit.body], [200, { id: A_NOTE, title: '고친 제목', body: '고친 본문' }]);
  assert.equal(rows.find(row => row.id === A_NOTE).owner_id, A);
  assert.equal(rows.find(row => row.id === B_NOTE).owner_id, B);
  // 새 메모를 B의 소유자로 넣어 달라고 해도(본문·쿼리) 확인된 ID로 저장됩니다.
  const created = await api.list({ method: 'POST', authorization: bearer(A), body: { title: '새 메모', body: '본문', owner_id: B } });
  assert.equal(created.status, 201);
  assert.equal(rows.find(row => row.id === created.body.id).owner_id, A);
  // B가 A의 메모와 같은 id로 만들려 해도 덮어쓰지 못합니다(409).
  const clash = await api.list({ method: 'POST', authorization: bearer(B), body: { id: A_NOTE, title: 'x', body: 'y' } });
  assert.equal(clash.status, 409);
  assert.equal(rows.find(row => row.id === A_NOTE).title, '고친 제목');
});

test('step 4: A and B can still add, read, edit and delete their own notes', async () => {
  const rows = seedRows();
  const api = makeApi({ rows });
  assert.deepEqual((await api.item({ method: 'PUT', authorization: bearer(B), id: B_NOTE, body: { title: 'B 수정', body: 'B 새 본문' } })).body,
    { id: B_NOTE, title: 'B 수정', body: 'B 새 본문' });
  assert.equal((await api.item({ method: 'DELETE', authorization: bearer(B), id: B_NOTE })).status, 200);
  assert.equal((await api.item({ authorization: bearer(B), id: B_NOTE })).status, 404);
  assert.deepEqual((await api.item({ method: 'DELETE', authorization: bearer(A), id: A_NOTE })).body, { id: A_NOTE });
  assert.deepEqual(rows.map(row => row.id), [NO_OWNER]);
});

test('step 4: the API code reads no owner from the request and the config lists the real methods and paths', () => {
  const code = readFileSync(new URL('../src/notes-api.mjs', import.meta.url), 'utf8').replace(/\/\/.*$/gmu, '');
  // owner_id는 서버가 확인한 userId에서만 옵니다. request.* 에서 owner를 읽는 코드가 없어야 합니다.
  assert.equal(/request\.(query|body|headers)[^;\n]*owner|req\.[^;\n]*owner/iu.test(code), false);
  assert.equal((code.match(/\.eq\('owner_id', userId\)/gu) ?? []).length, 4);
  assert.deepEqual(realConfig.allowedRoutes, ['GET /api/notes', 'POST /api/notes',
    'GET /api/notes/:id', 'PUT /api/notes/:id', 'DELETE /api/notes/:id', 'POST /api/login', 'POST /api/refresh']);
});

test('step 4 SQL files: owner link uses auth.users by email, RLS file revokes then grants four rights with own-row policies', () => {
  const owner = readFileSync(new URL('../sql/4-notes-owner.sql', import.meta.url), 'utf8');
  const rlsFull = readFileSync(new URL('../sql/4-notes-rls.sql', import.meta.url), 'utf8');
  const rls = rlsFull.replace(/--.*$/gmu, '');
  assert.match(owner, /from auth\.users where lower\(email\) = lower\('<<A_EMAIL>>'\)/u);
  assert.match(owner, /from auth\.users where lower\(email\) = lower\('<<B_EMAIL>>'\)/u);
  assert.equal(/@[a-z0-9-]+\.[a-z]{2,}/iu.test(owner + rls), false);
  assert.match(rls, /revoke all on table public\.notes from public, anon, authenticated;/u);
  assert.match(rls, /grant select, insert, update, delete on table public\.notes to authenticated;/u);
  assert.equal((rls.match(/create policy/gu) ?? []).length, 4);
  assert.equal((rls.match(/auth\.uid\(\) = owner_id/gu) ?? []).length, 5);
  assert.match(rls, /for update to authenticated\s+using \(auth\.uid\(\) = owner_id\)\s+with check \(auth\.uid\(\) = owner_id\)/u);
  assert.match(rls, /for insert to authenticated\s+with check/u);
  assert.equal(/\b(alter|drop|truncate)\s+table\s+(?!public\.notes\b)/iu.test(rls), false);
  assert.match(rls, /information_schema\.role_table_grants/u);
  assert.match(rls, /has_table_privilege/u);
});

test('step 4 attack check adds a direct anon Data API probe and leaves cross-owner probes as not run', async () => {
  const originalFetch = globalThis.fetch;
  const sent = [];
  const run = async (dataApi) => {
    sent.length = 0;
    globalThis.fetch = async (url, init = {}) => {
      const u = new URL(String(url));
      sent.push({ host: u.host, path: u.pathname + u.search, method: init.method ?? 'GET', apikey: init.headers?.apikey });
      if (u.host.endsWith('.supabase.co')) return dataApi();
      if (u.pathname === '/') return new Response('<script>const k="sb_publishable_TESTKEY123456"</script>', { status: 200 });
      if (u.pathname === '/data.json') return new Response('Not Found', { status: 404 });
      if (u.pathname === '/aleph.json') return new Response(JSON.stringify({ step: 4 }), { status: 200 });
      return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED' }), { status: 401 });
    };
    return runAttackChecks({ ...config, step: 4, identityProvider: realConfig.identityProvider });
  };
  try {
    const denied = await run(() => new Response(JSON.stringify({ code: '42501', message: 'permission denied for table notes' }), { status: 401 }));
    const ids = denied.map(item => item.attackId);
    assert.ok(ids.length <= 20 && new Set(ids).size === ids.length);
    assert.ok(denied.every(item => Object.keys(item).sort().join() === 'attackId,expected,observed'));
    const direct = denied.find(item => item.attackId === 'anon_data_api_notes_refused');
    assert.match(direct.observed, /^거부됨 \(HTTP 401/u);
    const probe = sent.find(item => item.host.endsWith('.supabase.co'));
    assert.deepEqual([probe.method, probe.path, probe.apikey],
      ['GET', '/rest/v1/notes?select=id&limit=1', 'sb_publishable_TESTKEY123456']);
    for (const id of ['other_owner_read_refused', 'other_owner_update_refused', 'other_owner_delete_refused']) {
      assert.match(denied.find(item => item.attackId === id).observed, /^미실행/u);
    }
    const open = await run(() => new Response(JSON.stringify([{ id: 'x', title: '가상 제목' }]), { status: 200 }));
    assert.match(open.find(item => item.attackId === 'anon_data_api_notes_refused').observed, /^거부되지 않음 \(HTTP 200, 메모 1건 이상/u);
    assert.equal(JSON.stringify(open).includes('가상 제목'), false);
    const proxy = await run(() => new Response('Host not in allowlist', { status: 403 }));
    assert.match(proxy.find(item => item.attackId === 'anon_data_api_notes_refused').observed, /^확인하지 못함/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 5: the direct probe uses originalApiUrl, and the revoke SQL touches only notes and revokes nothing from service_role', async () => {
  const sql = readFileSync(new URL('../sql/5-notes-revoke-direct.sql', import.meta.url), 'utf8').replace(/--.*$/gmu, '');
  assert.match(sql, /revoke all on table public\.notes from public, anon, authenticated;/u);
  assert.equal(/\bgrant\b|\bdrop\b|\btruncate\b|\bfrom\b[^;]*service_role/iu.test(sql.replace(/select[^;]*;/giu, '')), false);
  assert.equal(/\b(alter|drop|truncate|revoke)\s+(table\s+)?(?!(all on table )?public\.notes\b)/iu.test(sql), false);
  const originalFetch = globalThis.fetch;
  const sent = [];
  globalThis.fetch = async (url) => {
    const u = new URL(String(url));
    sent.push(u.host + u.pathname + u.search);
    if (u.host.endsWith('.supabase.co')) return new Response(JSON.stringify({ code: '42501' }), { status: 401 });
    if (u.pathname === '/') return new Response('sb_publishable_TESTKEY123456', { status: 200 });
    if (u.pathname === '/data.json') return new Response('Not Found', { status: 404 });
    return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED' }), { status: 401 });
  };
  try {
    const out = await runAttackChecks({ ...config, ...realConfig });
    assert.ok(sent.includes('vskaxngivuhucmbnoagz.supabase.co/rest/v1/notes?select=id&limit=1'));
    assert.match(out.find(item => item.attackId === 'anon_data_api_notes_refused').observed, /^거부됨/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

// ---- 5단계: 서버 로그인 ----
const { createAuthApi } = await import('../src/auth-api.mjs');
const fakeAuth = (upstream) => {
  const sent = [];
  const api = createAuthApi({
    getSettings: () => ({ url: 'https://example-project.supabase.co', secretKey: 'fake-server-key-for-test' }),
    fetchImpl: async (url, init) => { sent.push({ url, init }); return upstream(url, init); },
  });
  const call = async (handler, { method = 'POST', body } = {}) => {
    const out = { headers: {} };
    const response = { setHeader: (k, v) => { out.headers[k] = v; },
      status: (code) => { out.status = code; return { json: (b) => { out.body = b; return out; } }; } };
    return handler({ method, body }, response);
  };
  return { api, sent, call };
};
const goodSession = () => new Response(JSON.stringify({ access_token: 'AT', refresh_token: 'RT', expires_at: 1900000000,
  expires_in: 3600, token_type: 'bearer', user: { id: A, email: 'a@test.invalid', role: 'authenticated' } }), { status: 200 });

test('step 5 server login: sends the password only to the Supabase token URL and returns just the session fields', async () => {
  const { api, sent, call } = fakeAuth(goodSession);
  const result = await call(api.login, { body: { email: ' a@test.invalid ', password: 'pw-for-test', owner_id: B } });
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, { access_token: 'AT', refresh_token: 'RT', expires_at: 1900000000, email: 'a@test.invalid' });
  assert.equal(result.headers['Cache-Control'], 'no-store');
  assert.equal(sent.length, 1);
  assert.equal(sent[0].url, 'https://example-project.supabase.co/auth/v1/token?grant_type=password');
  assert.deepEqual(JSON.parse(sent[0].init.body), { email: 'a@test.invalid', password: 'pw-for-test' });
  const refreshed = await call(api.refresh, { body: { refresh_token: 'RT' } });
  assert.equal(refreshed.status, 200);
  assert.equal(sent[1].url, 'https://example-project.supabase.co/auth/v1/token?grant_type=refresh_token');
});

test('step 5 server login: wrong password, bad input, wrong method, upstream failure and missing settings all stay closed', async () => {
  const wrong = fakeAuth(() => new Response(JSON.stringify({ error_code: 'invalid_credentials', msg: 'secret detail' }), { status: 400 }));
  const denied = await wrong.call(wrong.api.login, { body: { email: 'a@test.invalid', password: 'x' } });
  assert.equal(denied.status, 401);
  assert.deepEqual(denied.body, { error: 'LOGIN_FAILED', reason: 'invalid_credentials' });
  const odd = fakeAuth(() => new Response(JSON.stringify({ error_code: 'something_internal' }), { status: 400 }));
  assert.equal((await odd.call(odd.api.login, { body: { email: 'a@test.invalid', password: 'x' } })).body.reason, 'unknown');
  const refreshDenied = await wrong.call(wrong.api.refresh, { body: { refresh_token: 'old' } });
  assert.deepEqual([refreshDenied.status, refreshDenied.body.error], [401, 'LOGIN_REQUIRED']);
  for (const body of [undefined, {}, { email: 'not-an-email', password: 'x' }, { email: 'a@test.invalid' },
    { email: 'a@test.invalid', password: 'x'.repeat(300) }, '[]', 'not json']) {
    const r = await wrong.call(wrong.api.login, { body });
    assert.equal(r.status, 400);
  }
  assert.equal(wrong.sent.length, 2);  // 잘못된 입력은 Supabase로 보내지 않았습니다.
  assert.equal((await wrong.call(wrong.api.login, { method: 'GET' })).status, 405);
  const down = fakeAuth(() => { throw new Error('network'); });
  assert.equal((await down.call(down.api.login, { body: { email: 'a@test.invalid', password: 'x' } })).status, 502);
  const html500 = fakeAuth(() => new Response('oops', { status: 500 }));
  assert.equal((await html500.call(html500.api.login, { body: { email: 'a@test.invalid', password: 'x' } })).status, 502);
  const none = createAuthApi({ getSettings: () => { throw new Error('missing_env'); }, fetchImpl: () => assert.fail('no call') });
  const closed = await fakeAuth(goodSession).call(none.login, { body: { email: 'a@test.invalid', password: 'x' } });
  assert.deepEqual([closed.status, closed.body], [500, { error: 'SERVER_NOT_CONFIGURED' }]);
  const text = JSON.stringify([denied, refreshDenied]);
  assert.equal(/secret detail|fake-server-key/u.test(text), false);
});

test('step 5: /aleph.json lists the allowed routes and the original API address; the page has no key', () => {
  const identity = deploymentIdentity(env, { ...realConfig, step: 5 });
  assert.deepEqual(identity.allowedRoutes, realConfig.allowedRoutes);
  assert.equal(identity.originalApiUrl, realConfig.originalApiUrl);
  assert.equal(findSecrets([['aleph.json', JSON.stringify(identity)]]).length, 0);
  assert.equal('allowedRoutes' in deploymentIdentity(env, { ...realConfig, step: 2 }), false);
  assert.equal('originalApiUrl' in deploymentIdentity(env, { ...realConfig, step: 4 }), false);
  assert.equal('allowedRoutes' in deploymentIdentity(env, { ...realConfig, allowedRoutes: ['bad route'] }), false);
});

test('step 5 attack check: with no key in the page the direct probe is not run, and a wrong-password login probe is refused', async () => {
  const originalFetch = globalThis.fetch;
  const sent = [];
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    sent.push(`${init.method ?? 'GET'} ${u.host}${u.pathname}`);
    if (u.pathname === '/') return new Response('<html>no key here</html>', { status: 200 });
    if (u.pathname === '/data.json') return new Response('Not Found', { status: 404 });
    if (u.pathname === '/api/login') return new Response(JSON.stringify({ error: 'LOGIN_FAILED' }), { status: 401 });
    return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED' }), { status: 401 });
  };
  try {
    const out = await runAttackChecks({ ...config, ...realConfig });
    assert.ok(out.length <= 20);
    assert.match(out.find(i => i.attackId === 'anon_data_api_notes_refused').observed, /^미실행/u);
    assert.equal(out.find(i => i.attackId === 'wrong_password_login_refused').observed, '거부됨 (HTTP 401)');
    assert.equal(sent.some(item => item.includes('supabase.co')), false);
    assert.equal(JSON.stringify(out).includes('wrong-password-for-check'), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
