import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
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
  const run = async (alephBody) => {
    globalThis.fetch = async (url) => {
      const path = new URL(String(url)).pathname;
      asked.push(path);
      const body = path === '/data.json' ? { notes: [] }
        : path === '/aleph.json' ? alephBody
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
    assert.match(results[0].observed, /0건/u);
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
