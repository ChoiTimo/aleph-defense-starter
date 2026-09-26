import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const fixtureDir = resolve(import.meta.dirname, '../xdr/fixtures');
const modules = ['brute-force', 'web-injection', 'known-cve', 'persistence',
  'privilege', 'exfiltration'];

test('XDR 합성 경보 6종과 정답표가 빠짐없이 맞는다', async () => {
  const key = JSON.parse(await readFile(resolve(fixtureDir, 'answer-key.json'), 'utf8'));
  assert.equal(key.synthetic, true);
  const ids = [];
  for (const moduleKey of modules) {
    const fixture = JSON.parse(await readFile(resolve(fixtureDir, `${moduleKey}.json`), 'utf8'));
    assert.equal(fixture.schema, 'aleph.xdr.synthetic-wazuh.v1');
    assert.equal(fixture.synthetic, true);
    assert.equal(fixture.moduleKey, moduleKey);
    assert.equal(fixture.alerts.length, 3);
    const decisions = fixture.alerts.map((alert) => {
      assert.match(alert.id, /^[a-z]{2}-\d{3}$/u);
      assert.ok(Number.isFinite(Date.parse(alert.timestamp)));
      assert.ok(alert.agent?.id && alert.rule?.id && alert.rule?.description);
      assert.ok(Number.isInteger(alert.rule.level));
      assert.ok(alert.data?.srcip && alert.data?.user);
      ids.push(alert.id);
      return key.cases[alert.id];
    });
    assert.deepEqual(decisions, ['block_candidate', 'alert', 'record']);
  }
  assert.equal(new Set(ids).size, 18);
  assert.deepEqual(Object.keys(key.cases).sort(), ids.sort());
});
