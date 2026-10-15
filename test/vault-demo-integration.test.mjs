import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createContext, runInContext } from 'node:vm';
import { protectDeviceRequests } from '../src/protected-device-handler.mjs';
import { createDemoVerifier } from '../src/demo-runtime.mjs';
import { buildOperationsSummary } from '../src/operations-summary.mjs';
import { RULE_IDS } from '../src/decider.mjs';

test('existing vault requests stay hidden pending, then show existing notes and preserve CRUD request handles', async () => {
  const source = async name => readFile(new URL('../public/' + name, import.meta.url), 'utf8');
  const nodes = new Map(), timers = [], calls = [];
  const makeNode = () => ({ hidden: true, textContent: '', value: '', disabled: false, children: [], listeners: {},
    addEventListener(event, fn) { this.listeners[event] = fn; }, reset() {}, focus() {}, scrollIntoView() {},
    replaceChildren(...children) { this.children = children; }, append(...children) { this.children.push(...children); } });
  const node = id => { if (!nodes.has(id)) nodes.set(id, makeNode()); return nodes.get(id); };
  let session = { user: { id: 'fixture-a' }, access_token: 'fixture-login' }, authListener, state = 'unregistered';
  const note = { id: '00000000-0000-4000-8000-000000000001', title: 'existing-title', body: 'existing-body' };
  const context = createContext({ AbortSignal, document: { querySelector: node, createElement: makeNode },
    window: { addEventListener() {}, confirm: () => true }, setTimeout: fn => timers.push(fn),
    suppliedAuth: { getSession: async () => ({ data: { session } }),
      onAuthStateChange: fn => { authListener = fn; fn('SIGNED_IN', session); },
      signOut: async () => { session = null; authListener('SIGNED_OUT', null); return {}; } },
    fetch: async (path, options) => {
      calls.push({ path, ...options });
      if (path === '/api/demo-device') {
        if (options.method === 'POST') {
          state = 'pending';
          return { ok: true, status: 201, json: async () => ({ demo: true, state, sessionToken: 'a'.repeat(43) }) };
        }
        return { ok: true, status: 200, json: async () => ({ demo: true, state }) };
      }
      assert.equal(state, 'approved');
      assert.equal(options.headers['X-Demo-Session'], 'a'.repeat(43));
      if (path === '/api/operations-summary') return { ok: true, status: 200,
        json: async () => buildOperationsSummary({ ruleIds: RULE_IDS, rows: [] }) };
      assert.ok(path.startsWith('/api/notes'));
      if (options.method === 'DELETE') return { ok: true, status: 204, json() { throw new Error('204 must not parse JSON'); } };
      return { ok: true, status: 200, json: async () => path === '/api/notes' && options.method === 'GET' ? [note] : note };
    } });
  runInContext((await source('demo-device-client.js')).replace('export function ', 'function '), context);
  runInContext((await source('device-approval.js')).replace(/^import.*$/m, '').replace('export function ', 'function '), context);
  runInContext((await source('operations-panel.js')).replaceAll('export function ', 'function '), context);
  const html = await source('index.html');
  assert.doesNotMatch(html, /가상 자료로 서버 승인 데모 체험하기|href="\/demo-approval.html"/);
  const code = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1]
    .replace("import { createDeviceApproval } from '/device-approval.js';", '')
    .replace("import { createOperationsPanel } from '/operations-panel.js';", '')
    .replace("const { createBrowserAuth } = await import('/auth-client.js');", 'const createBrowserAuth = () => suppliedAuth;');
  await runInContext('(async () => {' + code + '})()', context);
  for (const timer of timers) await timer();
  await node('#device-request').listeners.click();
  assert.equal(node('#notes').hidden, true); assert.equal(calls.some(c => c.path === '/api/notes'), false);
  assert.equal(node('#operations-room').hidden, true);
  state = 'approved'; await node('#device-refresh').listeners.click();
  assert.equal(node('#notes').hidden, false); assert.equal(node('#notes').children[0].children[0].textContent, note.title);
  assert.equal(node('#operations-room').hidden, false);
  await node('#ops-refresh').listeners.click();
  assert.match(node('#ops-rules').textContent, /3개/);
  assert.match(node('#ops-detection').textContent, /미실행/);
  const evidence = JSON.parse(node('#ops-evidence').textContent);
  assert.equal(evidence.rules.length, RULE_IDS.length); assert.equal(evidence.records.length, 0);
  node('#note-title').value = 'updated'; node('#note-body').value = 'new-body';
  await node('#note-form').listeners.submit({ preventDefault() {} });
  assert.ok(calls.some(c => c.path === '/api/notes' && c.method === 'POST'));
  const buttons = node('#notes').children[0].children[2].children;
  await buttons[0].listeners.click();
  await node('#note-form').listeners.submit({ preventDefault() {} });
  assert.ok(calls.some(c => c.path.endsWith(note.id) && c.method === 'PUT'));
  await node('#notes').children[0].children[2].children[1].listeners.click();
  assert.ok(calls.some(c => c.path.endsWith(note.id) && c.method === 'DELETE'));
  state = 'revoked'; await node('#device-refresh').listeners.click();
  assert.equal(node('#notes').hidden, true); assert.equal(node('#notes').children.length, 0);
  assert.equal(node('#operations-room').hidden, true); assert.equal(node('#ops-evidence').textContent, '');
  await node('#logout-button').listeners.click();
  assert.equal(node('#note-form').hidden, true);
});

test('verified demo access invokes existing authorization; forged claims and storage failures do not', async () => {
  const userId = '00000000-0000-4000-8000-000000000001';
  let state = 'pending', calls = 0;
  const actor = { kind: 'student', userId };
  const verify = createDemoVerifier({ env: { DEMO_APPROVAL_ADMIN_IDS: userId },
    getStore: async () => ({ find: async (owner, hash) => {
      assert.equal(owner, userId); assert.match(hash, /^[a-f0-9]{64}$/); return { state };
    } }) });
  const handler = protectDeviceRequests({ config: { step: 11 }, verifyLogin: async () => actor,
    verifyDemoAccess: verify, handler: async (_req, res) => { calls++; return res.status(404).json({ error: 'resource_forbidden' }); } });
  const req = { headers: { authorization: 'fixture', 'x-demo-session': 'a'.repeat(43), 'x-device-registered': 'true' }, body: { approved: true } };
  const response = () => ({ setHeader() {}, status(code) { this.code = code; return this; }, json(data) { this.data = data; return this; } });
  let res = response(); await handler(req, res); assert.equal(res.code, 403); assert.equal(calls, 0);
  state = 'approved'; res = response(); await handler(req, res);
  assert.equal(calls, 1); assert.equal(res.code, 404); // Existing resource denial is not overridden by demo approval.
  delete req.headers['x-demo-session']; res = response(); await handler(req, res); assert.equal(res.code, 403); assert.equal(calls, 1);
  const broken = protectDeviceRequests({ config: { step: 11 }, verifyLogin: async () => actor,
    verifyDemoAccess: async () => { throw new Error('storage unavailable'); }, handler: async () => calls++ });
  res = response(); await broken(req, res); assert.equal(res.code, 403); assert.equal(calls, 1);
});
