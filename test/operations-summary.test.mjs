import test from 'node:test';
import assert from 'node:assert/strict';
import { buildOperationsSummary, createOperationsHandler } from '../src/operations-summary.mjs';
import { operationsView, createOperationsPanel } from '../public/operations-panel.js';
import endpoint from '../api/operations-summary.js';
import { createDemoHandler } from '../src/demo-approval.mjs';
import { createOperationsStore } from '../src/operations-store.mjs';
import { readFile } from 'node:fs/promises';

const ADMIN = '00000000-0000-4000-8000-000000000001';
const USER = '00000000-0000-4000-8000-000000000002';
const ruleIds = ['device_registered', 'step_up_required', 'resource_scope'];
const row = (id, kind = 'note_restore', version = 'a'.repeat(64)) => ({
  id: `00000000-0000-4000-8000-${String(id).padStart(12, '0')}`, at: `2026-10-15T01:00:0${id}.000Z`, kind,
  version: kind === 'note_restore' ? version : null,
});
const response = () => ({ headers: {}, setHeader(key, value) { this.headers[key] = value; },
  status(code) { this.code = code; return this; }, json(data) { this.data = data; return this; } });
function handler(options = {}) {
  return createOperationsHandler({ ruleIds, env: { DEMO_APPROVAL_ADMIN_IDS: ADMIN },
    verifyLogin: async authorization => ({ kind: 'student', userId: authorization === 'admin' ? ADMIN : USER }),
    verifyDemoAccess: async () => true, loadRecords: async () => [], ...options });
}
test('summary metrics and UI labels match the same redacted server evidence', async () => {
  const rows = [row(1), row(2, 'demo_revocation'), row(3, 'note_restore', 'b'.repeat(64))];
  Object.defineProperty(rows[0], 'body', { get() { throw new Error('must never read note contents'); } });
  rows[0].authorization = 'private-marker'; rows[0].ownerId = 'identity-marker';
  const res = response();
  await handler({ loadRecords: async () => rows })({ method: 'GET', url: '/api/operations-summary', headers: { authorization: 'admin' } }, res);
  assert.equal(res.code, 200); assert.equal(res.headers['Cache-Control'], 'no-store');
  assert.equal(res.data.rules.count, 3); assert.equal(res.data.window.count, 3);
  assert.equal(res.data.recovery.count, 2); assert.equal(res.data.recovery.lastVersion, 'sha256:bbbbbbbbbbbb');
  assert.equal(res.data.revocation.demoConfirmedCount, 1); assert.equal(res.data.revocation.count, null);
  assert.equal(res.data.detection.count, null); assert.equal(res.data.detection.status, 'not_run');
  const view = operationsView(res.data);
  assert.match(view.rules, /3개/); assert.match(view.recovery, /2건/); assert.match(view.demoRevocation, /1건/);
  assert.equal(view.evidence.records.filter(r => r.kind === 'note_restore').length, res.data.recovery.count);
  assert.doesNotMatch(JSON.stringify(res.data), /private-marker|identity-marker|authorization|ownerId|"body"/);
  assert.doesNotMatch(JSON.stringify(view.evidence), /a{64}|b{64}/);
});
test('no runtime connector is not represented as zero successful events or real revocations', () => {
  const empty = buildOperationsSummary({ ruleIds, rows: [] });
  assert.equal(empty.recovery.status, 'not_run'); assert.equal(empty.recovery.count, 0);
  assert.equal(empty.detection.count, null); assert.equal(empty.revocation.count, null);
  assert.match(operationsView(empty).recovery, /미실행/);
  const unknown = buildOperationsSummary({ ruleIds, rows: null });
  assert.equal(unknown.recovery.status, 'unavailable'); assert.equal(unknown.recovery.count, null);
  assert.equal(unknown.revocation.demoConfirmedCount, null); assert.match(operationsView(unknown).note, /0건으로 집계하지/);
});
test('bad audit data and unavailable storage produce unknown counts, without leaking errors', async () => {
  for (const loadRecords of [async () => { throw new Error('secret-debug'); },
    async () => [{ ...row(1), version: 'invalid' }], async () => [row(1), row(1)]]) {
    const res = response();
    await handler({ loadRecords })({ method: 'GET', url: '/api/operations-summary', headers: { authorization: 'admin' } }, res);
    assert.equal(res.code, 200); assert.equal(res.data.window.status, 'unavailable');
    assert.equal(res.data.recovery.count, null); assert.equal(res.data.evidence.records, null);
    assert.doesNotMatch(JSON.stringify(res.data), /secret-debug/);
  }
});
test('summary requires a verified administrator and approved page; browsers cannot post records', async () => {
  let loads = 0;
  const send = async (req, extra = {}) => { const res = response(); await handler({ loadRecords: async () => { loads++; return []; }, ...extra })(req, res); return res; };
  const req = { method: 'GET', url: '/api/operations-summary', headers: { authorization: 'admin' } };
  assert.equal((await send({ ...req, headers: {} })).code, 401);
  assert.equal((await send({ ...req, headers: { authorization: 'user' } })).code, 403);
  assert.equal((await send(req, { verifyDemoAccess: async () => false })).code, 403);
  assert.equal((await send(req, { verifyDemoAccess: async () => { throw new Error(); } })).code, 503);
  assert.equal((await send({ ...req, method: 'POST', body: { count: 99 } })).code, 405);
  assert.equal((await send({ ...req, url: '/api/operations-summary?count=99' })).code, 404);
  assert.equal(loads, 0);
  const res = response(); await endpoint({ method: 'GET', url: '/api/operations-summary', headers: {} }, res);
  assert.equal(res.code, 401);
});
test('UI refuses mismatched counts and projects only redacted record fields', () => {
  const make = () => buildOperationsSummary({ ruleIds, rows: [row(1)] });
  for (const mutate of [s => { s.rules.count++; }, s => { s.recovery.count++; },
    s => { s.window.count++; }, s => { s.revocation.count = 1; }, s => { s.recovery.lastVersion = 'wrong'; }]) {
    const summary = make(); mutate(summary); assert.throws(() => operationsView(summary), /일치하지/);
  }
  const extra = make(); extra.evidence.records[0].body = 'hidden-note-body';
  assert.doesNotMatch(JSON.stringify(operationsView(extra).evidence), /hidden-note-body/);
});
test('panel clears old metrics on errors and ignores a late response after reset', async () => {
  const nodes = new Map();
  const find = id => { if (!nodes.has(id)) nodes.set(id, { textContent: '', disabled: false, addEventListener() {} }); return nodes.get(id); };
  let result = buildOperationsSummary({ ruleIds, rows: [row(1)] }), suspended;
  const panel = createOperationsPanel({ find, request: async () => { if (suspended) await suspended; if (!result) throw new Error(); return result; } });
  await panel.refresh(); assert.match(find('ops-recovery').textContent, /1건/);
  assert.equal(JSON.parse(find('ops-evidence').textContent).records.length, 1);
  result = null; await panel.refresh(); assert.equal(find('ops-recovery').textContent, '확인 불가'); assert.equal(find('ops-evidence').textContent, '');
  result = buildOperationsSummary({ ruleIds, rows: [row(1)] });
  let release; suspended = new Promise(done => { release = done; });
  const old = panel.refresh(); panel.reset(); release(); await old;
  assert.equal(find('ops-recovery').textContent, '미조회'); assert.equal(find('ops-evidence').textContent, '');
});
test('confirmed demo revoke API results enter the same evidence used by the summary', async () => {
  const records=[];
  const revoke=createDemoHandler({ env:{DEMO_APPROVAL_ADMIN_IDS:ADMIN},
    verifyLogin:async()=>({kind:'student',userId:ADMIN}),
    getStore:async()=>({transition:async()=>({id:USER,state:'revoked',created_at:'2026-10-15T01:00:00.000Z'})}),
    onConfirmedRevocation:async()=>records.push(row(1,'demo_revocation')) });
  const res=response();
  await revoke({method:'POST',url:'/api/demo-device',headers:{authorization:'admin'},body:{action:'revoke',requestId:USER}},res);
  assert.equal(res.code,200);assert.equal(res.data.state,'revoked');assert.equal(records.length,1);
  const summary=response();
  await handler({loadRecords:async()=>records})({method:'GET',url:'/api/operations-summary',headers:{authorization:'admin'}},summary);
  assert.equal(summary.data.revocation.demoConfirmedCount,1);
  assert.equal(summary.data.revocation.count,null);assert.equal(summary.data.revocation.status,'not_run');
  assert.match(operationsView(summary.data).demoRevocation,/1건/);
});
test('audit store writes only fixed metadata and reads a bounded private inventory', async()=>{
  const inserted=[],calls=[];
  const q={order(...args){calls.push(['order',...args]);return q;},limit(n){calls.push(['limit',n]);return Promise.resolve({data:[{...row(1),at:'2026-10-15T01:00:01+00:00'}],error:null});}};
  const store=createOperationsStore({from(table){assert.equal(table,'operations_audit');return {
    insert:async record=>{inserted.push(record);return {error:null};},
    select:columns=>{assert.equal(columns,'id,at,kind,version');return q;},
  };}});
  await store.append({kind:'note_restore',version:'a'.repeat(64),body:'must-not-store'});
  assert.deepEqual(Object.keys(inserted[0]).sort(),['at','id','kind','version']);
  const records=await store.list();assert.equal(records[0].at,'2026-10-15T01:00:01.000Z');
  assert.ok(calls.some(c=>c[0]==='limit'&&c[1]===100));
  await assert.rejects(()=>store.append({kind:'note_restore',version:null}));
  await assert.rejects(()=>store.append({kind:'detection',version:null}));
  const sql=await readFile(new URL('../docs/OPERATIONS_AUDIT.sql',import.meta.url),'utf8');
  assert.match(sql,/enable row level security/);assert.match(sql,/revoke all.*from public, anon, authenticated/);
});
