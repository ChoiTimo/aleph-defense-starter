import { randomUUID } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
export const OPERATIONS_RECORD_LIMIT = 100;

export function redactOperationsRecords(rows) {
  if (!Array.isArray(rows) || rows.length > OPERATIONS_RECORD_LIMIT) throw new Error('invalid_operations_records');
  const ids = new Set();
  return rows.map(row => {
    if (!row || !UUID.test(row.id ?? '') || ids.has(row.id) || !TIME.test(row.at ?? '')
        || !Number.isFinite(Date.parse(row.at)) || new Date(row.at).toISOString() !== row.at
        || !['note_restore', 'demo_revocation'].includes(row.kind)
        || (row.kind === 'note_restore' ? !HASH.test(row.version ?? '') : row.version !== null))
      throw new Error('invalid_operations_records');
    ids.add(row.id);
    // No request bodies, identities, device handles, note IDs or full backup hashes.
    return { id: row.id, at: row.at, kind: row.kind, source: 'confirmed_api_result',
      version: row.kind === 'note_restore' ? `sha256:${row.version.slice(0, 12)}` : null };
  }).sort((a, b) => b.at.localeCompare(a.at) || b.id.localeCompare(a.id));
}

export function buildOperationsSummary({ ruleIds, rows, observedAt = new Date().toISOString(), snapshotId = randomUUID() }) {
  if (!Array.isArray(ruleIds) || ruleIds.some(id => !/^[a-z][a-z0-9_.-]{0,79}$/.test(id))
      || new Set(ruleIds).size !== ruleIds.length) throw new Error('invalid_operations_rules');
  const records = rows === null ? null : redactOperationsRecords(rows);
  const restores = records?.filter(row => row.kind === 'note_restore');
  const demoRevocations = records?.filter(row => row.kind === 'demo_revocation');
  return {
    schema: 'aleph.operations-summary.v1', snapshotId, observedAt,
    window: { status: records === null ? 'unavailable' : 'confirmed', limit: OPERATIONS_RECORD_LIMIT,
      count: records?.length ?? null },
    rules: { status: 'confirmed', count: ruleIds.length, ruleIds: [...ruleIds], source: 'server_code',
      runtimeDecisionCount: null },
    detection: { status: 'not_run', count: null, reasonCode: 'engine_event_feed_not_connected' },
    revocation: { status: 'not_run', count: null, reasonCode: 'engine_revocation_not_connected',
      demoConfirmedCount: demoRevocations?.length ?? null },
    recovery: { status: records === null ? 'unavailable' : restores.length ? 'confirmed' : 'not_run',
      count: restores?.length ?? null, lastVersion: restores?.[0]?.version ?? null,
      policy: { status: 'not_run', version: null, reasonCode: 'trial_policy_audit_not_connected' } },
    evidence: { rules: { kind: 'rule_inventory', source: 'server_code', ruleIds: [...ruleIds] }, records },
  };
}

export function createOperationsHandler({ verifyLogin, verifyDemoAccess, loadRecords, ruleIds, env = process.env }) {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const fail = (code, reasonCode) => res.status(code).json({ error: '작전실 요약을 확인할 수 없습니다.', reasonCode });
    if (req.method !== 'GET') { res.setHeader('Allow', 'GET'); return fail(405, 'method_not_allowed'); }
    let url;
    try { url = new URL(req.url, 'https://local.invalid'); } catch { return fail(404, 'resource_not_allowed'); }
    if (url.pathname !== '/api/operations-summary' || url.search) return fail(404, 'resource_not_allowed');
    if (!req.headers.authorization) return fail(401, 'login_required');
    let actor;
    try { actor = await verifyLogin(req.headers.authorization); } catch {}
    if (actor?.kind !== 'student' || !UUID.test(actor.userId ?? '')) return fail(401, 'invalid_login');
    const admins = (env.DEMO_APPROVAL_ADMIN_IDS ?? '').split(',').map(s => s.trim().toLowerCase());
    if (!admins.includes(actor.userId.toLowerCase())) return fail(403, 'admin_required');
    try { if (await verifyDemoAccess(req, actor) !== true) return fail(403, 'demo_not_approved'); }
    catch { return fail(503, 'approval_unavailable'); }
    let summary;
    try {
      summary = buildOperationsSummary({ ruleIds, rows: await loadRecords() });
    } catch {
      // Missing/unreadable/invalid audit is unknown, never zero confirmed operations.
      try { summary = buildOperationsSummary({ ruleIds, rows: null }); }
      catch { return fail(503, 'summary_unavailable'); }
    }
    return res.status(200).json(summary);
  };
}
