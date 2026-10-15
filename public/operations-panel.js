const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const timestamp = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
  && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
const ruleId = value => typeof value === 'string' && /^[a-z][a-z0-9_.-]{0,79}$/.test(value);
const fail = () => { throw new Error('요약 수치와 가린 서버 기록이 일치하지 않습니다.'); };

// Render only a projected, internally consistent snapshot; never dump raw API JSON.
export function operationsView(data) {
  if (data?.schema !== 'aleph.operations-summary.v1' || !UUID.test(data.snapshotId ?? '')
      || !timestamp(data.observedAt)
      || !Array.isArray(data.evidence?.rules?.ruleIds)
      || data.evidence.rules.ruleIds.some(id => !ruleId(id))) fail();
  const ids = data.evidence.rules.ruleIds;
  if (new Set(ids).size !== ids.length || data.rules?.status !== 'confirmed' || data.rules.source !== 'server_code'
      || data.evidence.rules.kind !== 'rule_inventory' || data.evidence.rules.source !== 'server_code'
      || data.rules.runtimeDecisionCount !== null
      || data.rules.count !== ids.length || JSON.stringify(data.rules.ruleIds) !== JSON.stringify(ids)
      || data.detection?.status !== 'not_run' || data.detection.count !== null
      || data.revocation?.status !== 'not_run' || data.revocation.count !== null
      || data.recovery?.policy?.status !== 'not_run' || data.recovery.policy.version !== null
      || data.window?.limit !== 100) fail();
  const unknown = data.window.status === 'unavailable';
  let records = null;
  if (unknown) {
    if (data.window.count !== null || data.evidence.records !== null || data.recovery?.count !== null
        || data.recovery.status !== 'unavailable' || data.recovery.lastVersion !== null
        || data.revocation.demoConfirmedCount !== null) fail();
  } else {
    if (data.window.status !== 'confirmed' || !Array.isArray(data.evidence.records)
        || data.evidence.records.length > 100 || data.window.count !== data.evidence.records.length) fail();
    const seen = new Set();
    records = data.evidence.records.map(row => {
      if (!UUID.test(row.id ?? '') || seen.has(row.id) || !timestamp(row.at)
          || row.source !== 'confirmed_api_result' || !['note_restore', 'demo_revocation'].includes(row.kind)
          || (row.kind === 'note_restore' ? !/^sha256:[a-f0-9]{12}$/.test(row.version ?? '') : row.version !== null)) fail();
      seen.add(row.id);
      return { id: row.id, at: row.at, kind: row.kind, source: 'confirmed_api_result', version: row.version };
    }).sort((a, b) => b.at.localeCompare(a.at) || b.id.localeCompare(a.id));
    const restored = records.filter(row => row.kind === 'note_restore');
    if (data.recovery?.count !== restored.length || data.recovery.lastVersion !== (restored[0]?.version ?? null)
        || data.recovery.status !== (restored.length ? 'confirmed' : 'not_run')
        || data.revocation.demoConfirmedCount !== records.filter(row => row.kind === 'demo_revocation').length) fail();
  }
  return {
    rules: `${ids.length}개 · 서버 구현 확인`,
    detection: '미실행 · 실제 사건 수집 미연결',
    revocation: '미실행 · 실제 기기 회수 미연결',
    demoRevocation: unknown ? '데모 접속 취소: 기록 조회 불가' : `데모 접속 취소: ${data.revocation.demoConfirmedCount}건`,
    recovery: unknown ? '확인 불가 · 기록 조회 실패' : data.recovery.count ? `${data.recovery.count}건 · API 확인` : '미실행 · 확인된 기록 없음',
    recoveryVersion: `메모 사본: ${data.recovery.lastVersion ?? '확인된 복구 버전 없음'} · 정책 복구: 미실행(격리 시험 기록 미연결)`,
    note: unknown ? '서버 기록을 읽지 못했습니다. 0건으로 집계하지 않습니다.'
      : `최근 저장된 API 확인 기록 ${records.length}건 기준 · 최대 100건 · 전체 이력 합계가 아닙니다.`,
    evidence: { snapshotId: data.snapshotId, observedAt: data.observedAt,
      scope: 'latest_100_stored_api_results', rules: [...ids], records },
  };
}

export function createOperationsPanel({ request, find = id => document.querySelector('#' + id) }) {
  let generation = 0;
  const fields = ['rules', 'detection', 'revocation', 'demo-revocation', 'recovery', 'version'];
  function reset() {
    ++generation;
    find('ops-refresh').disabled = false;
    for (const id of fields) find('ops-' + id).textContent = '미조회';
    find('ops-evidence').textContent = '';
    find('ops-status').textContent = '서버 요약을 아직 조회하지 않았습니다.';
  }
  async function refresh() {
    const version = ++generation;
    find('ops-refresh').disabled = true;
    for (const id of fields) find('ops-' + id).textContent = '조회 중';
    find('ops-evidence').textContent = '';
    find('ops-status').textContent = '서버에서 확인한 결과를 조회하고 있습니다.';
    try {
      const view = operationsView(await request('/api/operations-summary'));
      if (version !== generation) return;
      for (const [id, value] of [['rules', view.rules], ['detection', view.detection], ['revocation', view.revocation],
        ['demo-revocation', view.demoRevocation], ['recovery', view.recovery], ['version', view.recoveryVersion]])
        find('ops-' + id).textContent = value;
      find('ops-status').textContent = view.note;
      find('ops-evidence').textContent = JSON.stringify(view.evidence, null, 2);
    } catch {
      if (version !== generation) return;
      for (const id of fields) find('ops-' + id).textContent = '확인 불가';
      find('ops-status').textContent = '요약 조회 또는 기록 대조에 실패했습니다. 로그인·승인·관리자 권한과 서버 연결을 확인하세요.';
    } finally { if (version === generation) find('ops-refresh').disabled = false; }
  }
  find('ops-refresh').addEventListener('click', refresh);
  reset();
  return { reset, refresh };
}
