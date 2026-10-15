// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step >= 2) return runProtectionChecks(config);
  if (config.step !== 1) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}

async function runProtectionChecks(config) {
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password
      || app.search || app.hash || app.pathname !== '/'
      || !app.hostname.endsWith('.vercel.app')) {
    throw new Error('설정의 실제 Vercel 운영 주소를 확인하세요.');
  }
  const attempts = [];
  async function check(attackId, path, expected, accepts, authorization, method = 'GET') {
    try {
      const response = await fetch(new URL(path, app), {
        method, redirect: 'error',
        signal: AbortSignal.timeout(10000),
        headers: authorization ? { Authorization: authorization } : {},
      });
      let data = null;
      if (/^application\/(?:json|[a-z0-9.+-]+\+json)(?:;|$)/i.test(response.headers.get('content-type') ?? '')) {
        try { data = await response.json(); } catch {}
      }
      const success = accepts(response, data);
      attempts.push({ attackId, expected,
        observed: `HTTP ${response.status}; 직접 점검 ${success ? '통과' : '실패'}` });
    } catch {
      attempts.push({ attackId, expected,
        observed: '요청 실패; 해당 응답 조건은 확인하지 못함' });
    }
  }
  const denied = (response, data) =>
    [401, 403].includes(response.status)
      && typeof data?.error === 'string' && !('notes' in data);
  await check('anonymous_note_read', '/api/notes',
    '무로그인 목록 요청은 401 또는 403 JSON 오류로 거부', denied);
  await check('anonymous_note_item', '/api/notes/00000000-0000-4000-8000-000000000001',
    '무로그인 개별 메모 요청은 401 또는 403 JSON 오류로 거부', denied);
  if (config.step >= 10) {
    await check('anonymous_note_restore', '/api/restore-note',
      '무로그인 복구 POST는 401 JSON 오류로 거부',
      (response, data) => response.status === 401 && data?.reasonCode === 'login_required',
      undefined, 'POST');
  }
  if (config.step >= 11) {
    await check('webapp_manifest', '/manifest.webmanifest',
      'manifest의 앱 이름·시작 주소·설치 표시·아이콘이 설정됨',
      (response, data) => response.ok && data?.name === 'BYTE BACK 내 자료실'
        && data.start_url === '/' && data.display === 'standalone'
        && Array.isArray(data.icons) && ['192x192', '512x512'].every(size => data.icons.some(icon => icon.sizes === size)));
    for (const method of ['GET', 'POST']) {
      await check('anonymous_device_' + method.toLowerCase(), '/api/device-approval',
        '무로그인 기기 승인 요청/조회는 401 JSON 오류이고 등록 상태가 false',
        (response, data) => response.status === 401 && data?.reasonCode === 'login_required'
          && data.deviceRegistered === false, undefined, method);
    }
  }
  if (config.step >= 12) {
    await check('anonymous_operations_summary', '/api/operations-summary',
      '무로그인 작전실 요약은 401이며 가린 기록도 반환하지 않음',
      (response, data) => response.status === 401 && data?.reasonCode === 'login_required' && !('evidence' in data));
  }
  await check('invalid_login_token', '/api/notes',
    '유효하지 않은 로그인 토큰은 JSON 오류로 거부', denied, 'Bearer invalid');
  await check('static_notes_removed', '/data.json',
    '공개 JSON은 404 또는 메모 0건이고 확인 표시가 없음',
    (response, data) => response.status === 404
      || (response.ok && Array.isArray(data?.notes) && data.notes.length === 0
        && !data.sampleMarker));
  await check('deployment_metadata', '/aleph.json',
    '배포 메타데이터 JSON의 단계가 현재 설정과 일치',
    (response, data) => response.ok && data?.step === config.step
      && /^[a-f0-9]{40}$/i.test(data?.commit ?? '')
      && (config.step < 5 || (Array.isArray(data.allowedRoutes) && data.allowedRoutes.length > 0)));
  await check('home_security_header', '/',
    '첫 화면에 nosniff 또는 CSP 헤더가 있음',
    response => response.ok
      && (response.headers.get('x-content-type-options') === 'nosniff'
        || Boolean(response.headers.get('content-security-policy'))));
  if (config.step >= 4) {
    attempts.push(await checkAnonymousDatabase(config));
  }
  if (config.step >= 5) {
    for (const path of ['/', '/owner-check.html', '/auth-client.js']) {
      try {
        const response = await fetch(new URL(path, app), { redirect: 'error', signal: AbortSignal.timeout(10000) });
        const text = await response.text();
        const success = response.ok && !/sb_(?:publishable|secret)_|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(text);
        attempts.push({ attackId: 'browser_key_' + (path === '/' ? 'home' : path.slice(1).replace(/[^a-z0-9]/g, '_')),
          expected: '배포된 화면과 공유 모듈에 Supabase 키가 없음',
          observed: `HTTP ${response.status}; 공개 코드 키 검사 ${success ? '통과' : '실패'}` });
      } catch {
        attempts.push({ attackId: 'browser_key_' + (path === '/' ? 'home' : path.slice(1).replace(/[^a-z0-9]/g, '_')),
          expected: '배포된 화면과 공유 모듈에 Supabase 키가 없음', observed: '요청 실패; 확인하지 못함' });
      }
    }
  }
  return attempts;
}

async function checkAnonymousDatabase(config) {
  const expected = '공개용 키만 사용한 DB 직접 읽기는 권한 오류로 거부';
  try {
    const issuer = new URL(config.identityProvider.issuer);
    if (issuer.protocol !== 'https:' || issuer.username || issuer.password
        || issuer.port || issuer.search || issuer.hash
        || issuer.pathname !== '/auth/v1'
        || !/^[a-z0-9-]+\.supabase\.co$/.test(issuer.hostname)) {
      throw new Error('invalid_database_origin');
    }
    const original = config.step >= 5 ? new URL(config.originalApiUrl) : new URL('/rest/v1/notes', issuer.origin);
    if (original.origin !== issuer.origin || original.pathname !== '/rest/v1/notes'
        || original.search || original.hash || original.username || original.password) throw new Error('invalid_original_api');
    original.search = '?select=id&limit=1';
    const response = await fetch(original, {
      redirect: 'error', signal: AbortSignal.timeout(10000),
      headers: { apikey: 'sb_publishable_KCBRXcZaX0rKlgxb6wVvZg_ad5fzavC' },
    });
    let data = null;
    try { data = await response.json(); } catch {}
    const success = [401, 403].includes(response.status) && data?.code === '42501';
    return { attackId: 'anonymous_database_read', expected,
      observed: `HTTP ${response.status}; 권한 거부 확인 ${success ? '통과' : '실패'}` };
  } catch {
    return { attackId: 'anonymous_database_read', expected,
      observed: '요청 실패; DB 직접 읽기 거부를 확인하지 못함' };
  }
}
