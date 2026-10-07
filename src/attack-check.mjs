// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (![1, 2, 3].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
  const get = (path) => fetch(new URL(path, app), { redirect: 'error', signal: AbortSignal.timeout(10000) });
  if (config.step === 3) return runStep3Checks(fetch, app, config.sampleMarker);
  if (config.step === 2) return runStep2Checks(get, config.sampleMarker);
  const response = await get('/data.json');
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

// 2단계: 실제로 보낸 비로그인 요청의 결과만 적습니다. 메모 본문과 키 값은 기록하지 않습니다.
// 심판의 판정이 아니라 학생의 자기 점검입니다.
async function staticChecks(get, marker) {
  const results = [];
  const dataResponse = await get('/data.json');
  const dataText = await dataResponse.text();
  let dataNotes = null;
  if (dataResponse.ok) {
    try {
      const data = JSON.parse(dataText);
      dataNotes = Array.isArray(data?.notes) ? data.notes.length : null;
    } catch {
      // 형식이 맞지 않으면 아래에서 확인 불가로 적습니다.
    }
  }
  results.push({ attackId: 'public_data_json_no_notes', expected: '비로그인 /data.json에 가상 메모가 없음(파일이 없거나 notes가 비어 있음)',
    observed: dataResponse.status === 404 ? '비로그인 /data.json이 없음 (HTTP 404)'
      : dataNotes === null ? `/data.json 형식을 확인하지 못함 (HTTP ${dataResponse.status})`
        : dataNotes === 0 ? '비로그인 /data.json의 notes가 0건임 (HTTP 200)'
          : `비로그인 /data.json에 메모 ${dataNotes}건이 보임` });
  const alephResponse = await get('/aleph.json');
  const alephText = await alephResponse.text();
  const markerPaths = [['/data.json', dataText], ['/aleph.json', alephText]]
    .filter(([, text]) => text.includes(marker)).map(([path]) => path);
  results.push({ attackId: 'static_marker_absent',
    expected: '비로그인 정적 응답(/data.json, /aleph.json)에 시작 틀 확인 표시가 없음',
    observed: markerPaths.length ? `확인 표시가 보임: ${markerPaths.join(', ')}`
      : `확인 표시가 보이지 않음 (/data.json HTTP ${dataResponse.status}, /aleph.json HTTP ${alephResponse.status})` });
  return results;
}

async function runStep2Checks(get, marker) {
  const results = await staticChecks(get, marker);
  const apiResponse = await get('/api/notes');
  const apiText = await apiResponse.text();
  let apiNotes = null;
  try {
    const data = JSON.parse(apiText);
    apiNotes = Array.isArray(data?.notes) ? data.notes.length : null;
  } catch {
    // JSON이 아니면 건수는 적지 않습니다.
  }
  const keyLike = /\bsb_secret_|\beyJ[A-Za-z0-9_-]{12,}\.|-----BEGIN /u.test(apiText);
  results.push({ attackId: 'anonymous_api_notes_read',
    expected: '비로그인 /api/notes 응답에 키 값이 없음. 로그인 없는 읽기는 3단계에서 막을 약점으로 기록',
    observed: `HTTP ${apiResponse.status}, ${apiNotes === null ? '메모 건수 확인 불가' : `메모 ${apiNotes}건`}, 키로 보이는 문자열 ${keyLike ? '있음' : '없음'}` });
  return results;
}

// 3단계: 로그인 없이(또는 가짜 토큰으로) 실제로 보낸 요청이 거부됐는지만 적습니다.
// 상태 번호만 기록하고 응답 본문·토큰·키 값은 기록하지 않습니다. 심판의 판정이 아니라 학생의 자기 점검입니다.
// 부작용이 없도록 쓰기 요청은 빈 본문이거나 존재하지 않는 임의의 id로 보냅니다
// (로그인 확인이 뚫려 있어도 새 메모가 생기거나 기존 메모가 바뀌지 않음).
const b64url = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const fakeJwt = (payload) => `${b64url({ alg: 'ES256', typ: 'JWT' })}.${b64url(payload)}.c2ln`;

async function runStep3Checks(doFetch, app, marker) {
  const send = (method, path, { token, body } = {}) => doFetch(new URL(path, app), {
    method, redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const get = (path) => send('GET', path);
  const results = await staticChecks(get, marker);
  const absentId = '00000000-0000-4000-8000-000000000000';
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: 'https://vskaxngivuhucmbnoagz.supabase.co/auth/v1', aud: 'authenticated',
    role: 'authenticated', sub: '11111111-1111-4111-8111-111111111111', exp: now + 600 };
  // 2xx 응답이거나 앱이 보낸 JSON이어야 거부 여부의 근거로 삼습니다. 거부는 앱의 401 LOGIN_REQUIRED뿐입니다.
  // 방화벽·접속 허용 목록·CDN이 보낸 403(JSON이 아닌 글자) 같은 응답은 앱이 거부한 것이 아니므로
  // "확인하지 못함"으로 적습니다.
  const refused = async (attackId, expected, response) => {
    let isAppJson = false;
    let code = null;
    try {
      const data = JSON.parse(await response.text());
      isAppJson = data !== null && typeof data === 'object';
      if (typeof data?.error === 'string') code = data.error;
    } catch {
      // JSON이 아니면 앱의 응답으로 보지 않습니다.
    }
    const notRefused = response.ok || isAppJson;
    return { attackId, expected,
      observed: !notRefused ? `확인하지 못함 (HTTP ${response.status}, 앱의 응답으로 보이지 않음)`
        : response.status === 401 && code === 'LOGIN_REQUIRED' ? '거부됨 (HTTP 401)'
          : `거부되지 않음 (HTTP ${response.status})` };
  };
  const cases = [
    ['anonymous_notes_list_refused', '로그인 없는 GET /api/notes가 거부됨', () => send('GET', '/api/notes')],
    ['anonymous_note_create_refused', '로그인 없는 POST /api/notes가 거부됨(빈 본문으로 보냄)', () => send('POST', '/api/notes', { body: {} })],
    ['anonymous_note_read_refused', '로그인 없는 GET /api/notes/:id가 거부됨(없는 id)', () => send('GET', `/api/notes/${absentId}`)],
    ['anonymous_note_update_refused', '로그인 없는 PUT /api/notes/:id가 거부됨(없는 id)', () => send('PUT', `/api/notes/${absentId}`, { body: {} })],
    ['anonymous_note_delete_refused', '로그인 없는 DELETE /api/notes/:id가 거부됨(없는 id)', () => send('DELETE', `/api/notes/${absentId}`)],
    ['forged_token_refused', '서명이 가짜인 로그인 토큰이 거부됨', () => send('GET', '/api/notes', { token: fakeJwt(claims) })],
    ['expired_token_refused', '만료된 로그인 토큰이 거부됨', () => send('GET', '/api/notes', { token: fakeJwt({ ...claims, exp: now - 600 }) })],
    ['other_issuer_token_refused', '다른 발급자의 로그인 토큰이 거부됨',
      () => send('GET', '/api/notes', { token: fakeJwt({ ...claims, iss: 'https://other.supabase.co/auth/v1' }) })],
  ];
  for (const [attackId, expected, run] of cases) results.push(await refused(attackId, expected, await run()));
  return results;
}
