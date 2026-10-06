// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 1 && config.step !== 2) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
async function runStep2Checks(get, marker) {
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
  results.push({ attackId: 'public_data_json_no_notes', expected: '비로그인 /data.json에 가상 메모가 없음',
    observed: dataNotes === null ? `/data.json 형식을 확인하지 못함 (HTTP ${dataResponse.status})`
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
