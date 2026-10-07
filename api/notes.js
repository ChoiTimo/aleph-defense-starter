// 3단계: 서버가 로그인 토큰을 검증한 요청에만 가상 메모를 돌려줍니다.
// SUPABASE_URL과 SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽습니다.
// 키·토큰 값은 응답·로그·브라우저 파일에 넣지 않습니다.
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

// 로그인 토큰이 없거나, 서명이 위조됐거나, 만료됐거나, 다른 서비스용이면 모두 같은 401입니다.
// 이유를 나누어 알려 주지 않아 요청자가 어느 검사에서 걸렸는지 알 수 없습니다.
export function createNotesHandler({ getVerifier, getSupabase }) {
  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    let verify;
    let supabase;
    try {
      verify = getVerifier();
      supabase = getSupabase();
    } catch {
      // 설정이 없거나 틀리면 열어 두지 않고 닫습니다.
      return response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });
    }
    try {
      const login = await verify(request.headers?.authorization);
      if (!login) {
        response.setHeader('WWW-Authenticate', 'Bearer');
        return response.status(401).json({ error: 'LOGIN_REQUIRED' });
      }
      // owner_id·id는 고르지 않습니다. 화면에 필요한 title, content만 내보냅니다.
      const read = (ordered) => {
        let query = supabase.from('notes').select('title, content');
        if (ordered) query = query.order('position', { ascending: true, nullsFirst: false });
        return query.order('created_at', { ascending: true }).order('title', { ascending: true });
      };
      // position(원래 표시 순서) 칸이 아직 없으면(42703) 순서 기준 없이 읽습니다.
      let { data, error } = await read(true);
      if (error?.code === '42703') ({ data, error } = await read(false));
      if (error) {
        console.error('notes 읽기 실패', error.code ?? 'unknown');
        return response.status(502).json({ error: 'NOTES_READ_FAILED' });
      }
      return response.status(200).json({ notes: data });
    } catch {
      console.error('notes 함수 오류');
      return response.status(500).json({ error: 'NOTES_FUNCTION_ERROR' });
    }
  };
}

// 서버 런타임에서 한 번만 만듭니다. 환경변수가 없으면 만들지 않고 던집니다.
let verifier;
let client;
function secrets() {
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) throw new Error('missing_env');
  return { url, secretKey };
}

export default createNotesHandler({
  getVerifier() {
    if (!verifier) {
      verifier = createLoginVerifier({ config, supabaseSecretKey: secrets().secretKey });
    }
    return verifier;
  },
  getSupabase() {
    if (!client) {
      const { url, secretKey } = secrets();
      client = createClient(url, secretKey, { auth: { persistSession: false } });
    }
    return client;
  },
});
