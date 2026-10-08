// 5단계: 로그인·로그인 갱신을 서버 한곳에서 합니다. (브라우저는 Supabase를 직접 부르지 않습니다.)
// - POST /api/login   { email, password }   → { access_token, refresh_token, expires_at, email }
// - POST /api/refresh { refresh_token }     → 같은 모양
// 비밀번호·토큰·키 값은 로그와 오류 응답에 넣지 않습니다. 서버 전용 키는 이 서버 안에서만 씁니다.
// 로그인 토큰의 검사(위조·만료·다른 발급자)와 소유자 검사는 src/verify-login.mjs, src/notes-api.mjs가 그대로 합니다.
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}$/u;
const MAX_PASSWORD = 256;
const MAX_TOKEN = 4096;
const TIMEOUT_MS = 10000;
// 화면에 보여 줘도 되는 실패 이유 코드만 돌려줍니다. 나머지는 unknown으로 숨깁니다.
const REASONS = new Set(['invalid_credentials', 'email_not_confirmed', 'user_banned',
  'over_request_rate_limit', 'validation_failed']);

const readJson = (raw) => {
  let data = raw;
  if (typeof data === 'string') {
    try { data = JSON.parse(data); } catch { return null; }
  }
  return data && typeof data === 'object' && !Array.isArray(data) ? data : null;
};

export function createAuthApi({ getSettings, fetchImpl = fetch }) {
  // 서버 한곳에서 Supabase 로그인 주소로만 보냅니다. 응답에서 필요한 칸만 꺼냅니다.
  const callAuth = async (grant, payload) => {
    const { url, secretKey } = getSettings();
    const response = await fetchImpl(`${url}/auth/v1/token?grant_type=${grant}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', apikey: secretKey },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    let data = null;
    try { data = await response.json(); } catch { /* 형식이 맞지 않으면 아래에서 502로 처리합니다. */ }
    return { response, data };
  };

  const toSession = (data) => ({
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_at: data.expires_at,
    email: typeof data.user?.email === 'string' ? data.user.email : '',
  });

  const handler = (grant, readPayload, failure) => async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    if (request.method !== 'POST') {
      response.setHeader('Allow', 'POST');
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    const payload = readPayload(readJson(request.body));
    if (!payload) return response.status(400).json({ error: 'INVALID_BODY' });
    try {
      getSettings();
    } catch {
      return response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });
    }
    try {
      const { response: upstream, data } = await callAuth(grant, payload);
      if (upstream.ok && typeof data?.access_token === 'string' && typeof data.refresh_token === 'string'
          && Number.isFinite(data.expires_at)) {
        return response.status(200).json(toSession(data));
      }
      if (upstream.status === 429) {
        return response.status(429).json({ error: failure, reason: 'over_request_rate_limit' });
      }
      if (upstream.status >= 400 && upstream.status < 500) {
        const code = data?.error_code ?? data?.code;
        return response.status(401).json({ error: failure, reason: REASONS.has(code) ? code : 'unknown' });
      }
      console.error('auth 요청 실패', upstream.status);
      return response.status(502).json({ error: 'AUTH_REQUEST_FAILED' });
    } catch {
      console.error('auth 함수 오류');
      return response.status(502).json({ error: 'AUTH_REQUEST_FAILED' });
    }
  };

  return {
    login: handler('password', (body) => {
      const email = typeof body?.email === 'string' ? body.email.trim() : '';
      const password = body?.password;
      if (!EMAIL.test(email) || typeof password !== 'string' || !password || password.length > MAX_PASSWORD) return null;
      return { email, password };
    }, 'LOGIN_FAILED'),
    refresh: handler('refresh_token', (body) => {
      const token = body?.refresh_token;
      return typeof token === 'string' && token && token.length <= MAX_TOKEN ? { refresh_token: token } : null;
    }, 'LOGIN_REQUIRED'),
  };
}

export const authApi = createAuthApi({
  getSettings() {
    const url = process.env.SUPABASE_URL;
    const secretKey = process.env.SUPABASE_SECRET_KEY;
    if (!url || !secretKey) throw new Error('missing_env');
    return { url, secretKey };
  },
});
