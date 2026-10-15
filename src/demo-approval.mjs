import { randomBytes, randomUUID, createHash } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const STATES = new Set(['pending', 'approved', 'revoked']);
const digest = token => createHash('sha256').update(token).digest('hex');
const publicRecord = row => ({ requestId: row.id, state: row.state, createdAt: row.created_at });

// A demo session handle proves possession of a page session, not hardware identity.
// Only server-stored state and the verified login can authorize dummy data.
export function createDemoHandler({ verifyLogin, getStore, env = process.env, onConfirmedRevocation = async () => {} }) {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const fail = (code, reasonCode, error) => res.status(code).json({ demo: true, error, reasonCode });
    let url;
    try { url = new URL(req.url, 'https://local.invalid'); } catch { return fail(404, 'invalid_route', '허용된 데모 경로가 아닙니다.'); }
    if (url.search || url.pathname !== '/api/demo-device')
      return fail(404, 'invalid_route', '허용된 데모 경로가 아닙니다.');
    if (!['GET', 'POST'].includes(req.method))
      return fail(405, 'method_not_allowed', '지원하지 않는 요청입니다.');
    if (!req.headers.authorization) return fail(401, 'login_required', '데모를 사용하려면 로그인하세요.');
    let actor;
    try { actor = await verifyLogin(req.headers.authorization); } catch {}
    if (actor?.kind !== 'student' || !UUID.test(actor.userId ?? ''))
      return fail(401, 'invalid_login', '학생 로그인을 확인할 수 없습니다.');
    const owner = actor.userId.toLowerCase();
    const admins = (env.DEMO_APPROVAL_ADMIN_IDS ?? '').split(',').map(s => s.trim().toLowerCase()).filter(s => UUID.test(s));
    if (!admins.length) return fail(503, 'demo_setup_required', '데모 관리자 계정 설정이 준비되지 않았습니다.');
    const token = req.headers['x-demo-session'];
    const validToken = typeof token === 'string' && TOKEN.test(token);
    const readSession = async store => validToken ? await store.find(owner, digest(token)) : null;
    try {
      let body;
      if (req.method === 'POST') {
        try { body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; } catch {}
        if (!body || Array.isArray(body) || typeof body !== 'object'
            || !['request', 'list', 'approve', 'revoke'].includes(body.action))
          return fail(400, 'invalid_body', '데모 요청 형식을 확인하세요.');
        const allowed = body.action === 'request' || body.action === 'list' ? ['action'] : ['action', 'requestId'];
        if (Object.keys(body).some(key => !allowed.includes(key)))
          return fail(400, 'invalid_body', '기기 상태나 권한을 요청에 넣을 수 없습니다.');
        if (body.action !== 'request' && !admins.includes(owner))
          return fail(403, 'admin_required', '관리자만 승인 목록과 승인 결과를 변경할 수 있습니다.');
        if (['approve', 'revoke'].includes(body.action) && !UUID.test(body.requestId ?? ''))
          return fail(400, 'invalid_body', '승인 요청 번호를 확인하세요.');
      }
      const store = await getStore();
      if (req.method === 'GET') {
        const row = await readSession(store);
        return res.status(200).json({ demo: true, state: row && STATES.has(row.state) ? row.state : 'unregistered',
          ...(row ? { requestId: row.id } : {}) });
      }
      if (body.action === 'request') {
        const previous = await readSession(store);
        if (previous) return res.status(200).json({ demo: true, ...publicRecord(previous) });
        const sessionToken = randomBytes(32).toString('base64url');
        const row = await store.request({ id: randomUUID(), owner_user_id: owner,
          session_hash: digest(sessionToken), state: 'pending', created_at: new Date().toISOString(), approved_by: null });
        return res.status(201).json({ demo: true, ...publicRecord(row), sessionToken });
      }
      if (body.action === 'list') return res.status(200).json({ demo: true, requests: (await store.list()).map(publicRecord) });
      const row = await store.transition(body.requestId, body.action === 'approve' ? 'approved' : 'revoked', owner);
      if (!row) return fail(409, 'request_changed', '요청이 바뀌었거나 이미 처리됐습니다. 목록을 다시 확인하세요.');
      if (body.action === 'revoke') {
        try { await onConfirmedRevocation(); }
        catch { res.setHeader('X-Operations-Audit', 'unavailable'); }
      }
      return res.status(200).json({ demo: true, ...publicRecord(row) });
    } catch {
      return fail(503, 'demo_setup_required', '데모 승인 저장소 연결이 준비되지 않았습니다.');
    }
  };
}
