// 3단계 제작 3: 로그인한 사용자의 가상 메모를 추가·조회·수정·삭제하는 서버 코드입니다.
// - 요청자는 Authorization 토큰을 src/verify-login.mjs로 검사해 확인합니다.
//   브라우저가 보낸 userId·role·owner_id는 읽지도 믿지도 않습니다.
// - POST는 서버가 확인한 사용자 ID를 owner_id로 저장합니다.
// - 아직 소유자 검사는 하지 않습니다. 로그인한 사용자라면 id를 알 때 다른 사람의 메모도
//   GET·PUT·DELETE 할 수 있습니다. 이 허점은 4단계에서 고칩니다.
// 키·토큰 값은 응답·로그에 넣지 않습니다.
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from './verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const MAX_TITLE = 200;
const MAX_BODY = 5000;

// 화면과 API가 쓰는 모양은 {id, title, body}입니다. DB 칸 이름은 content이고 owner_id는 내보내지 않습니다.
const toPublic = (row) => ({ id: row.id, title: row.title, body: row.content });

function readNote(raw, { allowId }) {
  let data = raw;
  if (typeof data === 'string') {
    try { data = JSON.parse(data); } catch { return null; }
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
  const { title, body, id } = data;
  if (typeof title !== 'string' || !title.trim() || title.length > MAX_TITLE) return null;
  if (typeof body !== 'string' || body.length > MAX_BODY) return null;
  if (allowId && id !== undefined && (typeof id !== 'string' || !UUID.test(id))) return null;
  // title·body·id 외의 값(owner_id, userId, role 등)은 버립니다.
  return { title: title.trim(), body, id: allowId && typeof id === 'string' ? id.toLowerCase() : undefined };
}

function idFromRequest(request) {
  const fromQuery = request.query?.id;
  if (typeof fromQuery === 'string') return fromQuery;
  if (fromQuery !== undefined) return null;
  try { return new URL(request.url, 'http://local').pathname.split('/').filter(Boolean).pop() ?? null; } catch { return null; }
}

export function createNotesApi({ getVerifier, getSupabase }) {
  // 모든 요청의 공통 앞부분: 허용 방법 → 서버 설정 → 로그인 확인. 통과한 요청만 handle로 갑니다.
  const guarded = (allowed, handle) => async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    if (!allowed.includes(request.method)) {
      response.setHeader('Allow', allowed.join(', '));
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
        // 토큰 없음·위조·만료·다른 서비스용은 모두 같은 응답입니다.
        response.setHeader('WWW-Authenticate', 'Bearer');
        return response.status(401).json({ error: 'LOGIN_REQUIRED' });
      }
      return await handle({ request, response, supabase, userId: login.userId });
    } catch {
      console.error('notes 함수 오류');
      return response.status(500).json({ error: 'NOTES_FUNCTION_ERROR' });
    }
  };

  const failed = (response, error, label) => {
    console.error(`notes ${label} 실패`, error.code ?? 'unknown');
    return response.status(502).json({ error: 'NOTES_REQUEST_FAILED' });
  };

  // GET /api/notes, POST /api/notes
  const collection = guarded(['GET', 'POST'], async ({ request, response, supabase, userId }) => {
    if (request.method === 'POST') {
      const note = readNote(request.body, { allowId: true });
      if (!note) return response.status(400).json({ error: 'INVALID_BODY' });
      const row = { owner_id: userId, title: note.title, content: note.body };
      if (note.id) row.id = note.id;
      const { data, error } = await supabase.from('notes').insert(row).select('id').single();
      if (error?.code === '23505') return response.status(409).json({ error: 'ID_ALREADY_EXISTS' });
      if (error) return failed(response, error, '추가');
      return response.status(201).json({ id: data.id });
    }
    // 목록: 서버가 확인한 사용자 본인의 메모만 돌려줍니다.
    const read = (ordered) => {
      let query = supabase.from('notes').select('id, title, content').eq('owner_id', userId);
      if (ordered) query = query.order('position', { ascending: true, nullsFirst: false });
      return query.order('created_at', { ascending: true }).order('title', { ascending: true });
    };
    // position(원래 표시 순서) 칸이 아직 없으면(42703) 순서 기준 없이 읽습니다.
    let { data, error } = await read(true);
    if (error?.code === '42703') ({ data, error } = await read(false));
    if (error) return failed(response, error, '목록 읽기');
    return response.status(200).json(data.map(toPublic));
  });

  // GET /api/notes/:id, PUT /api/notes/:id, DELETE /api/notes/:id
  const item = guarded(['GET', 'PUT', 'DELETE'], async ({ request, response, supabase }) => {
    const id = idFromRequest(request);
    if (typeof id !== 'string' || !UUID.test(id)) return response.status(400).json({ error: 'INVALID_ID' });
    const notFound = () => response.status(404).json({ error: 'NOT_FOUND' });
    if (request.method === 'GET') {
      const { data, error } = await supabase.from('notes').select('id, title, content').eq('id', id).maybeSingle();
      if (error) return failed(response, error, '읽기');
      return data ? response.status(200).json(toPublic(data)) : notFound();
    }
    if (request.method === 'PUT') {
      const note = readNote(request.body, { allowId: false });
      if (!note) return response.status(400).json({ error: 'INVALID_BODY' });
      const { data, error } = await supabase.from('notes')
        .update({ title: note.title, content: note.body }).eq('id', id).select('id, title, content');
      if (error) return failed(response, error, '수정');
      return data?.length ? response.status(200).json(toPublic(data[0])) : notFound();
    }
    const { data, error } = await supabase.from('notes').delete().eq('id', id).select('id');
    if (error) return failed(response, error, '삭제');
    return data?.length ? response.status(200).json({ id: data[0].id }) : notFound();
  });

  return { collection, item };
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

export const notesApi = createNotesApi({
  getVerifier() {
    if (!verifier) verifier = createLoginVerifier({ config, supabaseSecretKey: secrets().secretKey });
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
