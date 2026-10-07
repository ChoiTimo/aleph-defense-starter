// 로그인한 사용자의 가상 메모를 추가·조회·수정·삭제하는 서버 코드입니다. (3단계 제작 3, 4단계 제작 2에서 소유자 검사 추가)
// - 요청자는 Authorization 토큰을 src/verify-login.mjs로 검사해 확인합니다.
//   브라우저가 보낸 userId·role·owner_id는 URL·쿼리·본문 어디에 있어도 읽지도 믿지도 않습니다.
// - 소유자 검사: 모든 읽기·수정·삭제 조건에 "owner_id = 서버가 확인한 사용자 ID"를 함께 넣습니다.
//   조건을 한 질의에 넣어서 확인과 변경 사이에 끼어들 틈이 없습니다. 조건에 맞는 행이 없을 때만
//   그 id가 있는지 따로 보고, 있으면(남의 메모·주인 없는 메모) 403 FORBIDDEN, 없으면 404 NOT_FOUND로 답합니다.
//   남의 메모의 제목·본문은 어떤 응답에도 넣지 않습니다.
// - POST는 서버가 확인한 사용자 ID를 owner_id로 저장합니다.
// - PUT은 기존 행의 owner_id가 본인일 때만 바꾸고, 새 행의 owner_id도 본인 ID로 고정합니다(소유자 변경 불가).
// - owner_id가 비어 있는 처음 메모는 누구와도 일치하지 않아 아무도 접근하지 못합니다.
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
  const item = guarded(['GET', 'PUT', 'DELETE'], async ({ request, response, supabase, userId }) => {
    const id = idFromRequest(request);
    if (typeof id !== 'string' || !UUID.test(id)) return response.status(400).json({ error: 'INVALID_ID' });
    // 본인 조건에 맞는 행이 없을 때만 부릅니다: id가 있으면 남의 것(403), 없으면 404. 자료는 읽어 오지 않고 id만 봅니다.
    const notFound = async () => {
      const { data, error } = await supabase.from('notes').select('id').eq('id', id).maybeSingle();
      if (error) return failed(response, error, '소유자 확인');
      return data ? response.status(403).json({ error: 'FORBIDDEN' }) : response.status(404).json({ error: 'NOT_FOUND' });
    };
    if (request.method === 'GET') {
      const { data, error } = await supabase.from('notes').select('id, title, content')
        .eq('id', id).eq('owner_id', userId).maybeSingle();
      if (error) return failed(response, error, '읽기');
      return data ? response.status(200).json(toPublic(data)) : await notFound();
    }
    if (request.method === 'PUT') {
      const note = readNote(request.body, { allowId: false });
      if (!note) return response.status(400).json({ error: 'INVALID_BODY' });
      // 기존 행(owner_id = 본인)만 고르고, 새 값의 owner_id도 본인으로 고정합니다.
      const { data, error } = await supabase.from('notes')
        .update({ title: note.title, content: note.body, owner_id: userId })
        .eq('id', id).eq('owner_id', userId).select('id, title, content');
      if (error) return failed(response, error, '수정');
      return data?.length ? response.status(200).json(toPublic(data[0])) : await notFound();
    }
    const { data, error } = await supabase.from('notes').delete()
      .eq('id', id).eq('owner_id', userId).select('id');
    if (error) return failed(response, error, '삭제');
    return data?.length ? response.status(200).json({ id: data[0].id }) : await notFound();
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
