// 2단계: 가상 메모를 서버 함수가 Supabase에서 읽어 화면에 전달합니다.
// SUPABASE_URL과 SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽습니다.
// 키 값은 응답·로그·브라우저 파일에 넣지 않습니다.
import { createClient } from '@supabase/supabase-js';

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    return response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });
  }
  try {
    const supabase = createClient(url, secretKey, { auth: { persistSession: false } });
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
}
