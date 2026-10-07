// 3단계: GET /api/notes(내 메모 목록), POST /api/notes(메모 추가).
// 로그인 검사와 처리는 src/notes-api.mjs에 있습니다.
import { notesApi } from '../src/notes-api.mjs';

export default notesApi.collection;
