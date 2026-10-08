// 3단계: GET·PUT·DELETE /api/notes/:id (메모 한 건 읽기·수정·삭제).
// 로그인 검사와 처리는 src/notes-api.mjs에 있습니다. 소유자 검사는 4단계에서 붙입니다.
import { notesApi } from '../../src/notes-api.mjs';

export default notesApi.item;
