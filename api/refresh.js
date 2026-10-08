// 5단계: POST /api/refresh (로그인 유지용 토큰 갱신). 처리는 src/auth-api.mjs에 있습니다.
import { authApi } from '../src/auth-api.mjs';

export default authApi.refresh;
