// 5단계: POST /api/login (이메일·비밀번호 로그인). 처리는 src/auth-api.mjs에 있습니다.
import { authApi } from '../src/auth-api.mjs';

export default authApi.login;
