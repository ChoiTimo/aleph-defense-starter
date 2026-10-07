# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

(1단계 당시 기록) 배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있고, `/data.json`에 같은 가상 메모가 공개되었습니다. 이 공개 상태를 확인하는 것이 1단계의 출발점이었습니다. 2단계 이후의 현재 상태는 아래 "2단계" 절을 보세요. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`은 2단계 저장점에서 Git `origin` 주소로 맞췄습니다. `publicAppUrl`에는 실제 배포 주소 `https://choi-bujang-secret-vault-tr33.vercel.app`을 넣었습니다. `judgeIssuer`는 운영 측이 채운 값이므로 바꾸지 않습니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. `src/attack-check.mjs`의 1단계 점검은 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽었습니다. 2단계 점검은 아래 "2단계 저장점"에 적었습니다.

## 2단계: 자료를 코드 밖으로 옮깁니다

가상 메모 네 건은 학습용 Supabase `notes` 테이블에 있고(RLS 켬, anon·authenticated 권한 없음), 공개 `/data.json`은 더 이상 없습니다(404). 화면(`public/index.html`)은 `/api/notes`를 불러 메모를 그립니다. `api/notes.js`는 Vercel 서버 함수이며 `title`, `content`만 돌려줍니다.

- 환경변수 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`의 이름은 [`.env.example`](.env.example)에 값 없이 적어 두었습니다. 값은 Vercel 프로젝트의 Settings > Environment Variables 입력란에 학생이 직접 넣습니다. 이름 앞에 `NEXT_PUBLIC_`를 붙이거나 코드·Git·채팅에 값을 적지 않습니다. 값을 바꾼 뒤에는 다시 배포해야 반영됩니다.
- `/api/notes`는 `position` 칸 순서로 메모를 돌려줘 원래 자료의 순서(1~4)를 지킵니다. `position` 칸이 없으면 만든 시각·제목 순으로 읽습니다. 순서 값을 넣는 문장은 메모 제목이 들어 있어 Git에 두지 않았습니다.
- 표 구조·RLS·권한 회수 SQL은 [`sql/2-notes-schema.sql`](sql/2-notes-schema.sql)에 있습니다. 가상 메모 4건을 넣는 문장은 메모 본문이 들어 있어 Git에서 제외했습니다(`supabase/`).
- SQL Editor 확인 결과(학생이 직접 실행, 2026-10-06): `owner_id` 칸은 `uuid`, 외래키 0개(`auth.users` 연결 없음), RLS 켜짐(`rls_on` true), 메모 4건, anon·authenticated 권한 목록 0행, anon·authenticated 역할로 `notes` 읽기 시도는 `permission denied for table notes`(42501)로 거부됨.
- 다시 확인: 배포 주소의 `/`에서 카드 네 장이 보이는지, `/data.json`이 열리지 않는지(404) 봅니다. 환경변수가 없으면 `/api/notes`는 `SERVER_NOT_CONFIGURED`(500)를 돌려주고 화면에는 오류 문구만 보입니다.

**(2단계 당시 기록. 이 약점은 3단계에서 로그인 확인을 붙여 막았습니다. 아래 "3단계" 절을 보세요.) 아직 남은 약점**: `/api/notes`는 누구나 부를 수 있는 공개 주소입니다. 로그인 확인이 없어서, 주소를 아는 사람은 로그인 없이 같은 메모 네 건을 읽을 수 있습니다. 메모가 `/data.json`에서 빠졌을 뿐 자료 보호는 끝나지 않았습니다. 로그인과 허용 경로는 3단계 이후에 추가합니다.

### 2단계 저장점: 지금 작동하는 기능과 다시 실행하는 방법 (2단계 당시 기록)

- 작동하는 기능: `/`가 `/api/notes`(서버 함수)로 가상 메모 네 건을 그립니다. `/data.json`은 없습니다(404, 빌드가 2단계부터 복사를 끝냄). 로그인·허용 경로·원본 API는 아직 없습니다(`identityProvider` null, `allowedRoutes` 빈 배열, `originalApiUrl` null).
- 보안 헤더: `vercel.json`의 `headers`가 모든 응답(첫 화면 `/` 포함)에 `X-Content-Type-Options: nosniff`를 붙입니다. 강한 `Content-Security-Policy`는 화면의 인라인 스크립트를 막을 수 있어 쓰지 않았습니다. 브라우저 F12 > Network > 첫 요청 > Response Headers에서 확인합니다.
- `aleph.config.json`은 `step` 2, `repoUrl`은 Git `origin`과 같은 주소, `publicAppUrl`은 실제 배포 주소입니다. 배포 식별 파일 `/aleph.json`은 2단계부터 확인 표시(`sampleMarker`)를 내보내지 않습니다. `src/decider.mjs`의 `RULE_IDS`는 시작점 규칙 `starter.deny`(모두 거부) 하나뿐이며 6단계 전까지 늘리지 않습니다.
- `npm run bundle`은 **마지막 커밋의 바뀐 파일**을 읽으므로, PR을 합친 병합 커밋 위에서는 "마지막 커밋에 바뀐 파일이 없습니다" 오류가 납니다. 병합 커밋이 아닌 일반 커밋 위에서 실행합니다(예: 작업 브랜치 끝, 합치기 전). 시작 틀의 `scripts/bundle.mjs`는 고치지 않았습니다.
- 다시 실행: `npm run test:r5`(로컬 시험), `npm run build -- --local`(로컬 빌드), 변경 커밋 뒤 `npm run bundle`(제출 묶음 `artifacts/submission.json` 생성, 커밋하지 않음). `bundle`은 `bundle-notes.json`의 `explanation`이 필요하며 이 파일도 커밋하지 않습니다.
- `src/attack-check.mjs`의 2단계 점검은 배포 주소로 비로그인 `GET /data.json`, `GET /aleph.json`, `GET /api/notes`를 실제로 보내고 상태(`/data.json`은 404가 정상)·건수·시작 틀 확인 표시 유무·키 문자열 유무만 기록합니다. 심판의 판정이 아닙니다. 배포 주소가 없으면 실행하지 않은 점검으로 남습니다.

### 2단계 확인 절차: 가상 메모 문장 검색

검색어는 `실습용 가상 [과포아훈]`입니다. 정규식 문자 모임을 써서, 이 README 자신은 검색에 걸리지 않습니다. 메모 네 건이 모두 걸립니다.

1. 현재 배포 파일 (배포 주소 https://choi-bujang-secret-vault-tr33.vercel.app): 아래 한 줄을 실행합니다. `curl:`로 시작하는 오류 줄이 있으면 접속하지 못한 것이므로 그 결과는 통과가 아닙니다. 오류 줄이 보이면 접속하지 못한 것이므로 그 `0`은 통과가 아닙니다.
   `U=https://choi-bujang-secret-vault-tr33.vercel.app; curl -s -o /dev/null -w "/data.json HTTP %{http_code}\n" "$U/data.json"; for p in / /aleph.json; do curl -fsS "$U$p" | grep -c -E '실습용 가상 [과포아훈]'; done`
   `/data.json`은 `HTTP 404`여야 하고, 나머지 두 줄은 `0`이어야 합니다.
   화면 `/`는 메모를 `/api/notes`에서 받아 그리므로 HTML 파일에는 메모 문장이 없습니다.
2. GitHub 최신 파일: 배포에 쓰는 브랜치(보통 `main`)를 `git fetch origin main` 한 뒤 `git grep -n -E '실습용 가상 [과포아훈]' origin/main`을 실행합니다. 결과가 없어야 합니다. GitHub 저장소 화면의 검색창에서 같은 검색어를 넣어 봐도 됩니다.
3. 옛 공개 흔적: `git log --all -G'실습용 가상 [과포아훈]' --format='%h %ad %s' --date=short -- data.json public/data.json`. 이 결과는 비어 있지 않은 것이 정상이며, 아래 "남은 약점"의 근거입니다.

#### 검색 결과 기록

| 대상 | 명령 | 결과 | 실행 여부 |
| --- | --- | --- | --- |
| 작업 브랜치 `claude/gallant-tesla-wyxn5s` 최신 파일 | `git grep` (2번 항목 방식) | 메모 문장 없음 | 실행함 (2026-10-06) |
| `origin/main` 최신 파일 | `git grep` | 메모 문장 없음 (커밋 `c3bcc55` 기준) | 실행함 (2026-10-06) |
| 옛 커밋 이력 | `git log -G` | `0f9a3c9`(2026-09-26, 시작 틀), `5f21168`(2026-10-06, 삭제 커밋)에서 메모 문장 확인 | 실행함 (2026-10-06) |
| 현재 배포 파일 | 브라우저로 직접 열어 확인 (학생) | 배포 커밋 `c3bcc55` 기준(이후 `data.json` 복사를 끝내 지금은 404): `/data.json`은 `{"notes": []}`, `/aleph.json`에 확인 표시 없음, 화면 `/`에 카드 4장, `/api/notes`에 메모 4건과 키 문자열 없음, Production 배포 `Ready` | 학생이 브라우저로 확인함 (2026-10-06 15:22~15:29). 1번 `curl` 명령은 미실행 |

#### 공개 전 비밀값 검사

- `npm run check:secrets`: Git에 올라가는 모든 파일에서 서버 키·JWT·개인키·비밀번호가 든 DB 주소처럼 보이는 문자열을 찾습니다. 찾으면 파일 이름과 종류만 알리고 값은 출력하지 않습니다. 커밋·푸시 전에 실행합니다.
- `npm run build`(Vercel 배포 빌드)는 공개 폴더 `public/`을 같은 기준으로 검사하고, 걸리면 배포를 멈춥니다.
- 2026-10-06 실행 결과: 추적 파일 전체에서 키처럼 보이는 문자열 없음. 서버 키는 Vercel 환경변수에만 있습니다.

#### 알려진 문제와 수정

- 2단계 빌드는 `data.json` 복사를 끝냅니다(`scripts/build-public.mjs`는 `step` 1에서만 복사). 시작 틀의 오류 문구 "1단계 이후에는 공개 data.json 복사를 끝내고 보호된 자료 API로 바꾸세요"를 따른 것이며, 저장소의 `data.json`, `public/data.json`은 지웠습니다. 문제가 생기면 이 변경 PR 하나를 Revert 하면 원상복구됩니다.

- PR을 `main`에 합친 직후 Vercel 배포가 2건 실패했습니다. 원인은 `scripts/deployment-identity.mjs`가 `step`이 1이 아니면 빌드를 막은 것이며, 수정 커밋 `83de753`이 `step` 1~2를 허용합니다. 이 수정이 `main`에 합쳐져 배포가 `Ready`가 되기 전에는 사이트에 옛 배포(공개 `data.json`)가 남아 있을 수 있습니다. 위 1번의 배포 확인이 그 증거입니다.
- `public/aleph.json`(배포 식별 파일)은 2단계부터 시작 틀 확인 표시(`sampleMarker`)를 내보내지 않습니다. 심판 판정 `S02_MARKER_IN_STATIC`이 정적 응답의 표시를 지적했기 때문입니다. 1단계는 이전과 같습니다.
- `npm run test:package` 1건(패키징 함수 기준표 일치)은 실패합니다(3단계에서 `api/notes/[id].js`가 늘어 차이가 하나 더 커졌고, 같은 원인입니다). 원래 시작 틀에서는 통과했지만, 2단계 제작 2가 만든 `api/notes.js`가 운영 쪽 고정 기준표(`package/baseline-functions.json`)에 없기 때문입니다. 기준표는 운영 쪽 파일이라 고치지 않았습니다.
- 빌드 점검: `npm run build -- --local`은 배포 식별 검사를 건너뜁니다. 배포와 같은 조건은 `VERCEL_GIT_PROVIDER=github VERCEL_GIT_REPO_OWNER=<소유자> VERCEL_GIT_REPO_SLUG=<저장소> VERCEL_GIT_COMMIT_SHA=<40자리 커밋> VERCEL_URL=<이름>.vercel.app npm run build`로 확인합니다.

#### 남은 약점

- **과거 노출은 해소되지 않았습니다.** 옛 공개 커밋 `0f9a3c9` 등에 메모 문장이 Git 이력으로 남아 있고, 옛 배포(이전 Vercel 배포와 그 `/data.json`)도 남아 있을 수 있습니다. 최신 파일에서 메모를 지운 것은 이후 노출을 줄일 뿐, 이미 공개된 것을 되돌리지 못합니다. 이력을 지우거나 옛 배포를 삭제하기 전까지 "과거 노출 해소"라고 쓰지 않습니다. (메모는 가상 자료입니다. 실제 자료였다면 이력 정리와 옛 배포 삭제가 필요합니다.)
- **(3단계에서 로그인 확인으로 막음)** **공개 API의 약점이 남아 있었습니다.** `/api/notes`는 로그인 없이 누구나 부를 수 있어서 같은 메모 네 건을 읽을 수 있습니다. 검색에서 메모가 안 나와도 이 API로는 읽힙니다. 3단계 이후에 막습니다.
- **공개 API에 호출 횟수 제한이 없습니다.** 같은 주소를 계속 호출하면 학습용 DB의 무료 사용량을 소모시킬 수 있습니다.
- **검색은 파일 내용만 봅니다.** 다른 표현이나 글자를 바꾼 사본, 캐시, 제3자가 이미 복사한 자료는 이 검색으로 찾을 수 없습니다.

## 3단계: 진짜 로그인을 붙입니다

`aleph.config.json`은 `step` 3입니다. 화면에서 로그인한 사람만 서버(`/api/notes`)에서 자기 가상 메모를 추가·조회·수정·삭제합니다.

- **로그인 화면**: Supabase Auth 이메일·비밀번호 로그인·로그아웃입니다. 공식 SDK(`@supabase/supabase-js` 2.117.2)의 브라우저용 파일을 `public/vendor/supabase.js`에 두어 `signInWithPassword`·`signOut`을 씁니다. 화면 코드에는 프로젝트 주소와 공개 키(publishable)만 있고 서버 전용 키는 없습니다. 비밀번호는 저장하지 않으며 토큰은 SDK가 이 탭의 `sessionStorage`에만 둡니다. 로그인 실패 이유(비밀번호 불일치, 이메일 미확인 등)를 화면에 보여 줍니다.
- **서버 로그인 검사**: `src/notes-api.mjs`가 요청의 `Authorization` 토큰을 시작 틀의 `src/verify-login.mjs`(수정하지 않음)로 검사합니다. 브라우저가 보낸 `userId`·`role`·`owner_id`는 읽지 않습니다. 토큰이 없거나 위조·만료·다른 서비스용이면 모두 401 `LOGIN_REQUIRED`이고 자료는 나가지 않습니다. 서버 설정이 없으면 500 `SERVER_NOT_CONFIGURED`로 닫습니다.
- **API 모양**(`aleph.config.json`의 `allowedRoutes`와 같은 5개):

| 경로 | 요청 | 응답 |
| --- | --- | --- |
| `GET /api/notes` | 없음 | 로그인한 사용자 본인의 메모 배열 `[{id,title,body}]` |
| `POST /api/notes` | `{id?,title,body}` (id는 UUID, 없으면 서버가 만듦) | 201 `{id}` (서버가 확인한 사용자 ID를 `owner_id`로 저장, 같은 id가 있으면 409) |
| `GET /api/notes/:id` | 없음 | `{id,title,body}`, 없으면 404 |
| `PUT /api/notes/:id` | `{title,body}` | 수정된 `{id,title,body}`, 없으면 404 |
| `DELETE /api/notes/:id` | 없음 | `{id}`, 지운 뒤 GET은 404 |

  `title`은 1~200자, `body`는 5000자까지이고 형식이 틀리면 400입니다. 응답에 `owner_id`는 없습니다.
- `identityProvider`: Supabase 로그인 발급자·키 목록 주소·audience를 적었습니다(비밀 키 없음). `RULE_IDS`는 여전히 `starter.deny` 하나뿐이며 6단계 전까지 늘리지 않습니다.

**알려진 허점(4단계에서 고칠 예정)**: 아직 소유자 검사를 하지 않습니다. 로그인한 B가 A의 메모 id를 알면 `GET`·`PUT`·`DELETE /api/notes/:id`로 A의 메모를 읽고 고치고 지울 수 있습니다. 목록 `GET /api/notes`는 본인 메모만 돌려주지만 한 건 경로는 막지 않습니다. 이 허점은 4단계에서 소유자 검사로 막고, B의 타인 메모 접근 결과도 그때 기록합니다. 처음의 가상 메모 4건은 `owner_id`가 비어 있어 누구의 목록에도 보이지 않습니다(DB에는 그대로 있습니다).

### 3단계 확인 기록

| 항목 | 방법 | 결과 | 실행 여부 |
| --- | --- | --- | --- |
| 로그인 후 메모 보임, 로그아웃 후 사라짐, 틀린 비밀번호 안내 | 배포 주소를 InPrivate 창에서 직접 사용 | 모두 기대대로 (이 단계의 메모 추가·수정·삭제 화면이 들어가기 전 화면 기준) | 학생이 브라우저로 확인함 (2026-10-07) |
| 로그인 없는 `/api/notes` 거부 | 시크릿 창에서 주소창으로 열기 | `{"error":"LOGIN_REQUIRED"}` | 학생이 확인함 (2026-10-07) |
| 위조·만료·다른 발급자 토큰, 쿼리로 보낸 `role`·`userId` | 학생이 F12 콘솔에서 가짜 토큰으로 요청 5건 전송 | 5건 모두 401 `LOGIN_REQUIRED` (메모 추가·수정·삭제 경로가 생기기 전의 `/api/notes` 기준) | 학생이 확인함 (2026-10-07 10:34) |
| 메모 추가·수정·삭제 API·화면 | `npm run test:r5` 13건(가짜 DB), 가짜 서버를 둔 실제 브라우저(Chromium) | 통과. 추가·수정·삭제·새로고침 유지·로그아웃 | 실행함 (2026-10-07) |
| 배포된 서버의 메모 추가·수정·삭제 | 배포 주소에서 로그인한 뒤 학생이 화면에서 직접 누름 | 추가("추가했습니다."와 카드 생성), 수정(제목 변경과 "수정했습니다."), 삭제("삭제했습니다."와 "아직 메모가 없습니다.")가 모두 됨 | 학생이 브라우저로 확인함 (2026-10-07 11:39~11:42, 배포 커밋 `5f6a285`) |
| 새로고침 뒤 로그인 유지, 삭제한 메모가 돌아오지 않음 | 삭제 뒤 F5 | 로그인이 유지되고 목록이 빈 채로 남음 | 학생이 브라우저로 확인함 (2026-10-07 11:43) |
| 추가한 카드가 새로고침 뒤에도 남음, 메모 화면에서의 로그아웃 | 같은 화면 | 직접 확인하지 못함(추가 직후 화면은 서버에서 목록을 다시 읽어 그린 것) | **미확인** |
| 배포된 서버의 메모 경로별 무로그인·가짜 토큰 거부 | 학생이 F12 콘솔에서 요청 8건 전송: 토큰 없이 GET 목록·POST·GET 한 건·PUT·DELETE, 가짜 토큰으로 POST·PUT·DELETE(쓰기는 빈 본문 또는 없는 id) | 8건 모두 401 `LOGIN_REQUIRED` | 학생이 확인함 (2026-10-07, 배포 커밋 `5f6a285`) |
| 최신 파일에 메모 문장 없음 | `git grep -n -E '실습용 가상 [과포아훈]'` | 작업 브랜치·`origin/main`(`9327fd9`) 모두 없음 (README·시험·스크립트 제외) | 실행함 (2026-10-07) |
| 샌드박스에서 배포 주소로 `curl` | — | 외부 접속이 막혀 있어 못 함 | **미실행** |
| `npm run bundle` | — | 병합 커밋 위에서는 실행되지 않으므로 일반 커밋 위에서, `bundle-notes.json`을 만든 뒤 실행 | **미실행** |
| 포털 판정(점수) | 포털 | 코딩 도구는 볼 수 없음 | 확인하지 못함 |

- `src/attack-check.mjs`의 3단계 점검은 배포 주소로 로그인 없는 GET·POST·PUT·DELETE와 가짜(위조·만료·다른 발급자) 토큰 요청을 실제로 보내고, 상태 번호(거부됨/거부되지 않음)만 기록합니다. 쓰기 요청은 빈 본문이거나 없는 id로 보내 자료가 생기거나 바뀌지 않습니다. 본문·토큰·키 값은 기록하지 않고, 심판의 판정이 아닙니다. 아직 실행하지 않았습니다.
- 다시 실행: `npm run test:r5`(로컬 시험), `npm run build -- --local`(로컬 빌드), 일반 커밋 위에서 `npm run bundle`.
- 시험 순서(학생): 시크릿 창에서 배포 주소를 열어 입력창만 보이는지, 로그인하면 새 메모 입력칸이 보이는지, 추가·수정·삭제가 되는지, 로그아웃하면 사라지는지 봅니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
