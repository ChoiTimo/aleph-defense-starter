-- 5단계 제작 2: public.notes 표만 다룹니다. 다른 표는 건드리지 않습니다.
-- 브라우저·외부가 공개 키(anon)나 로그인 토큰(authenticated)으로 Data API(/rest/v1/notes)를 직접 부르는 길을 닫습니다.
-- 메모 읽기·추가·수정·삭제는 서버 함수(api/notes*.js)만 서버 전용 키(service_role)로 합니다.
-- service_role 은 PUBLIC·anon·authenticated 와 별개의 역할이라 아래 REVOKE 대상이 아니며, 서버 함수는 그대로 작동합니다.
-- 학생이 검토한 뒤 SQL Editor에서 [A] → [B] → [C] 순서로 "구역별로 따로" 선택해 실행하세요.
-- RLS(켜짐)와 4단계 정책 4개는 지우지 않고 그대로 둡니다. 권한이 없으니 정책까지 가기 전에 막힙니다(두 겹).
-- 되돌리려면 sql/4-notes-rls.sql 의 [B] 구역을 다시 실행하세요(내 자료만 보이는 정책과 함께 권한이 돌아옵니다).

-- ============ [A] 적용 전 확인 (읽기만 함) ============
-- A-1) 4단계 적용 상태라면 authenticated 의 DELETE·INSERT·SELECT·UPDATE 4줄이 보입니다.
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated', 'service_role')
order by grantee, privilege_type;

-- A-2) 실제 보유 권한(PUBLIC에서 물려받은 것 포함). 기대: authenticated 는 4개 true, anon 은 전부 false.
select r.role_name,
       has_table_privilege(r.role_name, 'public.notes', 'SELECT') as can_select,
       has_table_privilege(r.role_name, 'public.notes', 'INSERT') as can_insert,
       has_table_privilege(r.role_name, 'public.notes', 'UPDATE') as can_update,
       has_table_privilege(r.role_name, 'public.notes', 'DELETE') as can_delete
from (values ('anon'), ('authenticated'), ('service_role')) as r(role_name);

-- ============ [B] 변경 (한 덩어리로 실행. 오류가 나면 전부 취소됨) ============
begin;
revoke all on table public.notes from public, anon, authenticated;
commit;

-- ============ [C] 적용 후 확인 (읽기만 함. [A]와 같은 질의) ============
-- C-1) 기대: PUBLIC·anon·authenticated 줄이 없음(0행). service_role 줄만 남을 수 있음.
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated', 'service_role')
order by grantee, privilege_type;

-- C-2) 기대: anon·authenticated 는 전부 false, service_role 은 전부 true(서버 함수가 쓰는 역할).
select r.role_name,
       has_table_privilege(r.role_name, 'public.notes', 'SELECT') as can_select,
       has_table_privilege(r.role_name, 'public.notes', 'INSERT') as can_insert,
       has_table_privilege(r.role_name, 'public.notes', 'UPDATE') as can_update,
       has_table_privilege(r.role_name, 'public.notes', 'DELETE') as can_delete
from (values ('anon'), ('authenticated'), ('service_role')) as r(role_name);

-- C-3) 기대: rls_on = true (그대로).
select relrowsecurity as rls_on from pg_class where oid = 'public.notes'::regclass;

-- ============ [D] 선택: 역할을 흉내 내 직접 확인 (각 구역을 따로, 끝에 rollback 이라 DB는 안 바뀜) ============
-- D-1) 기대: "permission denied for table notes"
begin; set local role anon; select * from public.notes; rollback;
-- D-2) 기대: "permission denied for table notes" (4단계에서는 본인 메모가 보였지만 이제 직접 길은 닫힘)
begin; set local role authenticated; select * from public.notes; rollback;
