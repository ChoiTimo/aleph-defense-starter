-- 4단계 제작 3: public.notes 표만 다룹니다. 다른 표는 건드리지 않습니다.
-- 학생이 검토한 뒤 SQL Editor에서 [A] → [B] → [C] 순서로 "구역별로 따로" 선택해 실행하세요
-- (한꺼번에 실행하면 마지막 결과 표만 보입니다). [A]와 [C]의 표를 비교해 README에 적습니다.
-- 서버 함수(api/notes*.js)는 서버 전용 키(service_role)로 접근하므로 이 변경의 영향을 받지 않습니다.
-- service_role 은 PUBLIC·anon·authenticated 와 별개의 역할이라 아래 REVOKE 대상이 아닙니다.

-- ============ [A] 적용 전 확인 (읽기만 함) ============
-- A-1) 표에 부여된 권한 목록. 2단계 기록대로라면 anon·authenticated 줄이 0행이어야 합니다.
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by grantee, privilege_type;

-- A-2) 두 역할이 실제로 가진 권한(PUBLIC에서 물려받은 것 포함). 전부 false 이면 권한 없음.
select r.role_name,
       has_table_privilege(r.role_name, 'public.notes', 'SELECT')  as can_select,
       has_table_privilege(r.role_name, 'public.notes', 'INSERT')  as can_insert,
       has_table_privilege(r.role_name, 'public.notes', 'UPDATE')  as can_update,
       has_table_privilege(r.role_name, 'public.notes', 'DELETE')  as can_delete,
       has_table_privilege(r.role_name, 'public.notes', 'TRUNCATE')   as can_truncate,
       has_table_privilege(r.role_name, 'public.notes', 'REFERENCES') as can_references,
       has_table_privilege(r.role_name, 'public.notes', 'TRIGGER')    as can_trigger
from (values ('anon'), ('authenticated')) as r(role_name);

-- A-3) 지금 있는 정책과 RLS 켜짐 여부.
select policyname, cmd, roles, qual, with_check from pg_policies
where schemaname = 'public' and tablename = 'notes' order by policyname;
select relrowsecurity as rls_on from pg_class where oid = 'public.notes'::regclass;

-- ============ [B] 변경 (한 덩어리로 실행. 오류가 나면 전부 취소됨) ============
begin;

-- B-1) RLS를 켭니다(이미 켜져 있어도 같은 결과).
alter table public.notes enable row level security;

-- B-2) 기존 권한을 모두 회수합니다.
revoke all on table public.notes from public, anon, authenticated;

-- B-3) authenticated 에게 네 가지 권한만 줍니다. anon 에게는 아무것도 주지 않습니다.
grant select, insert, update, delete on table public.notes to authenticated;

-- B-4) 정책: 모두 authenticated 에게만, 본인 행(auth.uid() = owner_id)일 때만 허용합니다.
--      owner_id 가 비어 있는 행은 auth.uid() 와 같을 수 없어 아무에게도 보이지 않습니다.
drop policy if exists notes_select_own on public.notes;
drop policy if exists notes_insert_own on public.notes;
drop policy if exists notes_update_own on public.notes;
drop policy if exists notes_delete_own on public.notes;

-- 읽기: 기존 행 검사(USING)
create policy notes_select_own on public.notes
  for select to authenticated
  using (auth.uid() = owner_id);

-- 추가: 새 행 검사(WITH CHECK). 남의 owner_id 로는 넣을 수 없습니다.
create policy notes_insert_own on public.notes
  for insert to authenticated
  with check (auth.uid() = owner_id);

-- 수정: 기존 행 검사(USING)와 새 행 검사(WITH CHECK) 둘 다. 남의 행을 고칠 수 없고, owner_id 를 남에게 넘길 수도 없습니다.
create policy notes_update_own on public.notes
  for update to authenticated
  using (auth.uid() = owner_id)
  with check (auth.uid() = owner_id);

-- 삭제: 기존 행 검사(USING)
create policy notes_delete_own on public.notes
  for delete to authenticated
  using (auth.uid() = owner_id);

commit;

-- ============ [C] 적용 후 확인 (읽기만 함. [A]와 같은 질의) ============
-- C-1) 기대: authenticated 의 DELETE·INSERT·SELECT·UPDATE 4줄만. anon·PUBLIC 줄은 없음.
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by grantee, privilege_type;

-- C-2) 기대: anon 은 전부 false. authenticated 는 select·insert·update·delete 만 true,
--      truncate·references·trigger 는 false.
select r.role_name,
       has_table_privilege(r.role_name, 'public.notes', 'SELECT')  as can_select,
       has_table_privilege(r.role_name, 'public.notes', 'INSERT')  as can_insert,
       has_table_privilege(r.role_name, 'public.notes', 'UPDATE')  as can_update,
       has_table_privilege(r.role_name, 'public.notes', 'DELETE')  as can_delete,
       has_table_privilege(r.role_name, 'public.notes', 'TRUNCATE')   as can_truncate,
       has_table_privilege(r.role_name, 'public.notes', 'REFERENCES') as can_references,
       has_table_privilege(r.role_name, 'public.notes', 'TRIGGER')    as can_trigger
from (values ('anon'), ('authenticated')) as r(role_name);

-- C-3) 기대: 정책 4개(select·insert·update·delete), 모두 roles = {authenticated}, rls_on = true.
select policyname, cmd, roles, qual, with_check from pg_policies
where schemaname = 'public' and tablename = 'notes' order by cmd, policyname;
select relrowsecurity as rls_on from pg_class where oid = 'public.notes'::regclass;

-- ============ [D] 선택: 역할을 흉내 내 직접 확인 (각 구역을 따로, 끝에 rollback 이라 DB는 안 바뀜) ============
-- D-1) anon 역할로 읽기: "permission denied for table notes" 가 나와야 정상.
begin; set local role anon; select * from public.notes; rollback;

-- D-2) A 로 로그인한 것처럼 읽기: A의 메모만 보여야 합니다. <<A_EMAIL>> 은 실행할 때만 바꾸세요(저장·커밋 금지).
begin;
  select set_config('request.jwt.claims',
    json_build_object('sub', (select id from auth.users where lower(email) = lower('<<A_EMAIL>>')), 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) as visible_to_A from public.notes;                -- 기대: A의 메모 수
  select count(*) as owned_by_other from public.notes
   where owner_id is distinct from auth.uid();                      -- 기대: 0
rollback;
