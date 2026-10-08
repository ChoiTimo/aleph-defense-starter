-- 2단계 제작 1: 학습용 Supabase notes 표의 구조와 권한입니다.
-- 가상 메모 4건을 넣는 문장은 메모 본문이 들어 있어 Git에 두지 않습니다(학생이 SQL Editor에서 따로 실행).
-- 실제 키·비밀번호는 필요 없습니다.

create table if not exists public.notes (
  id         uuid primary key default gen_random_uuid(),
  owner_id   uuid,  -- 3단계 로그인에서 채울 칸. auth.users 외래키는 걸지 않습니다.
  position   int,   -- 화면에 보이는 순서(1, 2, 3, 4). 원래 자료의 순서를 지킵니다.
  title      text not null,
  content    text not null,
  created_at timestamptz not null default now()
);

-- 이미 만든 표에는 칸만 더합니다(새로 만들 때는 위에 포함됨).
alter table public.notes add column if not exists position int;

-- RLS를 켜고 정책은 만들지 않습니다. 정책이 없으면 anon·authenticated는 읽을 수 없습니다.
alter table public.notes enable row level security;

-- 표 권한도 회수합니다. 서버 함수(api/notes.js)만 서버 전용 키로 읽습니다.
revoke all on table public.notes from anon, authenticated;

-- 확인(2026-10-06 학생이 SQL Editor에서 실행한 결과는 README에 기록):
-- owner_id 칸 형식: uuid
select column_name, data_type from information_schema.columns
where table_schema = 'public' and table_name = 'notes' and column_name = 'owner_id';
-- 외래키 개수: 0
select count(*) as foreign_keys from pg_constraint
where conrelid = 'public.notes'::regclass and contype = 'f';
-- RLS: true
select relrowsecurity as rls_on from pg_class where oid = 'public.notes'::regclass;
-- anon·authenticated 권한: 0행
select grantee, privilege_type from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'notes' and grantee in ('anon', 'authenticated');
-- anon 역할로 읽기: permission denied for table notes 가 나와야 정상
begin; set local role anon; select * from public.notes; rollback;
