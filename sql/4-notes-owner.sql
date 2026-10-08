-- 4단계 제작 1: 기존 가상 메모 세 개를 A의 것으로 연결합니다. (학습용 DB의 SQL Editor에서 학생이 검토 후 직접 실행)
-- 이메일은 이 파일에 적지 않습니다. 실행할 때만 SQL Editor 화면에서 아래 두 자리표시자를 바꾸고,
-- 바꾼 상태로 저장·커밋하지 마세요.
--   <<A_EMAIL>> → A 계정의 로그인 이메일     <<B_EMAIL>> → B 계정의 로그인 이메일
-- 이 SQL은 public.notes 의 owner_id 칸만 바꿉니다. 메모 제목·본문은 건드리지 않습니다.
-- API 코드와 권한 정책(RLS)은 이 파일에서 바꾸지 않습니다.

-- [1] 두 계정의 ID를 찾아 봅니다. 두 줄이 나와야 하고 id 두 값이 서로 달라야 합니다.
select 'A' as who, id from auth.users where lower(email) = lower('<<A_EMAIL>>')
union all
select 'B' as who, id from auth.users where lower(email) = lower('<<B_EMAIL>>');

-- [2] A의 메모 연결. 순서 칸(position) 1·2·3번 메모 중 아직 주인이 없는 것만 A로 연결합니다.
--     (4번째 메모는 그대로 둡니다 = owner_id 비어 있음 = 누구의 목록에도 안 보임)
--     A·B 계정을 못 찾거나, 연결 뒤 A의 메모가 정확히 3개가 아니면 오류를 내고 전체를 취소합니다.
--     이미 A로 연결되어 있으면 다시 실행해도 같은 결과입니다.
do $$
declare
  a_id uuid;
  b_id uuid;
  a_count int;
begin
  select id into a_id from auth.users where lower(email) = lower('<<A_EMAIL>>');
  select id into b_id from auth.users where lower(email) = lower('<<B_EMAIL>>');
  if a_id is null then raise exception 'A 계정을 auth.users에서 찾지 못했습니다. 이메일을 확인하세요.'; end if;
  if b_id is null then raise exception 'B 계정을 auth.users에서 찾지 못했습니다. 이메일을 확인하세요.'; end if;
  if a_id = b_id then raise exception 'A와 B가 같은 계정입니다. 서로 다른 시험 계정이어야 합니다.'; end if;

  update public.notes
     set owner_id = a_id
   where owner_id is null and position in (1, 2, 3);

  select count(*) into a_count from public.notes where owner_id = a_id and position in (1, 2, 3);
  if a_count <> 3 then
    raise exception 'position 1~3 메모 중 A 소유가 % 개입니다(3개여야 함). 아래 [3] 확인 표로 현재 상태를 보고 다시 판단하세요.', a_count;
  end if;
end $$;

-- B 소유의 공개 가능한 시험 메모 한 건은 메모 본문이 들어 있어 Git에 두지 않았습니다.
-- supabase/4-b-test-note.sql (Git 제외 폴더)을 이어서 실행하세요.

-- [3] 확인: A는 position 1·2·3 세 건, B는 시험 메모 한 건(B 메모를 넣은 뒤)이 보여야 합니다.
--     소유자는 이메일이 아니라 A / B / 없음으로만 표시합니다.
select n.position, n.id,
       case when n.owner_id is null then '없음'
            when n.owner_id = (select id from auth.users where lower(email) = lower('<<A_EMAIL>>')) then 'A'
            when n.owner_id = (select id from auth.users where lower(email) = lower('<<B_EMAIL>>')) then 'B'
            else '다른 사용자' end as owner
from public.notes n
order by n.position nulls last, n.created_at;
