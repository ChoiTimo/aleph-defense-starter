-- Only redacted successful API-result metadata. No note or identity columns.
create table if not exists public.operations_audit (
  id uuid primary key,
  at timestamptz not null,
  kind text not null check (kind in ('note_restore', 'demo_revocation')),
  version text,
  check ((kind = 'note_restore' and version is not null and version ~ '^[a-f0-9]{64}$')
    or (kind = 'demo_revocation' and version is null))
);
create index if not exists operations_audit_recent on public.operations_audit (at desc, id desc);
alter table public.operations_audit enable row level security;
revoke all on table public.operations_audit from public, anon, authenticated;
grant select, insert on table public.operations_audit to service_role;
