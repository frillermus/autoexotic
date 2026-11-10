

create table if not exists public.receipts (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id) on delete set null,
  created_by_name text not null default '',
  kind text not null check (kind in ('police', 'civil')),
  receipt_data jsonb not null
);

alter table public.receipts enable row level security;
grant select, insert, delete on public.receipts to authenticated;

drop policy if exists "Users can view their own receipts" on public.receipts;
drop policy if exists "Users can insert their own receipts" on public.receipts;
drop policy if exists "Users can update their own receipts" on public.receipts;
drop policy if exists "Users can delete their own receipts" on public.receipts;


drop policy if exists "Signed-in employees can read shared receipts" on public.receipts;
create policy "Signed-in employees can read shared receipts"
  on public.receipts for select to authenticated
  using (true);


drop policy if exists "Employees can add their own receipts" on public.receipts;
create policy "Employees can add their own receipts"
  on public.receipts for insert to authenticated
  with check (created_by = (select auth.uid()));


drop policy if exists "Employees can delete their own receipts" on public.receipts;
create policy "Employees can delete their own receipts"
  on public.receipts for delete to authenticated
  using (created_by = (select auth.uid()));

do $$
begin
  if not exists (
    select 1
    from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'receipts'
  ) then
    execute 'alter publication supabase_realtime add table public.receipts';
  end if;
end
$$;
