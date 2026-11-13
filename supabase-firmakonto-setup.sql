-- Tilføjelse til den eksisterende opsætning (receipts-tabellen skal allerede findes).
-- Kør hele filen i Supabase SQL-editoren. Den kan køres flere gange uden skade.
-- Giver: administratorrolle, firmakonto, automatiske ordrenumre og indkøbspriser.

-- 1) Roller ---------------------------------------------------------------
create table if not exists public.user_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('admin', 'employee')) default 'employee'
);
alter table public.user_roles enable row level security;
grant select on public.user_roles to authenticated;
drop policy if exists "Users can read own role" on public.user_roles;
create policy "Users can read own role" on public.user_roles
  for select to authenticated using (user_id = (select auth.uid()));

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles r where r.user_id = (select auth.uid()) and r.role = 'admin')
$$;
revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to authenticated;

-- 2) Firmakonto -----------------------------------------------------------
-- Saldoen er summen af alle bevægelser (delta). Bevægelser kan ikke rettes eller slettes.
create table if not exists public.company_transactions (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id) on delete set null,
  created_by_name text not null default '',
  type text not null check (type in ('sale', 'refund', 'deposit', 'withdraw', 'adjust')),
  delta numeric(14,2) not null,
  note text not null default '',
  order_no bigint,
  receipt_id uuid references public.receipts(id) on delete set null
);
create index if not exists company_transactions_created_at_idx on public.company_transactions (created_at desc);

alter table public.company_transactions enable row level security;
grant select, insert on public.company_transactions to authenticated;

drop policy if exists "Signed-in users can read account" on public.company_transactions;
create policy "Signed-in users can read account" on public.company_transactions
  for select to authenticated using (true);

-- Kun administratorer kan indsætte/hæve/justere manuelt. Salg og sletninger sker via funktionerne nedenfor.
drop policy if exists "Admins can add manual account entries" on public.company_transactions;
create policy "Admins can add manual account entries" on public.company_transactions
  for insert to authenticated
  with check (public.is_admin() and created_by = (select auth.uid()) and type in ('deposit', 'withdraw', 'adjust'));

create or replace function public.company_balance() returns numeric
language sql stable security definer set search_path = public as $$
  select case when (select auth.uid()) is null then null
              else coalesce((select sum(delta) from public.company_transactions), 0) end
$$;
revoke all on function public.company_balance() from public;
grant execute on function public.company_balance() to authenticated;

-- 3) Automatiske ordrenumre + gem kvittering og læg salget på firmakontoen i ét trin
create sequence if not exists public.order_number_seq start 1;

create or replace function public.save_receipt(p_kind text, p_name text, p_data jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := (select auth.uid());
  v_no bigint;
  v_id uuid;
  v_total numeric;
begin
  if v_uid is null then raise exception 'Ikke logget ind'; end if;
  if p_kind not in ('police', 'civil') then raise exception 'Ugyldig kvitteringstype'; end if;
  v_no := nextval('public.order_number_seq');
  v_total := coalesce((p_data ->> 'total')::numeric, 0);

  insert into public.receipts (created_by, created_by_name, kind, receipt_data)
  values (v_uid, coalesce(p_name, ''), p_kind, p_data || jsonb_build_object('orderNo', v_no))
  returning id into v_id;

  if v_total > 0 then
    insert into public.company_transactions (created_by, created_by_name, type, delta, note, order_no, receipt_id)
    values (v_uid, coalesce(p_name, ''), 'sale', v_total,
            'Ordre nr. ' || v_no || coalesce(' – ' || nullif(p_data ->> 'name', ''), ''), v_no, v_id);
  end if;

  return jsonb_build_object('id', v_id, 'order_no', v_no);
end
$$;
revoke all on function public.save_receipt(text, text, jsonb) from public;
grant execute on function public.save_receipt(text, text, jsonb) to authenticated;

-- Sletter nogen en kvittering med ordrenummer, trækkes beløbet automatisk fra firmakontoen igen.
create or replace function public.receipt_deleted() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_total numeric := coalesce((old.receipt_data ->> 'total')::numeric, 0);
begin
  if v_total > 0 and old.receipt_data ? 'orderNo' then
    insert into public.company_transactions (created_by, created_by_name, type, delta, note, order_no)
    values ((select auth.uid()), 'Automatisk', 'refund', -v_total,
            'Slettet ordre nr. ' || (old.receipt_data ->> 'orderNo'), (old.receipt_data ->> 'orderNo')::bigint);
  end if;
  return old;
end
$$;
drop trigger if exists receipt_deleted_trg on public.receipts;
create trigger receipt_deleted_trg after delete on public.receipts
  for each row execute function public.receipt_deleted();

-- 4) Indkøbspriser (til profit) -------------------------------------------
create table if not exists public.item_costs (
  item_key text primary key,
  cost numeric(14,2) not null default 0 check (cost >= 0),
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null
);
alter table public.item_costs enable row level security;
grant select, insert, update, delete on public.item_costs to authenticated;

drop policy if exists "Signed-in users can read item costs" on public.item_costs;
create policy "Signed-in users can read item costs" on public.item_costs
  for select to authenticated using (true);
drop policy if exists "Admins can insert item costs" on public.item_costs;
create policy "Admins can insert item costs" on public.item_costs
  for insert to authenticated with check (public.is_admin());
drop policy if exists "Admins can update item costs" on public.item_costs;
create policy "Admins can update item costs" on public.item_costs
  for update to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists "Admins can delete item costs" on public.item_costs;
create policy "Admins can delete item costs" on public.item_costs
  for delete to authenticated using (public.is_admin());

-- 5) Live-opdatering ------------------------------------------------------
do $$
begin
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'company_transactions') then
    execute 'alter publication supabase_realtime add table public.company_transactions';
  end if;
end
$$;

-- 6) Gør dig selv til administrator --------------------------------------
-- Fjern -- og ret e-mailen til din egen login-adresse (fornavn.efternavn@login.autoexotic.dk), og kør:
-- insert into public.user_roles (user_id, role)
-- select id, 'admin' from auth.users where email = 'fornavn.efternavn@login.autoexotic.dk'
-- on conflict (user_id) do update set role = 'admin';
