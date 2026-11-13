-- Kør denne EFTER supabase-firmakonto-setup.sql (den opretter user_roles og is_admin()).
-- Giver: delte, redigerbare priser/varer og administration af administratorer.
-- Kan køres flere gange uden skade.

-- 1) Delt katalog (priser, varer, indkøbspriser) --------------------------
create table if not exists public.app_settings (
  id boolean primary key default true check (id),
  config jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null
);
alter table public.app_settings enable row level security;
grant select, insert, update on public.app_settings to authenticated;

drop policy if exists "Signed-in users can read settings" on public.app_settings;
create policy "Signed-in users can read settings" on public.app_settings
  for select to authenticated using (true);
drop policy if exists "Admins can insert settings" on public.app_settings;
create policy "Admins can insert settings" on public.app_settings
  for insert to authenticated with check (public.is_admin());
drop policy if exists "Admins can update settings" on public.app_settings;
create policy "Admins can update settings" on public.app_settings
  for update to authenticated using (public.is_admin()) with check (public.is_admin());

-- 2) Administrer administratorer fra siden ---------------------------------
create or replace function public.set_user_role(p_email text, p_role text) returns void
language plpgsql security definer set search_path = public as $$
declare v_id uuid;
begin
  if not public.is_admin() then raise exception 'Kun administratorer kan ændre roller'; end if;
  if p_role not in ('admin', 'employee') then raise exception 'Ugyldig rolle'; end if;
  select id into v_id from auth.users where lower(email) = lower(p_email);
  if v_id is null then raise exception 'Brugeren blev ikke fundet. Tjek navnet.'; end if;
  if v_id = (select auth.uid()) and p_role <> 'admin' then
    raise exception 'Du kan ikke fjerne din egen administratoradgang.';
  end if;
  insert into public.user_roles (user_id, role) values (v_id, p_role)
  on conflict (user_id) do update set role = excluded.role;
end
$$;
revoke all on function public.set_user_role(text, text) from public;
grant execute on function public.set_user_role(text, text) to authenticated;

create or replace function public.list_roles() returns table (user_id uuid, email text, role text)
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Kun administratorer kan se roller'; end if;
  return query
    select r.user_id, u.email::text, r.role
    from public.user_roles r join auth.users u on u.id = r.user_id
    order by u.email;
end
$$;
revoke all on function public.list_roles() from public;
grant execute on function public.list_roles() to authenticated;

-- 3) Live-opdatering af priser ---------------------------------------------
do $$
begin
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'app_settings') then
    execute 'alter publication supabase_realtime add table public.app_settings';
  end if;
end
$$;

-- 4) Den allerførste administrator (kun nødvendigt hvis ingen endnu er admin) -----
-- Fjern -- og ret e-mailen (fornavn.efternavn@login.autoexotic.dk), og kør:
-- insert into public.user_roles (user_id, role)
-- select id, 'admin' from auth.users where email = 'fornavn.efternavn@login.autoexotic.dk'
-- on conflict (user_id) do update set role = 'admin';
