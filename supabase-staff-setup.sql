-- Medarbejderliste: ansæt, ny kode, rolleskift og afskedigelse fra siden.
-- Kør EFTER supabase-firmakonto-setup.sql og supabase-admin-setup.sql. Kan køres flere gange.
-- Alle funktioner kræver at brugeren er administrator. Åben tilmelding er IKKE nødvendig (og bør forblive slået fra).

create or replace function public.hire_employee(p_email text, p_name text, p_password text, p_role text default 'employee')
returns uuid language plpgsql security definer set search_path = public, extensions, auth as $$
declare
  v_id uuid := gen_random_uuid();
begin
  if not public.is_admin() then raise exception 'Kun administratorer kan ansætte medarbejdere'; end if;
  if p_role not in ('admin', 'employee') then raise exception 'Ugyldig rolle'; end if;
  if p_email !~ '^[a-z0-9]+(\.[a-z0-9]+)+@login\.autoexotic\.dk$' then raise exception 'Ugyldigt navn'; end if;
  if length(coalesce(p_password, '')) < 6 then raise exception 'Koden skal være mindst 6 tegn.'; end if;
  if exists (select 1 from auth.users where lower(email) = lower(p_email)) then
    raise exception 'Der findes allerede en medarbejder med det navn.';
  end if;

  insert into auth.users (
    instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
    confirmation_token, recovery_token, email_change_token_new, email_change
  ) values (
    '00000000-0000-0000-0000-000000000000', v_id, 'authenticated', 'authenticated', lower(p_email),
    crypt(p_password, gen_salt('bf')), now(),
    '{"provider":"email","providers":["email"]}'::jsonb,
    jsonb_build_object('full_name', trim(p_name), 'email_verified', true),
    now(), now(), '', '', '', ''
  );

  insert into auth.identities (id, user_id, identity_data, provider, provider_id, last_sign_in_at, created_at, updated_at)
  values (gen_random_uuid(), v_id,
          jsonb_build_object('sub', v_id::text, 'email', lower(p_email), 'email_verified', true),
          'email', v_id::text, now(), now(), now());

  insert into public.user_roles (user_id, role) values (v_id, p_role)
  on conflict (user_id) do update set role = excluded.role;

  return v_id;
end
$$;
revoke all on function public.hire_employee(text, text, text, text) from public;
grant execute on function public.hire_employee(text, text, text, text) to authenticated;

create or replace function public.list_employees()
returns table (user_id uuid, email text, full_name text, role text, created_at timestamptz, last_sign_in_at timestamptz)
language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_admin() then raise exception 'Kun administratorer kan se medarbejdere'; end if;
  return query
    select u.id, u.email::text, coalesce(u.raw_user_meta_data ->> 'full_name', ''),
           coalesce(r.role, 'employee'), u.created_at, u.last_sign_in_at
    from auth.users u
    left join public.user_roles r on r.user_id = u.id
    order by lower(coalesce(nullif(u.raw_user_meta_data ->> 'full_name', ''), u.email));
end
$$;
revoke all on function public.list_employees() from public;
grant execute on function public.list_employees() to authenticated;

create or replace function public.set_employee_password(p_user_id uuid, p_password text)
returns void language plpgsql security definer set search_path = public, extensions, auth as $$
begin
  if not public.is_admin() then raise exception 'Kun administratorer kan sætte ny kode'; end if;
  if length(coalesce(p_password, '')) < 6 then raise exception 'Koden skal være mindst 6 tegn.'; end if;
  update auth.users set encrypted_password = crypt(p_password, gen_salt('bf')), updated_at = now() where id = p_user_id;
  if not found then raise exception 'Medarbejderen blev ikke fundet.'; end if;
end
$$;
revoke all on function public.set_employee_password(uuid, text) from public;
grant execute on function public.set_employee_password(uuid, text) to authenticated;

-- Afskedigelse sletter kontoen. Kvitteringer og kontobevægelser beholdes (med navnet).
create or replace function public.fire_employee(p_user_id uuid)
returns void language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_admin() then raise exception 'Kun administratorer kan afskedige'; end if;
  if p_user_id = (select auth.uid()) then raise exception 'Du kan ikke afskedige dig selv.'; end if;
  delete from auth.users where id = p_user_id;
  if not found then raise exception 'Medarbejderen blev ikke fundet.'; end if;
end
$$;
revoke all on function public.fire_employee(uuid) from public;
grant execute on function public.fire_employee(uuid) to authenticated;
