-- Offentlig medarbejderoversigt for indloggede medarbejdere.
-- Viser kun navn og rolle; e-mail, bruger-id og login-tider deles ikke.
-- Kan køres efter resten af dette setup.
create or replace function public.list_employee_directory()
returns table (full_name text, role text)
language sql security definer set search_path = public, auth as $$
  select coalesce(nullif(trim(u.raw_user_meta_data ->> 'full_name'), ''), 'Medarbejder')::text,
         coalesce(r.role, 'employee')::text
  from auth.users u
  left join public.user_roles r on r.user_id = u.id
  order by lower(coalesce(nullif(trim(u.raw_user_meta_data ->> 'full_name'), ''), 'Medarbejder'));
$$;
revoke all on function public.list_employee_directory() from public, anon;
grant execute on function public.list_employee_directory() to authenticated;
