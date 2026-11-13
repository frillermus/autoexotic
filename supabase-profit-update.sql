-- Opdatering: kun profit (salgspris minus indkøbspris) lægges på firmakontoen.
-- Varer uden indkøbspris tæller med hele salgsprisen. Kan køres flere gange.

create or replace function public.save_receipt(p_kind text, p_name text, p_data jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := (select auth.uid());
  v_no bigint;
  v_id uuid;
  v_amount numeric;
begin
  if v_uid is null then raise exception 'Ikke logget ind'; end if;
  if p_kind not in ('police', 'civil') then raise exception 'Ugyldig kvitteringstype'; end if;
  v_no := nextval('public.order_number_seq');
  -- profit hvis den findes på kvitteringen, ellers hele totalen
  v_amount := coalesce((p_data ->> 'profit')::numeric, (p_data ->> 'total')::numeric, 0);

  insert into public.receipts (created_by, created_by_name, kind, receipt_data)
  values (v_uid, coalesce(p_name, ''), p_kind, p_data || jsonb_build_object('orderNo', v_no))
  returning id into v_id;

  if v_amount <> 0 then
    insert into public.company_transactions (created_by, created_by_name, type, delta, note, order_no, receipt_id)
    values (v_uid, coalesce(p_name, ''), 'sale', v_amount,
            'Ordre nr. ' || v_no || coalesce(' – ' || nullif(p_data ->> 'name', ''), ''), v_no, v_id);
  end if;

  return jsonb_build_object('id', v_id, 'order_no', v_no);
end
$$;

-- Sletning trækker præcis det beløb fra igen, som ordren lagde på kontoen (også for ældre ordrer).
create or replace function public.receipt_deleted() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_no bigint;
  v_amount numeric;
begin
  if old.receipt_data ? 'orderNo' then
    v_no := (old.receipt_data ->> 'orderNo')::bigint;
    select coalesce(sum(delta), 0) into v_amount
      from public.company_transactions where type = 'sale' and order_no = v_no;
    if v_amount <> 0 then
      insert into public.company_transactions (created_by, created_by_name, type, delta, note, order_no)
      values ((select auth.uid()), 'Automatisk', 'refund', -v_amount, 'Slettet ordre nr. ' || v_no, v_no);
    end if;
  end if;
  return old;
end
$$;
