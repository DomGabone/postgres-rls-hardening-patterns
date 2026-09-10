create or replace function public.log_audit_event()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  cfg public.audit_config%rowtype;
  has_cfg boolean;
  v_old jsonb;
  v_new jsonb;
  field text;
begin
  select * into cfg from public.audit_config c where c.table_name = tg_table_name;
  has_cfg := found;

  if has_cfg then
    if not cfg.enabled then
      return coalesce(new, old);
    end if;
    if tg_op = 'INSERT' and not cfg.log_insert then return new; end if;
    if tg_op = 'UPDATE' and not cfg.log_update then return new; end if;
    if tg_op = 'DELETE' and not cfg.log_delete then return old; end if;
  end if;

  if tg_op in ('UPDATE', 'DELETE') then v_old := to_jsonb(old); end if;
  if tg_op in ('INSERT', 'UPDATE') then v_new := to_jsonb(new); end if;

  if has_cfg then
    foreach field in array cfg.excluded_fields loop
      v_old := v_old - field;
      v_new := v_new - field;
    end loop;
    foreach field in array cfg.sensitive_fields loop
      if v_old ? field then v_old := jsonb_set(v_old, array[field], '"***"'::jsonb); end if;
      if v_new ? field then v_new := jsonb_set(v_new, array[field], '"***"'::jsonb); end if;
    end loop;
  end if;

  if tg_op = 'UPDATE' and v_old = v_new then
    return new;
  end if;

  insert into public.audit_log (table_name, operation, row_id, actor, old_data, new_data)
  values (
    tg_table_name,
    tg_op,
    coalesce(v_new ->> 'id', v_old ->> 'id',
             coalesce(v_new ->> 'store_id', v_old ->> 'store_id') || ':' ||
             coalesce(v_new ->> 'member_id', v_old ->> 'member_id')),
    auth.uid(),
    v_old,
    v_new
  );

  return coalesce(new, old);
end;
$$;

revoke execute on function public.log_audit_event() from public, anon, authenticated;

create trigger audit_stores
  after insert or update or delete on public.stores
  for each row execute function public.log_audit_event();

create trigger audit_store_members
  after insert or update or delete on public.store_members
  for each row execute function public.log_audit_event();

create trigger audit_books
  after insert or update or delete on public.books
  for each row execute function public.log_audit_event();

create trigger audit_orders
  after insert or update or delete on public.orders
  for each row execute function public.log_audit_event();

insert into public.audit_config (table_name, sensitive_fields, excluded_fields) values
  ('stores',        '{}',              '{}'),
  ('store_members', '{}',              '{}'),
  ('books',         '{}',              '{updated_at}'),
  ('orders',        '{total_cents}',   '{}');
