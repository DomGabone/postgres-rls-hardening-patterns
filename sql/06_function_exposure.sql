create or replace function public.functions_executable_by(p_role text)
returns table (function_name text, arguments text, is_security_definer boolean)
language sql
stable
security definer
set search_path = ''
as $$
  select p.proname::text,
         pg_catalog.pg_get_function_identity_arguments(p.oid),
         p.prosecdef
  from pg_catalog.pg_proc p
  join pg_catalog.pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and pg_catalog.has_function_privilege(p_role, p.oid, 'execute')
  order by 1, 2;
$$;

revoke execute on function public.functions_executable_by(text) from public, anon, authenticated;

do $$
declare
  f record;
begin
  for f in
    select p.oid::regprocedure as signature
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and pg_catalog.has_function_privilege('anon', p.oid, 'execute')
  loop
    execute format('revoke execute on function %s from public, anon', f.signature);
  end loop;
end
$$;
