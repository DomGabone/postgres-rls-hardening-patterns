create or replace function public.is_platform_admin(p_uid uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.profiles p
    where p.id = p_uid
      and p.is_platform_admin
  );
$$;

create or replace function public.owns_store(p_uid uuid, p_store uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.stores s
    where s.id = p_store
      and s.owner_id = p_uid
  );
$$;

create or replace function public.store_permission_of(p_uid uuid, p_store uuid)
returns public.store_permission
language sql
stable
security definer
set search_path = ''
as $$
  select case
    when public.owns_store(p_uid, p_store) then 'manage'::public.store_permission
    else (
      select m.permission
      from public.store_members m
      where m.store_id = p_store
        and m.member_id = p_uid
    )
  end;
$$;

create or replace function public.can_manage_store(p_uid uuid, p_store uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select public.is_platform_admin(p_uid)
      or public.store_permission_of(p_uid, p_store) = 'manage'::public.store_permission;
$$;

create or replace function public.assert_can_manage_store(p_store uuid)
returns void
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not coalesce(public.can_manage_store(auth.uid(), p_store), false) then
    raise exception 'sem permissao para gerenciar a loja %', p_store
      using errcode = '42501';
  end if;
end;
$$;

create or replace function public.demo_unsafe_assert_can_edit_store(p_store uuid)
returns void
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if public.store_permission_of(auth.uid(), p_store) = 'view'::public.store_permission then
    raise exception 'somente leitura na loja %', p_store
      using errcode = '42501';
  end if;
end;
$$;

create or replace function public.assert_can_edit_store(p_store uuid)
returns void
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if coalesce(
       public.store_permission_of(auth.uid(), p_store)
         in ('edit'::public.store_permission, 'manage'::public.store_permission),
       false
     ) is not true
  then
    raise exception 'sem permissao de edicao na loja %', p_store
      using errcode = '42501';
  end if;
end;
$$;

grant execute on function public.is_platform_admin(uuid) to authenticated;
grant execute on function public.owns_store(uuid, uuid) to authenticated;
grant execute on function public.store_permission_of(uuid, uuid) to authenticated;
grant execute on function public.can_manage_store(uuid, uuid) to authenticated;
grant execute on function public.assert_can_manage_store(uuid) to authenticated;
grant execute on function public.assert_can_edit_store(uuid) to authenticated;
grant execute on function public.demo_unsafe_assert_can_edit_store(uuid) to authenticated;
