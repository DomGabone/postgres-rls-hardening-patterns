alter table public.profiles enable row level security;
alter table public.stores enable row level security;
alter table public.store_members enable row level security;
alter table public.books enable row level security;
alter table public.orders enable row level security;
alter table public.audit_config enable row level security;
alter table public.audit_log enable row level security;

revoke insert, update, delete on all tables in schema public from anon;
revoke select on public.profiles, public.stores, public.store_members, public.orders from anon;

create policy profiles_select_self_or_admin on public.profiles
  for select to authenticated
  using (id = auth.uid() or public.is_platform_admin(auth.uid()));

create policy profiles_update_self on public.profiles
  for update to authenticated
  using (id = auth.uid())
  with check (id = auth.uid() and is_platform_admin = false);

create policy stores_select_visible on public.stores
  for select to authenticated
  using (public.store_permission_of(auth.uid(), id) is not null
      or public.is_platform_admin(auth.uid()));

create policy stores_insert_as_owner on public.stores
  for insert to authenticated
  with check (owner_id = auth.uid());

create policy stores_update_manager on public.stores
  for update to authenticated
  using (public.can_manage_store(auth.uid(), id))
  with check (public.can_manage_store(auth.uid(), id));

create policy stores_delete_owner on public.stores
  for delete to authenticated
  using (public.owns_store(auth.uid(), id));

create policy members_select_same_store on public.store_members
  for select to authenticated
  using (public.store_permission_of(auth.uid(), store_id) is not null);

create policy members_write_manager on public.store_members
  for all to authenticated
  using (public.can_manage_store(auth.uid(), store_id))
  with check (public.can_manage_store(auth.uid(), store_id));

create policy books_public_catalog on public.books
  for select to anon, authenticated
  using (true);

create policy books_write_editor on public.books
  for all to authenticated
  using (public.store_permission_of(auth.uid(), store_id)
           in ('edit'::public.store_permission, 'manage'::public.store_permission))
  with check (public.store_permission_of(auth.uid(), store_id)
           in ('edit'::public.store_permission, 'manage'::public.store_permission));

create policy orders_select_customer_or_staff on public.orders
  for select to authenticated
  using (customer_id = auth.uid()
      or public.store_permission_of(auth.uid(), store_id) is not null);

create policy orders_insert_as_customer on public.orders
  for insert to authenticated
  with check (customer_id = auth.uid());

create policy orders_update_manager on public.orders
  for update to authenticated
  using (public.can_manage_store(auth.uid(), store_id))
  with check (public.can_manage_store(auth.uid(), store_id));

create policy audit_config_admin_read on public.audit_config
  for select to authenticated
  using (public.is_platform_admin(auth.uid()));

create policy audit_log_admin_read on public.audit_log
  for select to authenticated
  using (public.is_platform_admin(auth.uid()));
