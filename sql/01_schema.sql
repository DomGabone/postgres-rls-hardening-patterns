create extension if not exists pgcrypto;

create table public.profiles (
  id uuid primary key,
  display_name text not null,
  is_platform_admin boolean not null default false
);

create table public.stores (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles(id),
  name text not null,
  created_at timestamptz not null default now()
);

create type public.store_permission as enum ('view', 'edit', 'manage');

create table public.store_members (
  store_id uuid not null references public.stores(id) on delete cascade,
  member_id uuid not null references public.profiles(id) on delete cascade,
  permission public.store_permission not null default 'view',
  primary key (store_id, member_id)
);

create table public.books (
  id uuid primary key default gen_random_uuid(),
  store_id uuid not null references public.stores(id) on delete cascade,
  title text not null,
  price_cents integer not null check (price_cents >= 0),
  stock integer not null default 0 check (stock >= 0),
  updated_at timestamptz not null default now()
);

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  store_id uuid not null references public.stores(id),
  customer_id uuid not null references public.profiles(id),
  total_cents integer not null check (total_cents >= 0),
  status text not null default 'open',
  created_at timestamptz not null default now()
);

create table public.audit_config (
  table_name text primary key,
  enabled boolean not null default true,
  log_insert boolean not null default true,
  log_update boolean not null default true,
  log_delete boolean not null default true,
  sensitive_fields text[] not null default '{}',
  excluded_fields text[] not null default '{}'
);

create table public.audit_log (
  id bigint generated always as identity primary key,
  table_name text not null,
  operation text not null,
  row_id text,
  actor uuid,
  old_data jsonb,
  new_data jsonb,
  logged_at timestamptz not null default now()
);

create index on public.audit_log (table_name, logged_at desc);

grant all on all tables in schema public to anon, authenticated;
grant usage, select on all sequences in schema public to anon, authenticated;
