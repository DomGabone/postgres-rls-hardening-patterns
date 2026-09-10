do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    create role service_role nologin;
  end if;
end
$$;

create schema secrets;

revoke all on schema secrets from public;
grant usage on schema secrets to service_role;

create table secrets.store (
  name text primary key,
  ciphertext bytea not null,
  updated_at timestamptz not null default now()
);

revoke all on secrets.store from public, anon, authenticated, service_role;

create or replace function secrets.put(p_name text, p_value text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  k text := nullif(current_setting('app.secrets_key', true), '');
begin
  if k is null then
    raise exception 'chave de cifragem ausente na sessao' using errcode = '22023';
  end if;
  insert into secrets.store (name, ciphertext)
  values (p_name, public.pgp_sym_encrypt(p_value, k))
  on conflict (name) do update
    set ciphertext = excluded.ciphertext,
        updated_at = now();
end;
$$;

create or replace function secrets.read(p_name text)
returns text
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  k text := nullif(current_setting('app.secrets_key', true), '');
  v text;
begin
  if k is null then
    raise exception 'chave de cifragem ausente na sessao' using errcode = '22023';
  end if;
  select public.pgp_sym_decrypt(s.ciphertext, k) into v
  from secrets.store s
  where s.name = p_name;
  if v is null then
    raise exception 'segredo % nao encontrado', p_name using errcode = 'P0002';
  end if;
  return v;
end;
$$;

revoke execute on function secrets.put(text, text), secrets.read(text)
  from public, anon, authenticated;
grant execute on function secrets.put(text, text), secrets.read(text)
  to service_role;
