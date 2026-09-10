\set ON_ERROR_STOP on

insert into public.profiles (id, display_name, is_platform_admin) values
  ('00000000-0000-0000-0000-00000000000a', 'Dona da loja A', false),
  ('00000000-0000-0000-0000-00000000000b', 'Dono da loja B', false),
  ('00000000-0000-0000-0000-00000000000e', 'Editor da loja A', false),
  ('00000000-0000-0000-0000-00000000000c', 'Cliente', false),
  ('00000000-0000-0000-0000-00000000000f', 'Administracao', true);

insert into public.stores (id, owner_id, name) values
  ('10000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000a', 'Livraria Alecrim'),
  ('10000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-00000000000b', 'Sebo Baobá');

insert into public.store_members (store_id, member_id, permission) values
  ('10000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000e', 'edit');

insert into public.books (id, store_id, title, price_cents, stock) values
  ('20000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-00000000000a', 'Grande Sertão: Veredas', 8990, 3),
  ('20000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-00000000000b', 'Quarto de Despejo', 4590, 5);

insert into public.orders (id, store_id, customer_id, total_cents) values
  ('30000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000c', 8990);

do $$
declare n int;
begin
  set local role authenticated;
  perform set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000a', true);
  select count(*) into n from public.stores;
  if n <> 1 then raise exception 'T01 dona ve % lojas, esperava 1', n; end if;
  select count(*) into n from public.orders;
  if n <> 1 then raise exception 'T01 dona ve % pedidos da propria loja, esperava 1', n; end if;
  raise notice 'T01 ok: dona ve apenas a propria loja e seus pedidos';
end $$;

do $$
declare n int;
begin
  set local role authenticated;
  perform set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000b', true);
  update public.books set price_cents = 1 where id = '20000000-0000-0000-0000-000000000001';
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'T02 estranho alterou % livro de outra loja', n; end if;
  select count(*) into n from public.books;
  if n <> 2 then raise exception 'T02 catalogo publico deveria listar 2 livros, listou %', n; end if;
  raise notice 'T02 ok: catalogo e publico, escrita em loja alheia e filtrada';
end $$;

do $$
declare n int;
begin
  set local role authenticated;
  perform set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000e', true);
  update public.books set price_cents = 7990 where id = '20000000-0000-0000-0000-000000000001';
  get diagnostics n = row_count;
  if n <> 1 then raise exception 'T03 editor nao conseguiu editar livro da propria loja'; end if;
  begin
    insert into public.store_members (store_id, member_id, permission)
    values ('10000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000c', 'view');
    raise exception 'T03 editor conseguiu gerenciar equipe sem permissao manage';
  exception when insufficient_privilege then
    null;
  end;
  raise notice 'T03 ok: edit edita catalogo, mas nao gerencia equipe';
end $$;

do $$
declare n int;
begin
  set local role anon;
  select count(*) into n from public.books;
  if n <> 2 then raise exception 'T04 anon deveria ler o catalogo'; end if;
  begin
    insert into public.books (store_id, title, price_cents)
    values ('10000000-0000-0000-0000-00000000000a', 'invasor', 1);
    raise exception 'T04 anon conseguiu escrever no catalogo';
  exception when insufficient_privilege then
    null;
  end;
  begin
    perform count(*) from public.orders;
    raise exception 'T04 anon conseguiu ler pedidos';
  exception when insufficient_privilege then
    null;
  end;
  raise notice 'T04 ok: anon le catalogo e nada mais';
end $$;

do $$
begin
  set local role authenticated;
  perform set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000a', true);
  begin
    truncate public.books;
    raise exception 'T05 authenticated conseguiu TRUNCATE, e TRUNCATE ignora RLS';
  exception when insufficient_privilege then
    null;
  end;
  raise notice 'T05 ok: TRUNCATE fora do alcance das roles do app';
end $$;

do $$
declare n int; k boolean;
begin
  set local role authenticated;
  perform set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000a', true);
  begin
    insert into public.audit_log (table_name, operation) values ('x', 'FAKE');
    raise exception 'T06 authenticated escreveu direto na trilha de auditoria';
  exception when insufficient_privilege then
    null;
  end;
  begin
    delete from public.audit_log;
    raise exception 'T06 authenticated apagou a trilha de auditoria';
  exception when insufficient_privilege then
    null;
  end;
  reset role;
  select count(*) into n from public.audit_log where table_name = 'books' and operation = 'UPDATE';
  if n < 1 then raise exception 'T06 trigger nao registrou o UPDATE do editor'; end if;
  select bool_and(not (new_data ? 'updated_at')) into k from public.audit_log where table_name = 'books';
  if not k then raise exception 'T06 campo excluido apareceu na auditoria'; end if;
  select bool_and(new_data ->> 'total_cents' = '***') into k from public.audit_log where table_name = 'orders';
  if not k then raise exception 'T06 campo sensivel nao foi mascarado'; end if;
  select count(*) into n from public.audit_log where table_name = 'books' and operation = 'UPDATE' and actor = '00000000-0000-0000-0000-00000000000e';
  if n < 1 then raise exception 'T06 autor da alteracao nao foi registrado'; end if;
  raise notice 'T06 ok: trilha so cresce pelo trigger, com mascara e exclusao de campos';
end $$;

do $$
begin
  set local role authenticated;
  perform set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000b', true);
  begin
    perform public.assert_can_manage_store('10000000-0000-0000-0000-00000000000a');
    raise exception 'T07 estranho passou pela asserção de gerencia';
  exception when insufficient_privilege then
    null;
  end;
  begin
    perform public.assert_can_edit_store('10000000-0000-0000-0000-00000000000a');
    raise exception 'T07 estranho passou pela asserção segura de edicao';
  exception when insufficient_privilege then
    null;
  end;
  perform public.demo_unsafe_assert_can_edit_store('10000000-0000-0000-0000-00000000000a');
  raise notice 'T07 ok: a asserção segura barra o estranho; a versão ingênua deixa passar porque NULL <> ''view'' não é verdadeiro nem falso';
end $$;

do $$
declare n int;
begin
  select count(*) into n from public.functions_executable_by('anon');
  if n <> 0 then raise exception 'T08 % funcoes do schema public executaveis por anon', n; end if;
  raise notice 'T08 ok: nenhuma funcao de public executavel por anon';
end $$;

do $$
declare still boolean;
begin
  grant execute on function public.owns_store(uuid, uuid) to anon;
  revoke execute on function public.owns_store(uuid, uuid) from public;
  select has_function_privilege('anon', 'public.owns_store(uuid, uuid)', 'execute') into still;
  if not still then raise exception 'T09 esperava que revogar de PUBLIC nao removesse o grant direto a anon'; end if;
  revoke execute on function public.owns_store(uuid, uuid) from anon;
  select has_function_privilege('anon', 'public.owns_store(uuid, uuid)', 'execute') into still;
  if still then raise exception 'T09 revogar de anon deveria fechar o acesso'; end if;
  raise notice 'T09 ok: revoke from public nao remove grant direto; e preciso revogar da role';
end $$;

do $$
declare n int;
begin
  set local role authenticated;
  perform set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000f', true);
  select count(*) into n from public.stores;
  if n <> 2 then raise exception 'T10 administracao deveria ver 2 lojas, viu %', n; end if;
  select count(*) into n from public.audit_log;
  if n < 1 then raise exception 'T10 administracao deveria ler a auditoria'; end if;
  raise notice 'T10 ok: administracao le tudo sob RLS';
end $$;

do $$
declare n int;
begin
  set local role authenticated;
  perform set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000f', true);
  begin
    perform secrets.read('gateway_token');
    raise exception 'T11 authenticated, mesmo administracao, alcancou o cofre';
  exception when insufficient_privilege then
    null;
  end;
  begin
    perform count(*) from secrets.store;
    raise exception 'T11 authenticated leu a tabela do cofre';
  exception when insufficient_privilege then
    null;
  end;
  reset role;
  select count(*) into n from public.functions_executable_by('anon', 'secrets');
  n := n + (select count(*) from public.functions_executable_by('authenticated', 'secrets'));
  if n <> 0 then raise exception 'T11 % funcoes do cofre executaveis por papeis do app', n; end if;
  raise notice 'T11 ok: cofre fora do alcance de anon e authenticated';
end $$;

do $$
declare v text; leaked int; trg int;
begin
  set local role service_role;
  perform set_config('app.secrets_key', 'chave-local-somente-para-teste', true);
  perform secrets.put('gateway_token', 'tok_abc123');
  select secrets.read('gateway_token') into v;
  if v <> 'tok_abc123' then raise exception 'T12 leitura devolveu valor errado'; end if;
  reset role;
  select count(*) into leaked from secrets.store where position('tok_abc123'::bytea in ciphertext) > 0;
  if leaked <> 0 then raise exception 'T12 segredo gravado em texto puro'; end if;
  select count(*) into trg
  from pg_trigger t
  join pg_class c on c.oid = t.tgrelid
  join pg_namespace ns on ns.oid = c.relnamespace
  where ns.nspname = 'secrets' and not t.tgisinternal;
  if trg <> 0 then raise exception 'T12 cofre tem gatilho, e gatilho de auditoria copiaria o segredo'; end if;
  begin
    perform set_config('app.secrets_key', '', true);
    perform secrets.read('gateway_token');
    raise exception 'T12 leitura sem chave deveria falhar';
  exception when invalid_parameter_value then
    null;
  end;
  raise notice 'T12 ok: cofre cifrado, sem gatilho, chave fora do banco';
end $$;

select 'todas as asserções passaram' as resultado;
