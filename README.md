# postgres-rls-hardening-patterns

Padrões de endurecimento de segurança em PostgreSQL com Row Level Security, escritos para bancos expostos diretamente a clientes por uma API automática, como PostgREST ou Supabase. Cada padrão vem com a lição que o motivou e com uma asserção executável que falha se o padrão for quebrado.

O esquema de exemplo é uma livraria fictícia com lojas, equipe, catálogo e pedidos. O CI aplica todos os arquivos em um Postgres 16 limpo e roda as asserções a cada push.

## As lições, em ordem de gravidade

**1. TRUNCATE ignora RLS.** Políticas de linha protegem SELECT, INSERT, UPDATE e DELETE. TRUNCATE não passa por elas. Se a role da aplicação tiver esse privilégio, um único comando esvazia a tabela inteira. A defesa é privilégio de tabela, não política. Ver `05_immutable_audit.sql` e a asserção T05.

**2. `REVOKE ... FROM PUBLIC` não remove um grant direto a uma role.** Revogar de PUBLIC só retira o privilégio herdado. Se em algum momento alguém concedeu execução diretamente a `anon`, a função continua exposta. A auditoria precisa perguntar ao catálogo o que cada role consegue executar de fato, e não confiar na leitura dos scripts. Ver `06_function_exposure.sql` e as asserções T08 e T09.

**3. NULL dentro de `IF` em plpgsql passa em silêncio.** `IF permissao <> 'view' THEN RAISE` não levanta exceção quando a permissão é NULL, porque `NULL <> 'view'` não é verdadeiro nem falso. Um usuário sem vínculo nenhum passa pela checagem. Toda asserção de autorização precisa envolver o resultado em `coalesce(..., false)`. O repositório mantém uma versão deliberadamente ingênua, `demo_unsafe_assert_can_edit_store`, ao lado da versão segura, e a asserção T07 documenta a diferença.

**4. Trilha de auditoria imutável por permissão, não por disciplina.** A role da aplicação só lê a trilha, e mesmo assim sob RLS. Quem escreve é um gatilho `SECURITY DEFINER`, que grava como dono da função. Campos sensíveis são mascarados e campos ruidosos são excluídos por configuração em tabela, não por código. Ver `04_audit_trigger.sql` e a asserção T06.

**5. Segredo no banco só em cofre fechado, com a chave fora do banco.** Se um segredo precisa viver no banco, ele fica em esquema próprio, cifrado, sem privilégio nenhum para os papéis do app, lido por função `SECURITY DEFINER` concedida apenas ao papel de serviço. A chave de cifragem chega pela sessão do serviço, nunca é gravada. E a tabela do cofre não recebe gatilho de auditoria, porque a trilha copiaria o segredo em texto puro. Ver `07_secrets_store.sql` e as asserções T11 e T12. Em plataformas gerenciadas, o cofre nativo do provedor cumpre o mesmo papel.

**6. Funções nascem fechadas.** `ALTER DEFAULT PRIVILEGES ... REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC` antes de criar qualquer função, e grants explícitos só para o que a aplicação chama. Toda função de autorização usa `SECURITY DEFINER` com `search_path` vazio e nomes totalmente qualificados.

## Arquivos

| Arquivo | Conteúdo |
|---|---|
| `sql/00_roles_and_defaults.sql` | Roles `anon` e `authenticated`, função `auth.uid()` que lê a claim do JWT, privilégios padrão fechados. |
| `sql/01_schema.sql` | Esquema da livraria e o grant amplo que imita o padrão de plataformas gerenciadas, para que o endurecimento seguinte tenha o que corrigir. |
| `sql/02_authz_helpers.sql` | Funções de autorização estáveis e reutilizáveis pelas políticas, mais as asserções segura e ingênua. |
| `sql/03_rls_policies.sql` | Políticas por tabela: catálogo público, escrita por permissão de equipe, pedidos visíveis ao cliente e à loja. |
| `sql/04_audit_trigger.sql` | Gatilho genérico de auditoria em JSONB dirigido por `audit_config`. |
| `sql/05_immutable_audit.sql` | Trilha somente leitura, TRUNCATE revogado em todo o esquema, privilégios padrão ajustados. |
| `sql/06_function_exposure.sql` | Função de inventário do que cada role executa e o fechamento automático de tudo que `anon` ainda alcançava. |
| `sql/07_secrets_store.sql` | Cofre de segredos em esquema isolado, cifrado com chave de sessão, legível só pelo papel de serviço. |
| `tests/90_assertions.sql` | Doze cenários com sessões reais por role e claim, que abortam o CI se algum padrão regredir. |

## Rodando localmente

```bash
docker compose up -d
export PGHOST=localhost PGUSER=postgres PGPASSWORD=postgres PGDATABASE=postgres
scripts/apply.sh --test
```

Cada asserção imprime uma linha `Tnn ok`. Qualquer regressão interrompe a execução com a mensagem do cenário que falhou.

## Como testar RLS de verdade

As asserções não usam mocks. Cada bloco troca a role da sessão com `SET LOCAL ROLE` e define a claim do usuário com `set_config('request.jwt.claim.sub', ...)`, exatamente como a API faria. O que passa aqui passa em produção, e o que falha aqui falharia lá.

## Licença

MIT.
