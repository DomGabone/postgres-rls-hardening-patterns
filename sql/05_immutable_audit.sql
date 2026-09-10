revoke insert, update, delete, truncate, references, trigger
  on public.audit_log, public.audit_config
  from anon, authenticated;

revoke select on public.audit_log, public.audit_config from anon;

revoke truncate on all tables in schema public from anon, authenticated;

alter default privileges in schema public
  revoke truncate on tables from anon, authenticated;

revoke references, trigger on all tables in schema public from anon, authenticated;
