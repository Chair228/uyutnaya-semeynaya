-- Edge Functions use service_role for server-only lookups. Bypass-RLS does not
-- grant SQL table privileges, so grant only the reads/deletes those functions need.
grant usage on schema public to service_role;
grant select on public.profiles to service_role;
grant select on public.messages, public.chat_members, public.push_subscriptions to service_role;
grant delete on public.push_subscriptions to service_role;
