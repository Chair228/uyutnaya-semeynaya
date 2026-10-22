-- Keep password-only signup from bypassing Supabase Auth's public signup limits.
create table if not exists public.signup_rate_limits (
  ip_hash text primary key check (ip_hash ~ '^[a-f0-9]{64}$'),
  window_started_at timestamptz not null default now(),
  attempts integer not null default 0 check (attempts >= 0)
);

alter table public.signup_rate_limits enable row level security;
revoke all on public.signup_rate_limits from public, anon, authenticated;

create or replace function public.consume_signup_attempt(p_ip_hash text)
returns boolean language plpgsql security definer set search_path=public,pg_temp
as $$
declare v_attempts integer;
begin
  if coalesce(auth.role(),'') <> 'service_role' then raise exception 'server only'; end if;
  if p_ip_hash is null or p_ip_hash !~ '^[a-f0-9]{64}$' then raise exception 'invalid rate limit key'; end if;

  insert into public.signup_rate_limits(ip_hash,window_started_at,attempts)
  values(p_ip_hash,now(),1)
  on conflict(ip_hash) do update set
    window_started_at=case when public.signup_rate_limits.window_started_at < now()-interval '10 minutes' then now() else public.signup_rate_limits.window_started_at end,
    attempts=case when public.signup_rate_limits.window_started_at < now()-interval '10 minutes' then 1 else public.signup_rate_limits.attempts+1 end
  returning attempts into v_attempts;

  delete from public.signup_rate_limits where window_started_at < now()-interval '1 day';
  return v_attempts <= 5;
end $$;

revoke all on function public.consume_signup_attempt(text) from public,anon,authenticated;
grant execute on function public.consume_signup_attempt(text) to service_role;
