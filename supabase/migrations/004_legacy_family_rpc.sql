-- Keep existing deployed create-family and join-family Edge Functions compatible.
create function public.create_family_for_user(p_user_id uuid,p_name text,p_display_name text)
returns jsonb language plpgsql security definer set search_path=public,extensions,pg_temp
as $$
declare v_username text;
begin
  if coalesce(auth.role(),'') <> 'service_role' then raise exception 'server only'; end if;
  select lower(raw_user_meta_data->>'username') into v_username from auth.users where id=p_user_id;
  return public.create_family_for_user(p_user_id,p_name,p_display_name,v_username);
end $$;
revoke all on function public.create_family_for_user(uuid,text,text) from public,anon,authenticated;
grant execute on function public.create_family_for_user(uuid,text,text) to service_role;

create function public.join_family_for_user(p_user_id uuid,p_invite_code text,p_display_name text)
returns jsonb language plpgsql security definer set search_path=public,extensions,pg_temp
as $$
declare v_username text;
begin
  if coalesce(auth.role(),'') <> 'service_role' then raise exception 'server only'; end if;
  select lower(raw_user_meta_data->>'username') into v_username from auth.users where id=p_user_id;
  return public.join_family_for_user(p_user_id,p_invite_code,p_display_name,v_username);
end $$;
revoke all on function public.join_family_for_user(uuid,text,text) from public,anon,authenticated;
grant execute on function public.join_family_for_user(uuid,text,text) to service_role;
