-- Extend the small-family MVP limit so a circle can include grandparents,
-- aunts, uncles, and other close relatives. Invite-code validation and row
-- locking remain unchanged; only the maximum size increases from 5 to 25.
create or replace function public.join_family_for_user(p_user_id uuid,p_invite_code text,p_display_name text)
returns jsonb language plpgsql security definer set search_path=public,pg_temp
as $$
declare v_family public.families; v_chat uuid;
begin
  if coalesce(auth.role(),'') <> 'service_role' then raise exception 'server only'; end if;
  if p_display_name is null or length(trim(p_display_name)) not between 1 and 60 then raise exception 'Display name must be 1 to 60 characters'; end if;
  if exists(select 1 from public.profiles where id=p_user_id) then raise exception 'Account already belongs to a family'; end if;
  select * into v_family from public.families where invite_code=upper(trim(p_invite_code)) for update;
  if not found then raise exception 'Invite code is invalid'; end if;
  if (select count(*) from public.profiles where family_id=v_family.id)>=25 then raise exception 'This family circle already has 25 members'; end if;
  insert into public.profiles(id,family_id,display_name) values(p_user_id,v_family.id,trim(p_display_name));
  select id into v_chat from public.chats where family_id=v_family.id and kind='general';
  if v_chat is null then raise exception 'Family chat is not configured'; end if;
  insert into public.chat_members(chat_id,user_id) values(v_chat,p_user_id);
  return jsonb_build_object('family',jsonb_build_object('id',v_family.id,'name',v_family.name),'chat_id',v_chat);
end $$;

revoke all on function public.join_family_for_user(uuid,text,text) from public,anon,authenticated;
grant execute on function public.join_family_for_user(uuid,text,text) to service_role;
