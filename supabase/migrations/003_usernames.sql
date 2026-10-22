-- Add private, unique account usernames for password sign-in.
alter table public.profiles add column if not exists username text;

update public.profiles
set username='member_' || substr(replace(id::text,'-',''),1,10)
where username is null;

alter table public.profiles alter column username set not null;
alter table public.profiles add constraint profiles_username_format
  check (username ~ '^[a-z0-9_]{3,20}$');
create unique index profiles_username_unique on public.profiles(username);

drop function if exists public.create_family_for_user(uuid,text,text);
create function public.create_family_for_user(p_user_id uuid,p_name text,p_display_name text,p_username text)
returns jsonb language plpgsql security definer set search_path=public,extensions,pg_temp
as $$
declare v_family public.families; v_chat uuid;
begin
  if coalesce(auth.role(),'') <> 'service_role' then raise exception 'server only'; end if;
  if p_name is null or length(trim(p_name)) not between 2 and 60 then raise exception 'Family name must be 2 to 60 characters'; end if;
  if p_display_name is null or length(trim(p_display_name)) not between 1 and 60 then raise exception 'Display name must be 1 to 60 characters'; end if;
  if p_username is null or p_username !~ '^[a-z0-9_]{3,20}$' then raise exception 'Username must be 3 to 20 characters'; end if;
  if exists(select 1 from public.profiles where id=p_user_id) then raise exception 'Account already belongs to a family'; end if;
  insert into public.families(name,owner_id) values(trim(p_name),p_user_id) returning * into v_family;
  insert into public.profiles(id,family_id,display_name,username) values(p_user_id,v_family.id,trim(p_display_name),p_username);
  insert into public.chats(family_id,kind,title) values(v_family.id,'general','Общий чат') returning id into v_chat;
  insert into public.chat_members(chat_id,user_id) values(v_chat,p_user_id);
  return jsonb_build_object('family',jsonb_build_object('id',v_family.id,'name',v_family.name,'invite_code',v_family.invite_code),'chat_id',v_chat);
end $$;
revoke all on function public.create_family_for_user(uuid,text,text,text) from public,anon,authenticated;
grant execute on function public.create_family_for_user(uuid,text,text,text) to service_role;

drop function if exists public.join_family_for_user(uuid,text,text);
create function public.join_family_for_user(p_user_id uuid,p_invite_code text,p_display_name text,p_username text)
returns jsonb language plpgsql security definer set search_path=public,pg_temp
as $$
declare v_family public.families; v_chat uuid;
begin
  if coalesce(auth.role(),'') <> 'service_role' then raise exception 'server only'; end if;
  if p_display_name is null or length(trim(p_display_name)) not between 1 and 60 then raise exception 'Display name must be 1 to 60 characters'; end if;
  if p_username is null or p_username !~ '^[a-z0-9_]{3,20}$' then raise exception 'Username must be 3 to 20 characters'; end if;
  if exists(select 1 from public.profiles where id=p_user_id) then raise exception 'Account already belongs to a family'; end if;
  select * into v_family from public.families where invite_code=upper(trim(p_invite_code)) for update;
  if not found then raise exception 'Invite code is invalid'; end if;
  if (select count(*) from public.profiles where family_id=v_family.id)>=25 then raise exception 'This family already has 25 members'; end if;
  insert into public.profiles(id,family_id,display_name,username) values(p_user_id,v_family.id,trim(p_display_name),p_username);
  select id into v_chat from public.chats where family_id=v_family.id and kind='general';
  if v_chat is null then raise exception 'Family chat is not configured'; end if;
  insert into public.chat_members(chat_id,user_id) values(v_chat,p_user_id);
  return jsonb_build_object('family',jsonb_build_object('id',v_family.id,'name',v_family.name),'chat_id',v_chat);
end $$;
revoke all on function public.join_family_for_user(uuid,text,text,text) from public,anon,authenticated;
grant execute on function public.join_family_for_user(uuid,text,text,text) to service_role;
