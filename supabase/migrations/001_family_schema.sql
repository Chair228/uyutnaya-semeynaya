-- Privacy-first base schema. Run only on a fresh Supabase project.
create extension if not exists pgcrypto with schema extensions;

create table public.families (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(name) between 2 and 60),
  invite_code text not null unique default upper(encode(gen_random_bytes(12), 'hex')),
  owner_id uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now()
);
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  family_id uuid not null references public.families(id) on delete cascade,
  display_name text not null check (length(display_name) between 1 and 60),
  avatar_path text,
  cover_path text,
  notifications_enabled boolean not null default true,
  created_at timestamptz not null default now()
);
create table public.chats (
  id uuid primary key default gen_random_uuid(),
  family_id uuid not null references public.families(id) on delete cascade,
  kind text not null check (kind in ('general','direct')),
  title text,
  created_at timestamptz not null default now(),
  check ((kind='general' and title is not null) or kind='direct')
);
create unique index one_general_chat_per_family on public.chats(family_id) where kind='general';
create table public.chat_members (
  chat_id uuid not null references public.chats(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  primary key (chat_id,user_id)
);
create table public.messages (
  id uuid primary key default gen_random_uuid(),
  chat_id uuid not null references public.chats(id) on delete cascade,
  author_id uuid not null references public.profiles(id) on delete cascade,
  body text not null check (length(body) between 1 and 4000),
  created_at timestamptz not null default now()
);
create index messages_chat_created_idx on public.messages(chat_id,created_at desc);
create table public.message_reactions (
  message_id uuid not null references public.messages(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  emoji text not null check (length(emoji) between 1 and 8),
  created_at timestamptz not null default now(), primary key(message_id,user_id,emoji)
);
create table public.posts (
  id uuid primary key default gen_random_uuid(),
  family_id uuid not null references public.families(id) on delete cascade,
  author_id uuid not null references public.profiles(id) on delete cascade,
  body text check (length(body)<=4000),
  image_path text,
  created_at timestamptz not null default now(),
  check (nullif(trim(coalesce(body,'')),'') is not null or image_path is not null)
);
create index posts_family_created_idx on public.posts(family_id,created_at desc);
create table public.post_likes (
  post_id uuid not null references public.posts(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(), primary key(post_id,user_id)
);
create table public.comments (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  author_id uuid not null references public.profiles(id) on delete cascade,
  body text not null check (length(body) between 1 and 2000),
  created_at timestamptz not null default now()
);
create table public.avatar_history (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  storage_path text not null,
  created_at timestamptz not null default now()
);
create table public.push_subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  endpoint text not null unique,
  p256dh text not null,
  auth text not null,
  created_at timestamptz not null default now()
);

create function public.my_family_id() returns uuid
language sql stable security definer set search_path=public,pg_temp
as $$ select family_id from public.profiles where id=auth.uid() $$;
revoke all on function public.my_family_id() from public;
grant execute on function public.my_family_id() to authenticated;

-- RPCs are only callable by a server holding the service role; no invite creation/redemption in an untrusted client.
create function public.create_family_for_user(p_user_id uuid,p_name text,p_display_name text)
returns jsonb language plpgsql security definer set search_path=public,extensions,pg_temp
as $$
declare v_family public.families; v_chat uuid;
begin
  if coalesce(auth.role(),'') <> 'service_role' then raise exception 'server only'; end if;
  if p_name is null or length(trim(p_name)) not between 2 and 60 then raise exception 'Family name must be 2 to 60 characters'; end if;
  if p_display_name is null or length(trim(p_display_name)) not between 1 and 60 then raise exception 'Display name must be 1 to 60 characters'; end if;
  if exists(select 1 from public.profiles where id=p_user_id) then raise exception 'Account already belongs to a family'; end if;
  insert into public.families(name,owner_id) values(trim(p_name),p_user_id) returning * into v_family;
  insert into public.profiles(id,family_id,display_name) values(p_user_id,v_family.id,trim(p_display_name));
  insert into public.chats(family_id,kind,title) values(v_family.id,'general','Общий чат') returning id into v_chat;
  insert into public.chat_members(chat_id,user_id) values(v_chat,p_user_id);
  return jsonb_build_object('family',jsonb_build_object('id',v_family.id,'name',v_family.name,'invite_code',v_family.invite_code),'chat_id',v_chat);
end $$;
revoke all on function public.create_family_for_user(uuid,text,text) from public,anon,authenticated;
grant execute on function public.create_family_for_user(uuid,text,text) to service_role;

create function public.join_family_for_user(p_user_id uuid,p_invite_code text,p_display_name text)
returns jsonb language plpgsql security definer set search_path=public,pg_temp
as $$
declare v_family public.families; v_chat uuid;
begin
  if coalesce(auth.role(),'') <> 'service_role' then raise exception 'server only'; end if;
  if p_display_name is null or length(trim(p_display_name)) not between 1 and 60 then raise exception 'Display name must be 1 to 60 characters'; end if;
  if exists(select 1 from public.profiles where id=p_user_id) then raise exception 'Account already belongs to a family'; end if;
  select * into v_family from public.families where invite_code=upper(trim(p_invite_code)) for update;
  if not found then raise exception 'Invite code is invalid'; end if;
  if (select count(*) from public.profiles where family_id=v_family.id)>=5 then raise exception 'This family already has five members'; end if;
  insert into public.profiles(id,family_id,display_name) values(p_user_id,v_family.id,trim(p_display_name));
  select id into v_chat from public.chats where family_id=v_family.id and kind='general';
  if v_chat is null then raise exception 'Family chat is not configured'; end if;
  insert into public.chat_members(chat_id,user_id) values(v_chat,p_user_id);
  return jsonb_build_object('family',jsonb_build_object('id',v_family.id,'name',v_family.name),'chat_id',v_chat);
end $$;
revoke all on function public.join_family_for_user(uuid,text,text) from public,anon,authenticated;
grant execute on function public.join_family_for_user(uuid,text,text) to service_role;

create function public.open_direct_chat(other_user_id uuid) returns uuid
language plpgsql security definer set search_path=public,pg_temp
as $$
declare my_id uuid:=auth.uid(); my_family uuid; chat_id uuid; first_id uuid; second_id uuid;
begin
  if my_id is null then raise exception 'Not authenticated'; end if;
  select family_id into my_family from public.profiles where id=my_id;
  if my_family is null or not exists(select 1 from public.profiles where id=other_user_id and family_id=my_family) then raise exception 'Member is not in your family'; end if;
  first_id:=least(my_id,other_user_id); second_id:=greatest(my_id,other_user_id);
  select c.id into chat_id from public.chats c where c.family_id=my_family and c.kind='direct' and exists(select 1 from public.chat_members a where a.chat_id=c.id and a.user_id=first_id) and exists(select 1 from public.chat_members b where b.chat_id=c.id and b.user_id=second_id) limit 1;
  if chat_id is null then
    insert into public.chats(family_id,kind) values(my_family,'direct') returning id into chat_id;
    insert into public.chat_members(chat_id,user_id) values(chat_id,my_id),(chat_id,other_user_id);
  end if;
  return chat_id;
end $$;
revoke all on function public.open_direct_chat(uuid) from public,anon;
grant execute on function public.open_direct_chat(uuid) to authenticated;

alter table public.families enable row level security;
alter table public.profiles enable row level security;
alter table public.chats enable row level security;
alter table public.chat_members enable row level security;
alter table public.messages enable row level security;
alter table public.message_reactions enable row level security;
alter table public.posts enable row level security;
alter table public.post_likes enable row level security;
alter table public.comments enable row level security;
alter table public.avatar_history enable row level security;
alter table public.push_subscriptions enable row level security;

create policy family_read on public.families for select to authenticated using(id=public.my_family_id());
create policy family_update_owner on public.families for update to authenticated using(owner_id=auth.uid()) with check(owner_id=auth.uid());
create policy profiles_read_family on public.profiles for select to authenticated using(family_id=public.my_family_id());
create policy profile_update_self on public.profiles for update to authenticated using(id=auth.uid() and family_id=public.my_family_id()) with check(id=auth.uid() and family_id=public.my_family_id());
create policy chats_read_family on public.chats for select to authenticated using(family_id=public.my_family_id());
create function public.can_read_chat_members(p_chat_id uuid) returns boolean
language sql stable security definer set search_path=public,pg_temp
as $$ select exists(select 1 from public.chats c where c.id=p_chat_id and c.family_id=public.my_family_id() and (c.kind='general' or exists(select 1 from public.chat_members mine where mine.chat_id=c.id and mine.user_id=auth.uid()))) $$;
revoke all on function public.can_read_chat_members(uuid) from public;
grant execute on function public.can_read_chat_members(uuid) to authenticated;
create policy chat_members_read_own_conversations on public.chat_members for select to authenticated using(public.can_read_chat_members(chat_id));
create policy messages_read_member on public.messages for select to authenticated using(exists(select 1 from public.chat_members cm where cm.chat_id=messages.chat_id and cm.user_id=auth.uid()));
create policy messages_insert_member on public.messages for insert to authenticated with check(author_id=auth.uid() and exists(select 1 from public.chat_members cm where cm.chat_id=messages.chat_id and cm.user_id=auth.uid()));
create policy messages_delete_own on public.messages for delete to authenticated using(author_id=auth.uid());
create policy reactions_read_family on public.message_reactions for select to authenticated using(exists(select 1 from public.messages m join public.chats c on c.id=m.chat_id where m.id=message_id and c.family_id=public.my_family_id()));
create policy reactions_insert_own on public.message_reactions for insert to authenticated with check(user_id=auth.uid() and exists(select 1 from public.messages m join public.chat_members cm on cm.chat_id=m.chat_id where m.id=message_id and cm.user_id=auth.uid()));
create policy reactions_delete_own on public.message_reactions for delete to authenticated using(user_id=auth.uid());
create policy posts_read_family on public.posts for select to authenticated using(family_id=public.my_family_id());
create policy posts_insert_family on public.posts for insert to authenticated with check(author_id=auth.uid() and family_id=public.my_family_id());
create policy posts_delete_own on public.posts for delete to authenticated using(author_id=auth.uid() and family_id=public.my_family_id());
create policy likes_read_family on public.post_likes for select to authenticated using(exists(select 1 from public.posts p where p.id=post_id and p.family_id=public.my_family_id()));
create policy likes_insert_own on public.post_likes for insert to authenticated with check(user_id=auth.uid() and exists(select 1 from public.posts p where p.id=post_id and p.family_id=public.my_family_id()));
create policy likes_delete_own on public.post_likes for delete to authenticated using(user_id=auth.uid());
create policy comments_read_family on public.comments for select to authenticated using(exists(select 1 from public.posts p where p.id=post_id and p.family_id=public.my_family_id()));
create policy comments_insert_family on public.comments for insert to authenticated with check(author_id=auth.uid() and exists(select 1 from public.posts p where p.id=post_id and p.family_id=public.my_family_id()));
create policy comments_delete_own on public.comments for delete to authenticated using(author_id=auth.uid());
create policy avatars_read_family on public.avatar_history for select to authenticated using(exists(select 1 from public.profiles p where p.id=user_id and p.family_id=public.my_family_id()));
create policy avatars_insert_self on public.avatar_history for insert to authenticated with check(user_id=auth.uid());
create policy push_subscriptions_read_self on public.push_subscriptions for select to authenticated using(user_id=auth.uid());
create policy push_subscriptions_insert_self on public.push_subscriptions for insert to authenticated with check(user_id=auth.uid());
create policy push_subscriptions_delete_self on public.push_subscriptions for delete to authenticated using(user_id=auth.uid());

-- Remove default API grants before restoring the exact least-privilege set below.
revoke all on all tables in schema public from anon,authenticated;
-- Prevent editing identity or family membership from the client. Grants are column-scoped.
revoke insert,update,delete on public.families from anon,authenticated;
grant select on public.families to authenticated;
grant update(name) on public.families to authenticated;
revoke insert,update,delete on public.profiles from anon,authenticated;
grant select on public.profiles to authenticated;
grant update(display_name,avatar_path,cover_path,notifications_enabled) on public.profiles to authenticated;
revoke insert,update,delete on public.chats,public.chat_members from anon,authenticated;
grant select on public.chats,public.chat_members to authenticated;
revoke update,delete on public.messages,public.message_reactions,public.posts,public.post_likes,public.comments,public.avatar_history from anon,authenticated;
grant select,insert,delete on public.messages,public.message_reactions,public.posts,public.post_likes,public.comments to authenticated;
grant select,insert on public.avatar_history to authenticated;
revoke update on public.push_subscriptions from anon,authenticated;
grant select,insert,delete on public.push_subscriptions to authenticated;
grant usage on schema public to authenticated;
grant execute on function public.open_direct_chat(uuid) to authenticated;

-- Private files are stored below <family uuid>/<user uuid>/...; signed URLs only.
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('family-media','family-media',false,10485760,array['image/jpeg','image/png','image/webp','image/heic'])
on conflict(id) do update set public=false,file_size_limit=10485760,allowed_mime_types=excluded.allowed_mime_types;
create policy family_media_read on storage.objects for select to authenticated using(bucket_id='family-media' and split_part(name,'/',1)=public.my_family_id()::text);
create policy family_media_insert_self on storage.objects for insert to authenticated with check(bucket_id='family-media' and split_part(name,'/',1)=public.my_family_id()::text and split_part(name,'/',2)=auth.uid()::text);
create policy family_media_delete_self on storage.objects for delete to authenticated using(bucket_id='family-media' and split_part(name,'/',1)=public.my_family_id()::text and split_part(name,'/',2)=auth.uid()::text);

-- Realtime for the in-app live feed and family chat. Safe to run again on a fresh/restored project.
do $$ begin alter publication supabase_realtime add table public.messages; exception when duplicate_object then null; end $$;
do $$ begin alter publication supabase_realtime add table public.posts; exception when duplicate_object then null; end $$;
do $$ begin alter publication supabase_realtime add table public.profiles; exception when duplicate_object then null; end $$;
