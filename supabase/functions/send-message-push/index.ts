import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import webpush from 'npm:web-push@3.6.7';

const origins=(Deno.env.get('APP_ORIGINS')||'https://uyutnaya-semeynaya.elatedbook7.chatgpt.site,http://localhost:4173').split(',').map(x=>x.trim());
const responseHeaders=(origin:string|null)=>({'Access-Control-Allow-Origin':origin&&origins.includes(origin)?origin:'null','Vary':'Origin','Access-Control-Allow-Headers':'authorization, x-client-info, apikey, content-type','Access-Control-Allow-Methods':'POST, OPTIONS','Content-Type':'application/json'});

Deno.serve(async req=>{
 const cors=responseHeaders(req.headers.get('Origin'));
 if(req.method==='OPTIONS')return new Response('ok',{headers:cors});
 if(req.headers.has('Origin')&&cors['Access-Control-Allow-Origin']==='null')return new Response(JSON.stringify({error:'Origin is not allowed'}),{status:403,headers:cors});
 if(req.method!=='POST')return new Response(JSON.stringify({error:'Method not allowed'}),{status:405,headers:cors});
 try{
  const url=Deno.env.get('SUPABASE_URL')!,anon=Deno.env.get('SUPABASE_ANON_KEY')!,service=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
  const vapidPublic=Deno.env.get('VAPID_PUBLIC_KEY'),vapidPrivate=Deno.env.get('VAPID_PRIVATE_KEY');
  if(!vapidPublic||!vapidPrivate)throw new Error('Push notifications are not configured');
  const bearer=req.headers.get('Authorization');if(!bearer?.startsWith('Bearer '))return new Response(JSON.stringify({error:'Sign in first'}),{status:401,headers:cors});
  const userClient=createClient(url,anon,{global:{headers:{Authorization:bearer}}});const {data:{user},error:authError}=await userClient.auth.getUser();if(authError||!user)return new Response(JSON.stringify({error:'Invalid session'}),{status:401,headers:cors});
  const {message_id}=await req.json();if(typeof message_id!=='string')throw new Error('Message is required');
  const admin=createClient(url,service,{auth:{persistSession:false,autoRefreshToken:false}});
  const {data:message,error}=await admin.from('messages').select('id,chat_id,author_id,body,profiles!messages_author_id_fkey(display_name)').eq('id',message_id).single();
  if(error||!message||message.author_id!==user.id)throw new Error('Message is not available');
  const {data:recipients}=await admin.from('chat_members').select('user_id').eq('chat_id',message.chat_id).neq('user_id',user.id);
  const ids=(recipients||[]).map(x=>x.user_id);if(!ids.length)return Response.json({sent:0},{headers:cors});
  const [{data:profiles},{data:subs}]=await Promise.all([
   admin.from('profiles').select('id,notifications_enabled').in('id',ids),
   admin.from('push_subscriptions').select('id,user_id,endpoint,p256dh,auth').in('user_id',ids),
  ]);
  const enabled=new Set((profiles||[]).filter(x=>x.notifications_enabled).map(x=>x.id));
  const targets=(subs||[]).filter(x=>enabled.has(x.user_id));
  if(!targets.length)return Response.json({sent:0},{headers:cors});
  webpush.setVapidDetails(Deno.env.get('VAPID_SUBJECT')||'mailto:family@example.invalid',vapidPublic,vapidPrivate);
  const author=(message.profiles as {display_name?:string}|null)?.display_name||'Кто-то из семьи';
  const payload=JSON.stringify({title:author,body:String(message.body).slice(0,180),url:'/'});
  const results=await Promise.allSettled(targets.map(sub=>webpush.sendNotification({endpoint:sub.endpoint,keys:{p256dh:sub.p256dh,auth:sub.auth}},payload,{TTL:60})));
  const stale=results.flatMap((r,i)=>r.status==='rejected'&&[404,410].includes(Number((r.reason as {statusCode?:number})?.statusCode))?[targets[i].id]:[]);
  if(stale.length)await admin.from('push_subscriptions').delete().in('id',stale);
  return Response.json({sent:results.filter(x=>x.status==='fulfilled').length},{headers:cors});
 }catch(error){const message=error instanceof Error?error.message:'Could not send notification';console.error('send-message-push failed',message);return new Response(JSON.stringify({error:message}),{status:400,headers:cors});}
});
