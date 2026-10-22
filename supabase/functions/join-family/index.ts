import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
const allowedOrigins=[...new Set(['https://uyutnaya-semeynaya.pages.dev','https://uyutnaya-semeynaya.elatedbook7.chatgpt.site','http://localhost:4173',...(Deno.env.get('APP_ORIGINS')||'').split(',').map(x=>x.trim())])];
const headers=(origin:string|null)=>({'Access-Control-Allow-Origin':origin&&allowedOrigins.includes(origin)?origin:'null','Vary':'Origin','Access-Control-Allow-Headers':'authorization, x-client-info, apikey, content-type','Access-Control-Allow-Methods':'POST, OPTIONS','Content-Type':'application/json'});
Deno.serve(async req=>{
 const cors=headers(req.headers.get('Origin'));if(req.method==='OPTIONS')return new Response('ok',{headers:cors});
 if(req.headers.has('Origin')&&cors['Access-Control-Allow-Origin']==='null')return new Response(JSON.stringify({error:'Origin is not allowed'}),{status:403,headers:cors});
 if(req.method!=='POST')return new Response(JSON.stringify({error:'Method not allowed'}),{status:405,headers:cors});
 try{
  const url=Deno.env.get('SUPABASE_URL')!,anon=Deno.env.get('SUPABASE_ANON_KEY')!,service=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
  const bearer=req.headers.get('Authorization');if(!bearer?.startsWith('Bearer '))return new Response(JSON.stringify({error:'Sign in first'}),{status:401,headers:cors});
  const userClient=createClient(url,anon,{global:{headers:{Authorization:bearer}}});const {data:{user},error:authError}=await userClient.auth.getUser();if(authError||!user)return new Response(JSON.stringify({error:'Invalid session'}),{status:401,headers:cors});
  const body=await req.json();const code=String(body.invite_code||'').trim().toUpperCase().replace(/[^A-Z0-9]/g,'').slice(0,20);const displayName=String(body.display_name||user.user_metadata?.display_name||'').trim().slice(0,60);
  if(code.length<16||displayName.length<1)return new Response(JSON.stringify({error:'Check the invite code and your name'}),{status:400,headers:cors});
  const admin=createClient(url,service,{auth:{persistSession:false,autoRefreshToken:false}});const {data,error}=await admin.rpc('join_family_for_user',{p_user_id:user.id,p_invite_code:code,p_display_name:displayName});if(error)throw error;
  return new Response(JSON.stringify(data),{status:200,headers:cors});
 }catch(error){const message=error instanceof Error?error.message:'Could not join family';console.error('join-family failed',message);return new Response(JSON.stringify({error:message}),{status:400,headers:cors});}
});
