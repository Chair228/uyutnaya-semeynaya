import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const allowedOrigins=[...new Set(['https://uyutnaya-semeynaya.pages.dev','https://uyutnaya-semeynaya.elatedbook7.chatgpt.site','http://localhost:4173',...(Deno.env.get('APP_ORIGINS')||'').split(',').map(x=>x.trim())])];
const headers=(origin:string|null)=>({'Access-Control-Allow-Origin':origin&&allowedOrigins.includes(origin)?origin:'null','Vary':'Origin','Access-Control-Allow-Headers':'authorization, x-client-info, apikey, content-type','Access-Control-Allow-Methods':'POST, OPTIONS','Content-Type':'application/json'});

Deno.serve(async req=>{
  const cors=headers(req.headers.get('Origin'));
  if(req.method==='OPTIONS')return new Response('ok',{headers:cors});
  if(req.headers.has('Origin')&&cors['Access-Control-Allow-Origin']==='null')return new Response(JSON.stringify({error:'Origin is not allowed'}),{status:403,headers:cors});
  if(req.method!=='POST')return new Response(JSON.stringify({error:'Method not allowed'}),{status:405,headers:cors});
  try{
    const url=Deno.env.get('SUPABASE_URL')!,anon=Deno.env.get('SUPABASE_ANON_KEY')!,service=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const body=await req.json();
    const username=String(body.username||'').trim().toLowerCase();
    const password=String(body.password||'');
    if(!/^[a-z0-9_]{3,20}$/.test(username)||password.length<8)return new Response(JSON.stringify({error:'Неверный логин или пароль'}),{status:400,headers:cors});

    const admin=createClient(url,service,{auth:{persistSession:false,autoRefreshToken:false}});
    const {data:profile,error:lookupError}=await admin.from('profiles').select('id').eq('username',username).maybeSingle();
    if(lookupError)throw lookupError;
    let email=`${username}@accounts.uyutnaya-semeynaya.invalid`;
    if(profile){
      const {data:userResult,error:userError}=await admin.auth.admin.getUserById(profile.id);
      if(userError)throw userError;
      if(!userResult?.user?.email)return new Response(JSON.stringify({error:'Неверный логин или пароль'}),{status:401,headers:cors});
      email=userResult.user.email;
    }

    const auth=createClient(url,anon,{auth:{persistSession:false,autoRefreshToken:false}});
    const {data,error}=await auth.auth.signInWithPassword({email,password});
    if(error||!data.session)return new Response(JSON.stringify({error:'Неверный логин или пароль'}),{status:401,headers:cors});
    return new Response(JSON.stringify({session:data.session}),{status:200,headers:cors});
  }catch(error){
    console.error('username-login failed',error instanceof Error?error.message:'unknown error');
    return new Response(JSON.stringify({error:'Не удалось войти. Попробуйте ещё раз.'}),{status:500,headers:cors});
  }
});
