import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const allowedOrigins=[...new Set(['https://uyutnaya-semeynaya.pages.dev','https://uyutnaya-semeynaya.elatedbook7.chatgpt.site','http://localhost:4173',...(Deno.env.get('APP_ORIGINS')||'').split(',').map(x=>x.trim())])];
const headers=(origin:string|null)=>({'Access-Control-Allow-Origin':origin&&allowedOrigins.includes(origin)?origin:'null','Vary':'Origin','Access-Control-Allow-Headers':'authorization, x-client-info, apikey, content-type','Access-Control-Allow-Methods':'POST, OPTIONS','Content-Type':'application/json'});
const response=(body:unknown,status:number,cors:Record<string,string>)=>new Response(JSON.stringify(body),{status,headers:cors});
const internalDomain='accounts.uyutnaya-semeynaya.invalid';
const describeError=(error:unknown)=>{
  if(error instanceof Error)return `${error.name}: ${error.message}`;
  if(error&&typeof error==='object')return Object.entries(error).map(([key,value])=>`${key}=${String(value)}`).join(' ');
  return String(error);
};

Deno.serve(async req=>{
  const origin=req.headers.get('Origin');
  const cors=headers(origin);
  if(!origin||!allowedOrigins.includes(origin))return response({error:'Origin is not allowed'},403,cors);
  if(req.method==='OPTIONS')return new Response('ok',{headers:cors});
  if(req.method!=='POST')return response({error:'Method not allowed'},405,cors);
  try{
    const url=Deno.env.get('SUPABASE_URL')!,anon=Deno.env.get('SUPABASE_ANON_KEY')!,service=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const body=await req.json();
    const username=String(body.username||'').trim().toLowerCase();
    const password=String(body.password||'');
    const displayName=String(body.display_name||'').trim().slice(0,60);
    const setup=body.family_setup&&typeof body.family_setup==='object'?body.family_setup:{};
    const mode=setup.mode==='create'?'create':setup.mode==='join'?'join':null;
    const familyName=String(setup.familyName||'').trim().slice(0,60);
    const inviteCode=String(setup.code||'').trim().toUpperCase().replace(/[^A-Z0-9]/g,'');
    if(!/^[a-z0-9_]{3,20}$/.test(username))return response({error:'Логин: 3–20 латинских букв, цифр или _'},400,cors);
    if(password.length<8||password.length>72)return response({error:'Пароль должен содержать от 8 до 72 символов'},400,cors);
    if(displayName.length<2)return response({error:'Введите имя длиной не менее 2 символов'},400,cors);
    if(!mode||(mode==='create'&&familyName.length<2)||(mode==='join'&&inviteCode.length!==24))return response({error:mode==='join'?'Код семьи должен состоять из 24 символов. Проверьте код и попробуйте снова.':'Сначала укажите, создать семейный круг или присоединиться к нему'},400,cors);

    const forwarded=req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()||req.headers.get('cf-connecting-ip')||'unknown';
    const keyMaterial=new TextEncoder().encode(`${service}:${forwarded}`);
    const digest=await crypto.subtle.digest('SHA-256',keyMaterial);
    const ipHash=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');
    const admin=createClient(url,service,{auth:{persistSession:false,autoRefreshToken:false}});
    const {data:rateAllowed,error:rateError}=await admin.rpc('consume_signup_attempt',{p_ip_hash:ipHash});
    if(rateError)throw rateError;
    if(!rateAllowed)return response({error:'Слишком много попыток. Попробуйте через 10 минут.'},429,cors);

    const {data:existing,error:lookupError}=await admin.from('profiles').select('id').eq('username',username).maybeSingle();
    if(lookupError)throw lookupError;
    if(existing)return response({error:'Этот логин уже занят. Придумайте другой.'},409,cors);

    const family_setup=mode==='create'?{mode,familyName}:{mode,code:inviteCode};
    const email=`${username}@${internalDomain}`;
    const {data:created,error:createError}=await admin.auth.admin.createUser({email,password,email_confirm:true,user_metadata:{username,display_name:displayName,family_setup}});
    if(createError){
      if(/already|duplicate|unique/i.test(createError.message))return response({error:'Этот логин уже занят. Придумайте другой.'},409,cors);
      throw createError;
    }
    const auth=createClient(url,anon,{auth:{persistSession:false,autoRefreshToken:false}});
    const {data:login,error:loginError}=await auth.auth.signInWithPassword({email,password});
    if(loginError||!login.session){await admin.auth.admin.deleteUser(created.user.id);throw loginError||new Error('Could not create a session');}
    return response({session:login.session},200,cors);
  }catch(error){
    console.error('username-signup failed',describeError(error));
    return response({error:'Не удалось создать аккаунт. Попробуйте ещё раз.'},500,cors);
  }
});
