interface Env {
  SUPABASE_URL?: string;
  SUPABASE_ANON_KEY?: string;
  VAPID_PUBLIC_KEY?: string;
}

export const onRequestGet: PagesFunction<Env> = ({ env }) => {
  if (!env.SUPABASE_URL || !env.SUPABASE_ANON_KEY) {
    return Response.json({ error: 'Application is not configured yet' }, { status: 503 });
  }
  // The anon/publishable key is intended for browser clients. RLS protects all data.
  // Never add the Supabase service role key to this response.
  return Response.json({ url: env.SUPABASE_URL, anonKey: env.SUPABASE_ANON_KEY, vapidPublicKey: env.VAPID_PUBLIC_KEY || null }, {
    headers: { 'Cache-Control': 'no-store' },
  });
};
