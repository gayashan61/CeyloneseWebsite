// netlify/functions/create-staff.js
import { createClient } from '@supabase/supabase-js';

export const handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  let body = {};
  try { body = JSON.parse(event.body || '{}'); } catch { return json(400, { error: 'Bad JSON' }); }

  const {
    email,
    full_name,
    role = 'staff',
    is_admin = false,
    send_invite = true,
    password // required if send_invite=false
  } = body;

  if (!email || !full_name) return json(400, { error: 'email and full_name are required' });
  if (!send_invite && !password) return json(400, { error: 'password is required when send_invite is false' });

  const SUPABASE_URL  = process.env.SUPABASE_URL;
  const SERVICE_KEY   = process.env.SUPABASE_SERVICE_ROLE_KEY; // server-only!
  const ANON_KEY      = process.env.SUPABASE_ANON_KEY;         // used to verify caller token
  const INVITE_REDIRECT_TO = process.env.INVITE_REDIRECT_TO;   // optional

  if (!SUPABASE_URL || !SERVICE_KEY || !ANON_KEY) {
    return json(500, { error: 'Missing env vars: SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY / SUPABASE_ANON_KEY' });
  }

  // Validate caller is an admin using their Supabase JWT (from browser)
  const authHeader = event.headers.authorization || event.headers.Authorization;
  if (!authHeader) return json(401, { error: 'Missing Authorization header' });

  const caller = createClient(SUPABASE_URL, ANON_KEY, {
    global: { headers: { Authorization: authHeader } },
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { data: userRes, error: getUserErr } = await caller.auth.getUser();
  if (getUserErr || !userRes?.user) return json(401, { error: 'Invalid token' });

  // Service client for privileged ops
  const admin = createClient(SUPABASE_URL, SERVICE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  // Check caller is admin
  const { data: prof, error: profErr } = await admin
    .from('profiles').select('is_admin, role').eq('id', userRes.user.id).maybeSingle();
  if (profErr) return json(500, { error: 'Failed to read caller profile' });
  const callerIsAdmin = prof?.is_admin === true || String(prof?.role || '').toLowerCase() === 'admin';
  if (!callerIsAdmin) return json(403, { error: 'Forbidden: admin only' });

  // Create auth user
  let createdUser;
  try {
    if (send_invite) {
      const { data, error } = await admin.auth.admin.inviteUserByEmail(email, {
        redirectTo: INVITE_REDIRECT_TO
      });
      if (error) throw error;
      createdUser = data.user;
    } else {
      const { data, error } = await admin.auth.admin.createUser({
        email, password, email_confirm: true,
        user_metadata: { full_name, role, is_admin }
      });
      if (error) throw error;
      createdUser = data.user;
    }
  } catch (e) {
    return json(400, { error: e?.message || 'Failed to create auth user' });
  }

  // Upsert profiles row
  try {
    const { error: upErr } = await admin
      .from('profiles')
      .upsert({ id: createdUser.id, full_name, role, is_admin }, { onConflict: 'id' });
    if (upErr) throw upErr;
  } catch (e) {
    return json(400, { error: 'Auth user created, but profile upsert failed: ' + (e?.message || '') });
  }

  return json(200, { ok: true, id: createdUser.id, email, full_name, role, is_admin, invited: !!send_invite });
};

function json(statusCode, body) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    body: JSON.stringify(body)
  };
}
