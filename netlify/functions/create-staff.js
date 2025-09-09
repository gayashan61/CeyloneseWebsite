// netlify/functions/create-staff.js
import { createClient } from '@supabase/supabase-js';

function json(statusCode, body) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    body: JSON.stringify(body)
  };
}

function generatePassword(len = 14) {
  // 14 chars: upper/lower/digits/symbols
  const U = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const L = 'abcdefghijkmnopqrstuvwxyz';
  const D = '23456789';
  const S = '!@#$%^&*()-_=+[]{}?';
  const ALL = U + L + D + S;

  // ensure complexity: at least 1 of each
  const pick = (chars) => chars[Math.floor(Math.random() * chars.length)];
  let pwd = pick(U) + pick(L) + pick(D) + pick(S);
  for (let i = 4; i < len; i++) pwd += pick(ALL);

  // shuffle
  return pwd.split('').sort(() => Math.random() - 0.5).join('');
}

export const handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  let body = {};
  try { body = JSON.parse(event.body || '{}'); } catch { return json(400, { error: 'Bad JSON' }); }

  const {
    email,
    full_name,
    // ignore incoming role / is_admin (we force staff)
    password: providedPassword
  } = body;

  if (!email || !full_name) return json(400, { error: 'email and full_name are required' });

  const SUPABASE_URL  = process.env.SUPABASE_URL;
  const SERVICE_KEY   = process.env.SUPABASE_SERVICE_ROLE_KEY; // server-only!
  const ANON_KEY      = process.env.SUPABASE_ANON_KEY;         // used to verify caller token

  if (!SUPABASE_URL || !SERVICE_KEY || !ANON_KEY) {
    return json(500, { error: 'Missing env vars: SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY / SUPABASE_ANON_KEY' });
  }

  // Validate caller (must be signed-in admin), using their Supabase JWT
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

  // Force staff role server-side
  const role = 'staff';
  const is_admin = false;

  // Use provided password if valid; otherwise auto-generate
  const password = (typeof providedPassword === 'string' && providedPassword.trim().length >= 8)
    ? providedPassword.trim()
    : generatePassword(14);

  let createdUser;
  try {
    const { data, error } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name, role, is_admin }
    });
    if (error) throw error;
    createdUser = data.user;
  } catch (e) {
    return json(400, { error: e?.message || 'Failed to create auth user' });
  }

  // Upsert profiles row (forced staff)
  try {
    const { error: upErr } = await admin
      .from('profiles')
      .upsert({ id: createdUser.id, full_name, role, is_admin }, { onConflict: 'id' });
    if (upErr) throw upErr;
  } catch (e) {
    return json(400, { error: 'Auth user created, but profile upsert failed: ' + (e?.message || '') });
  }

  // Return the password so the admin can share it securely with the staff member
  return json(200, {
    ok: true,
    id: createdUser.id,
    email,
    full_name,
    role,
    is_admin,
    invited: false,
    password
  });
};
