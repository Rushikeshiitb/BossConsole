-- ============================================================================
-- BOSS Database Schema: Lock down completed_authentications to service_role
-- ============================================================================
-- File: 20260911000000_revoke_anon_completed_authentications.sql
-- Description:
--   Removes the anon (and authenticated) access to completed_authentications.
--   That table stores freshly minted access_token + refresh_token for the
--   cross-device (QR) login flow, and its original policies were guarded only
--   by `session_id IS NOT NULL` - a per-row filter that is TRUE for every real
--   row, so it never checked that the caller actually knows a session_id.
--
--   Combined with `GRANT ALL ... TO anon` and the fact that the anon key is
--   public (shipped in the desktop app; the repo is public), any client with
--   the anon apikey could hit PostgREST directly and:
--     - Token harvest -> account takeover:
--         GET /rest/v1/completed_authentications?select=*
--         returns every in-flight login's access_token / refresh_token.
--     - DoS: DELETE /rest/v1/completed_authentications wipes all in-flight
--         logins.
--     - Session fixation: anon INSERT lets an attacker pre-seed a victim's
--         session_id with the attacker's tokens.
--
--   This is dead code as far as the real flow is concerned. The desktop no
--   longer touches this table directly - it polls the Edge Function
--   (GET /passkey/auth/status/{sessionId}, service role) and writes through the
--   Edge Function too (auth.ts checkAuthStatus / storeCompletedAuthentication).
--   So dropping the anon/authenticated policies and revoking their grants
--   removes the exposure without touching the only real path, service_role,
--   which bypasses RLS.
--
-- Dependencies:
--   - 20251023000013_rls_policies.sql (created the policies dropped here)
--   - 20251023000014_grants.sql       (created the grants revoked here)
--
-- Test: supabase/tests/completed_authentications_lockdown_test.sql
-- ============================================================================


-- ----------------------------------------------------------------------------
-- 1. Drop the anon policies (the leaking path)
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS "Anon can insert completed authentications" ON "public"."completed_authentications";
DROP POLICY IF EXISTS "Anon can select by session_id"             ON "public"."completed_authentications";
DROP POLICY IF EXISTS "Anon can delete by session_id"             ON "public"."completed_authentications";


-- ----------------------------------------------------------------------------
-- 2. Drop the authenticated policies
-- ----------------------------------------------------------------------------
-- The grant below removes every authenticated privilege on this table, so these
-- policies can never fire again. Dropping them keeps the RLS surface honest: a
-- policy for a role that holds no table privilege is misleading dead code. Every
-- real mutation and read of this table goes through the service_role Edge
-- Function, never a logged-in client.
DROP POLICY IF EXISTS "Authenticated users can insert own results" ON "public"."completed_authentications";
DROP POLICY IF EXISTS "Authenticated users can select own results" ON "public"."completed_authentications";
DROP POLICY IF EXISTS "Authenticated users can delete own results" ON "public"."completed_authentications";


-- ----------------------------------------------------------------------------
-- 3. Revoke the table grants from anon and authenticated
-- ----------------------------------------------------------------------------
-- Supabase's default privileges GRANT ALL ON TABLES to anon and authenticated
-- for schema public, and 20251023000014_grants.sql granted them explicitly too,
-- so RLS alone is not enough - the privilege has to go as well. service_role is
-- deliberately left untouched: it is the only real path and it bypasses RLS.
REVOKE ALL ON TABLE "public"."completed_authentications" FROM "anon";
REVOKE ALL ON TABLE "public"."completed_authentications" FROM "authenticated";
