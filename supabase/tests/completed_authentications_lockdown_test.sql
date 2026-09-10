-- pgTAP tests for the completed_authentications lockdown
-- (migration 20260911000000_revoke_anon_completed_authentications.sql).
--
-- completed_authentications stores freshly minted access_token + refresh_token
-- for the cross-device (QR) login flow. Its original anon policies were guarded
-- only by `session_id IS NOT NULL`, which is TRUE for every real row, so with
-- the public anon apikey plus `GRANT ALL ... TO anon` any client could read
-- every in-flight login's tokens, delete them all, or pre-seed a victim's
-- session. The migration drops the anon and authenticated policies and revokes
-- their grants, leaving service_role (the Edge Function path) as the only way
-- in. RLS alone would not be enough here: the table privilege has to go too, so
-- both halves are asserted.

begin;
select plan(6);

-- ---------------------------------------------------------------------------
-- Table grants: anon and authenticated hold nothing, service_role keeps all.
-- ---------------------------------------------------------------------------
select ok(
    NOT has_table_privilege('anon', 'public.completed_authentications', 'SELECT')
    AND NOT has_table_privilege('anon', 'public.completed_authentications', 'INSERT')
    AND NOT has_table_privilege('anon', 'public.completed_authentications', 'UPDATE')
    AND NOT has_table_privilege('anon', 'public.completed_authentications', 'DELETE'),
    'anon holds no privilege on completed_authentications - the public apikey can no longer reach the tokens'
);

select ok(
    NOT has_table_privilege('authenticated', 'public.completed_authentications', 'SELECT')
    AND NOT has_table_privilege('authenticated', 'public.completed_authentications', 'INSERT')
    AND NOT has_table_privilege('authenticated', 'public.completed_authentications', 'UPDATE')
    AND NOT has_table_privilege('authenticated', 'public.completed_authentications', 'DELETE'),
    'authenticated holds no privilege on completed_authentications either'
);

select ok(
    has_table_privilege('service_role', 'public.completed_authentications', 'SELECT')
    AND has_table_privilege('service_role', 'public.completed_authentications', 'INSERT')
    AND has_table_privilege('service_role', 'public.completed_authentications', 'UPDATE')
    AND has_table_privilege('service_role', 'public.completed_authentications', 'DELETE'),
    'service_role keeps full access - the Edge Function path is unaffected'
);

-- ---------------------------------------------------------------------------
-- Policies: no anon or authenticated policy survives; the service_role one does.
-- A leftover policy for a role that holds no privilege would be misleading dead
-- code, and a leftover anon policy would be the exact hole this migration closes
-- if a grant were ever re-added by accident.
-- ---------------------------------------------------------------------------
select is(
    (select count(*)::int from pg_policies
      where schemaname = 'public'
        and tablename = 'completed_authentications'
        and 'anon' = any(roles)),
    0,
    'no anon policy remains on completed_authentications'
);

select is(
    (select count(*)::int from pg_policies
      where schemaname = 'public'
        and tablename = 'completed_authentications'
        and 'authenticated' = any(roles)),
    0,
    'no authenticated policy remains on completed_authentications'
);

select is(
    (select count(*)::int from pg_policies
      where schemaname = 'public'
        and tablename = 'completed_authentications'
        and 'service_role' = any(roles)),
    1,
    'the service_role policy is left intact'
);

select * from finish();
rollback;
