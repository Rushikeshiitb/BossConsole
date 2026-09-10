-- Restrict plugin_downloads to the server-side download pipeline only.
--
-- Problem
-- -------
-- plugin_downloads stores one row per download with `user_id` and `ip_hash`
-- (see 20260130000000_plugin_store_tables.sql). Its original RLS policies were:
--
--   SELECT USING (true)        -- "aggregated only via functions" (it was not)
--   INSERT WITH CHECK (true)   -- "service role can insert" (it was not scoped)
--
-- Neither policy was scoped to a role, so both applied to `anon` and
-- `authenticated`, the roles RLS actually gates (service_role runs the
-- SECURITY DEFINER pipeline below and never needed a permissive policy). The
-- result was two live defects reachable with nothing more than the anon/JWT key
-- the desktop client already ships:
--
--   1. Read leak. `select * from plugin_downloads` returned every row to any
--      client - which user downloaded which plugin and when, plus ip_hash -
--      across all users. The "aggregated only via functions" intent was never
--      enforced.
--   2. Forgeable writes. `WITH CHECK (true)` let any client insert arbitrary
--      rows: inflate download_count (which drives the store's default
--      `sortBy = "downloads"` ranking) or write rows with a forged user_id.
--
-- Why this is safe
-- ----------------
-- Every legitimate path is SECURITY DEFINER and so bypasses RLS:
--   - reads:  get_plugin_with_stats, search_plugins, get_plugin_versions
--             (all COUNT(*) over plugin_downloads)
--   - writes: record_plugin_download (EXECUTE granted to service_role only),
--             called from the plugin-store Edge Function.
-- So removing the permissive client policies changes nothing for the app and
-- closes both defects. Direct table reads and writes by anon/authenticated are
-- denied by RLS with no permissive policy in force.

-- Belt and braces: drop the inherited base-table privileges too, so the gate does
-- not rely on RLS alone. The SECURITY DEFINER functions above run as their owner
-- and are unaffected; a future permissive policy could not re-open access without
-- a matching GRANT being added deliberately.
REVOKE SELECT, INSERT, UPDATE, DELETE ON public.plugin_downloads FROM anon, authenticated;

-- Remove the over-broad policies. IF EXISTS keeps this re-runnable.
DROP POLICY IF EXISTS "Downloads viewable via service role" ON public.plugin_downloads;
DROP POLICY IF EXISTS "Service role can track downloads" ON public.plugin_downloads;

-- Re-state the intent explicitly for service_role. These are no-ops at runtime
-- (service_role bypasses RLS) but keep the intended access legible next to the
-- table and guard against a future GRANT to service_role changing behaviour.
CREATE POLICY "plugin_downloads service role read"
    ON public.plugin_downloads FOR SELECT TO service_role
    USING (true);

CREATE POLICY "plugin_downloads service role insert"
    ON public.plugin_downloads FOR INSERT TO service_role
    WITH CHECK (true);

COMMENT ON POLICY "plugin_downloads service role read" ON public.plugin_downloads IS
    'Raw rows are service-role only; clients read counts through the SECURITY DEFINER stats functions.';
COMMENT ON POLICY "plugin_downloads service role insert" ON public.plugin_downloads IS
    'Downloads are written only by record_plugin_download (SECURITY DEFINER, service_role).';
