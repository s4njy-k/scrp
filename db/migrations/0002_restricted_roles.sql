-- Least-privilege grants for optional adapters (blueprint §13).
-- The optional Scrapling worker runs its browser in the same container as its
-- driver (weaker boundary than the hardened driver/engine split), so its
-- database role may only lease/commit scrapling-stage work and never read
-- source records, identifiers, findings or case holds.
-- The login role itself is created by docker/postgres/init-roles.sh when a
-- password secret is supplied; these grants apply only if it exists.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'collector_scrapling') THEN
    GRANT USAGE ON SCHEMA public TO collector_scrapling;
    GRANT SELECT ON targets, capture_profiles, system_state TO collector_scrapling;
    GRANT SELECT, UPDATE ON jobs, global_permits TO collector_scrapling;
    GRANT SELECT, INSERT, UPDATE ON attempts, domain_pacing TO collector_scrapling;
    GRANT SELECT, INSERT, DELETE ON artifacts, domain_edges TO collector_scrapling;
    GRANT INSERT ON audit_events, sessions TO collector_scrapling;
    GRANT USAGE ON SEQUENCE lease_token_seq, artifacts_id_seq, domain_edges_id_seq, audit_events_id_seq TO collector_scrapling;
  END IF;
END $$;
