-- One active monitoring rule per target, capture profile AND case. The same
-- deduplicated target can belong to several cases; a rule in one case must not
-- block (or reveal) a rule in another. The per-target daily revisit cap still
-- applies across all cases (monitor.ts), so visits to the site stay proportionate.
DROP INDEX monitoring_rules_one_active_idx;
CREATE UNIQUE INDEX monitoring_rules_one_active_idx ON monitoring_rules (target_id, case_id, capture_variant) WHERE active;
