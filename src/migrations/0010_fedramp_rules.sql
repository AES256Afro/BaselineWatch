-- FedRAMP's machine-readable Consolidated Rules for 2026 (checked 2026-10-15): the FRR rules by
-- family and subset, the Key Security Indicators, the definitions and the parameter values and
-- guidance FedRAMP sets on NIST SP 800-53 controls, one JSON file on GitHub, diffed entry by
-- entry. Takes the place of the plan's FedRAMP Rev5 OSCAL baselines, whose repository GSA has
-- taken down.

INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes) VALUES
('fedramp-rules', 'FedRAMP Consolidated Rules (2026)', 'requirement-set', 'standards', 'https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json', 'json', 'daily', 1, 'US Government work, public domain', NULL, 'FRR rules, KSI indicators, FRD definitions and CTL parameter selections, each with FedRAMP''s dated change notes. Published at https://github.com/FedRAMP/rules.');
