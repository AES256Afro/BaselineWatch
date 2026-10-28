-- AI tooling joins the platforms (src/platforms.ts): model servers, agent frameworks, chat front
-- ends, ML libraries and MCP servers, by vendor and product. Every CVE's platforms are cleared so
-- recomputePlatforms reads them again with the new rule at the next start (about a second, once),
-- and the trigger from 0047 keeps vuln_platforms in step as it does.
UPDATE vulns SET platforms_json = NULL;
