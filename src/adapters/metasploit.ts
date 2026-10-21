import type { ExploitDraft } from "../exploits.ts";
import { pullIndex } from "./exploitdb.ts";
import type { Adapter } from "./types.ts";

/**
 * Metasploit Framework's module metadata, db/modules_metadata_base.json in its repository: every
 * module with its references, of which the CVE ids are kept. A module that exists is the strongest
 * public-exploit signal there is short of KEV, and its rank says how reliably it works: good or
 * better is marked verified here. The file is eleven megabytes; its hash keeps an unchanged day
 * to one download.
 */

interface MsfModule {
  name?: string;
  fullname?: string;
  rank?: number;
  disclosure_date?: string | null;
  type?: string;
  references?: string[];
  path?: string;
}

/** Metasploit's numeric ranks; 400 is "good", the first rank the project calls reliable. */
export const goodRank = 400;

export function parseMetasploit(text: string): ExploitDraft[] {
  const modules = JSON.parse(text) as Record<string, MsfModule>;
  const drafts: ExploitDraft[] = [];
  for (const m of Object.values(modules)) {
    const cves = (m.references ?? []).filter((r) => /^CVE-\d{4}-\d{4,7}$/i.test(r)).map((r) => r.toUpperCase());
    if (cves.length === 0 || !m.fullname) continue;
    const path = (m.path ?? "").replace(/^\//, "");
    for (const cve of cves) {
      drafts.push({
        cveId: cve,
        ref: m.fullname,
        title: `${m.name ?? m.fullname}${m.type ? ` (${m.type} module)` : ""}`,
        url: path ? `https://github.com/rapid7/metasploit-framework/blob/master/${path}` : "https://github.com/rapid7/metasploit-framework",
        publishedAt: m.disclosure_date && /^\d{4}-\d{2}-\d{2}/.test(m.disclosure_date) ? `${m.disclosure_date.slice(0, 10)}T00:00:00.000Z` : null,
        verified: (m.rank ?? 0) >= goodRank,
      });
    }
  }
  return drafts;
}

export const metasploitAdapter: Adapter = {
  id: "metasploit",
  pull: (ctx) => pullIndex(ctx, ctx.source.url, parseMetasploit),
};
