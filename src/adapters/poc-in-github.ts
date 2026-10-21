import type { ExploitDraft } from "../exploits.ts";
import { pullIndex } from "./exploitdb.ts";
import type { Adapter } from "./types.ts";

/**
 * nomi-sec's PoC-in-GitHub: a community-kept README listing, under a heading per CVE, the GitHub
 * repositories whose names or topics claim a proof of concept for it. A claim is what it is — a
 * repository can be empty, wrong or worse — so nothing here is marked verified, and the chip says
 * "PoC on GitHub" rather than "exploit". The README is seven megabytes and grows daily; its hash
 * keeps an unchanged day to one download.
 */

export function parsePocInGithub(text: string): ExploitDraft[] {
  const drafts: ExploitDraft[] = [];
  let cve: string | null = null;
  for (const line of text.split("\n")) {
    const head = /^### (CVE-\d{4}-\d{4,7})/.exec(line);
    if (head) {
      cve = head[1]!.toUpperCase();
      continue;
    }
    if (!cve) continue;
    const repo = /^- \[([^\]]+)\]\((https:\/\/github\.com\/[^)\s]+)\)/.exec(line);
    if (!repo) continue;
    drafts.push({ cveId: cve, ref: repo[1]!, title: repo[1]!, url: repo[2]!, publishedAt: null, verified: false });
  }
  return drafts;
}

export const pocInGithubAdapter: Adapter = {
  id: "poc-in-github",
  pull: (ctx) => pullIndex(ctx, ctx.source.url, parsePocInGithub),
};
