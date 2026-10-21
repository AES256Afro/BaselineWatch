import { knownCertIds } from "../ct.ts";
import { upsertItems } from "../items.ts";
import { parseJson } from "../json.ts";
import { getSetting } from "../netscan.ts";
import type { Adapter, ParsedItem, PullOutcome } from "./types.ts";

/**
 * crt.sh, the public index of the certificate-transparency logs: `?q=<domain>&output=json` lists
 * every certificate whose names include the domain. The pull reads it for each domain the owner
 * listed on the domain check, keeps what it has seen, and makes one Wire item per certificate
 * issued since the last read — a lookalike's certificate, or one the owner did not expect, is
 * news the day it is logged. The first read of a domain is silent, except for a certificate
 * issued in the last week. crt.sh is slow and sometimes down; a domain that fails is skipped
 * this run and read again tomorrow.
 */

export const crtshUrl = (domain: string): string => `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;

/** The domains the owner listed on /scan/domain, the one setting both pages share. */
export const domainsKey = "scan.domains";

/** A certificate issued this many days before the first read is still news. */
export const firstReadWindowDays = 7;

export interface CtEntry {
  id: number;
  issuer: string | null;
  names: string[];
  notBefore: string | null;
  notAfter: string | null;
}

/** The issuer as a person says it: the CN, else the O, of the distinguished name. */
function issuerName(dn: string): string | null {
  const part = (key: string): string | null => new RegExp(`(?:^|,\\s*)${key}=([^,]+)`).exec(dn)?.[1]?.trim() ?? null;
  return part("CN") ?? part("O");
}

export function parseCrtsh(text: string): CtEntry[] {
  const data = parseJson<unknown>(text, null);
  if (!Array.isArray(data)) throw new Error("crt.sh did not answer with the JSON list expected");
  const out = new Map<number, CtEntry>();
  for (const raw of data) {
    const e = (raw ?? {}) as Record<string, unknown>;
    const id = typeof e.id === "number" ? e.id : Number(e.id);
    if (!Number.isInteger(id) || out.has(id)) continue;
    const names = typeof e.name_value === "string" ? [...new Set(e.name_value.split(/\r?\n/).map((n) => n.trim().toLowerCase()).filter((n) => n))] : [];
    out.set(id, { id, issuer: typeof e.issuer_name === "string" ? issuerName(e.issuer_name) : null, names, notBefore: typeof e.not_before === "string" ? e.not_before : null, notAfter: typeof e.not_after === "string" ? e.not_after : null });
  }
  return [...out.values()].sort((a, b) => (b.notBefore ?? "").localeCompare(a.notBefore ?? "") || b.id - a.id);
}

function certItem(domain: string, c: CtEntry): ParsedItem {
  const names = c.names.join(", ");
  return {
    kind: "article",
    externalId: `${domain}:${c.id}`,
    title: `New certificate for ${names || domain}${c.issuer ? ` (${c.issuer})` : ""}`,
    url: `https://crt.sh/?id=${c.id}`,
    summary: `Logged for ${names || domain}${c.notBefore ? `, valid from ${c.notBefore.slice(0, 10)}` : ""}${c.notAfter ? ` to ${c.notAfter.slice(0, 10)}` : ""}${c.issuer ? `, issued by ${c.issuer}` : ""}. Expected? If not, someone else holds a certificate for a name of yours.`,
    publishedAt: c.notBefore ? new Date(/[Zz]$|[+-]\d\d:\d\d$/.test(c.notBefore) ? c.notBefore : `${c.notBefore}Z`).toISOString() : null,
    signals: { domain, names: c.names, issuer: c.issuer },
  };
}

export const crtshAdapter: Adapter = {
  id: "crtsh",
  headers: { accept: "application/json" },
  async pull(ctx): Promise<PullOutcome> {
    const now = ctx.now();
    const at = now.toISOString();
    const domains = (getSetting(ctx.db, domainsKey) ?? "").split(",").map((d) => d.trim().toLowerCase()).filter((d) => d);
    if (domains.length === 0) return { items: 0, inserted: 0, updated: 0, detail: "no domain listed on the domain check; nothing to read" };
    const insert = ctx.db.prepare("INSERT OR IGNORE INTO ct_certs (domain, id, issuer, names, not_before, not_after, seen_at) VALUES (?, ?, ?, ?, ?, ?, ?)");
    const items: ParsedItem[] = [];
    let seen = 0;
    const skipped: string[] = [];
    for (const domain of domains) {
      let entries: CtEntry[];
      try {
        const response = await ctx.http(crtshUrl(domain), { headers: { accept: "application/json" }, timeoutMs: 60_000, maxBytes: 8 * 1024 * 1024 });
        entries = parseCrtsh(new TextDecoder("utf-8").decode(response.bytes));
      } catch (error) {
        ctx.log(`[crtsh] ${domain}: ${error instanceof Error ? error.message : String(error)}`);
        skipped.push(domain);
        continue;
      }
      const known = knownCertIds(ctx.db, domain);
      const firstRead = known.size === 0;
      const since = now.getTime() - firstReadWindowDays * 86_400_000;
      for (const c of entries) {
        seen += 1;
        if (known.has(c.id)) continue;
        insert.run(domain, c.id, c.issuer, c.names.join("\n"), c.notBefore, c.notAfter, at);
        const issued = c.notBefore ? new Date(`${c.notBefore}Z`).getTime() : 0;
        if (!firstRead || issued >= since) items.push(certItem(domain, c));
      }
    }
    const counts = upsertItems(ctx.db, ctx.source.id, items, at);
    return { items: seen, inserted: counts.inserted, updated: counts.updated, detail: `${domains.length - skipped.length} of ${domains.length} domain(s) read, ${items.length} new certificate(s)${skipped.length ? `; crt.sh did not answer for ${skipped.join(", ")}` : ""}` };
  },
};
