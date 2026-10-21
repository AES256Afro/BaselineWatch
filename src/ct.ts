import type { DatabaseSync } from "node:sqlite";

/**
 * Certificates the transparency logs hold for the owner's domains (Scan 2.0, S3): one row per
 * certificate crt.sh has shown, kept so the next read knows what is new. The adapter in
 * src/adapters/crtsh.ts fills it; the domain check's page shows the recent ones.
 */

export interface CtCertRow {
  domain: string;
  id: number;
  issuer: string | null;
  names: string;
  not_before: string | null;
  not_after: string | null;
  seen_at: string;
}

/** The newest certificates for a domain, by issuance. */
export function recentCerts(db: DatabaseSync, domain: string, limit = 8): CtCertRow[] {
  return db.prepare("SELECT * FROM ct_certs WHERE domain = ? ORDER BY not_before DESC, id DESC LIMIT ?").all(domain.toLowerCase(), limit) as unknown as CtCertRow[];
}

/** The ids already seen for a domain, so a read can tell new from known. */
export function knownCertIds(db: DatabaseSync, domain: string): Set<number> {
  return new Set((db.prepare("SELECT id FROM ct_certs WHERE domain = ?").all(domain) as { id: number }[]).map((r) => r.id));
}
