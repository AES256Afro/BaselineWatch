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
  serial: string | null;
  issuer_dn: string | null;
}

/** The newest certificates for a domain, by issuance. */
export function recentCerts(db: DatabaseSync, domain: string, limit = 8): CtCertRow[] {
  return db.prepare("SELECT * FROM ct_certs WHERE domain = ? ORDER BY not_before DESC, id DESC LIMIT ?").all(domain.toLowerCase(), limit) as unknown as CtCertRow[];
}

/**
 * One issuance: crt.sh lists a precertificate and its certificate under two ids, with the same
 * serial from the same issuer. The parse folds the pair on this key and the next read tells a known
 * issuance by it; null when crt.sh gave no serial.
 */
export const issuanceKey = (serial: string | null, issuerDn: string | null): string | null => (serial ? `${serial.toLowerCase()}\u0000${issuerDn ?? ""}` : null);

/** The key a row stored before serials were kept (migration 0062) answers to: the issuer, the names and the start. */
const legacyIssuanceKey = (issuer: string | null, names: string, notBefore: string | null): string => `legacy\u0000${issuer ?? ""}\u0000${names}\u0000${notBefore ?? ""}`;

/** What a read needs of a certificate to tell whether it is known. */
export interface CtIssuance {
  id: number;
  serial: string | null;
  issuerDn: string | null;
  issuer: string | null;
  names: string[];
  notBefore: string | null;
}

export interface KnownCerts {
  ids: Set<number>;
  issuances: Set<string>;
}

/** The ids already seen for a domain, and the issuances they stand for, so a read can tell new from known. */
export function knownCerts(db: DatabaseSync, domain: string): KnownCerts {
  const rows = db.prepare("SELECT id, issuer, names, not_before, serial, issuer_dn FROM ct_certs WHERE domain = ?").all(domain) as { id: number; issuer: string | null; names: string; not_before: string | null; serial: string | null; issuer_dn: string | null }[];
  return { ids: new Set(rows.map((r) => r.id)), issuances: new Set(rows.map((r) => issuanceKey(r.serial, r.issuer_dn) ?? legacyIssuanceKey(r.issuer, r.names, r.not_before))) };
}

/**
 * Known by id, or as the other half of an issuance a row already holds (a read that saw only the
 * precertificate, then both): by serial and issuer where the row has them, else, for a row stored
 * before serials were kept, by issuer, names and start.
 */
export function isKnownCert(known: KnownCerts, c: CtIssuance): boolean {
  if (known.ids.has(c.id)) return true;
  const key = issuanceKey(c.serial, c.issuerDn);
  return (key !== null && known.issuances.has(key)) || known.issuances.has(legacyIssuanceKey(c.issuer, c.names.join("\n"), c.notBefore));
}
