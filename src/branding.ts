import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { putBlob, sha256Hex } from "./blobs.ts";
import { imageType } from "./images.ts";

/**
 * Branding: the owner's own logo and favicon, applied from the Desk. The bytes live in the
 * content-addressed blob store the way article images do, and app_settings carries each image's
 * hash and served type, so nothing new lands on disk and no migration is needed. The type comes
 * from the bytes alone, never from the upload's declared Content-Type, and SVG never qualifies
 * because it can script.
 */

export const brandKinds = ["logo", "favicon"] as const;
export type BrandKind = (typeof brandKinds)[number];

export function isBrandKind(value: unknown): value is BrandKind {
  return typeof value === "string" && (brandKinds as readonly string[]).includes(value);
}

export interface BrandImage {
  sha256: string;
  type: string;
}

/** What the layout wears: either image is null until the owner uploads one. */
export interface Brand {
  logo: BrandImage | null;
  favicon: BrandImage | null;
}

/** A masthead logo or a favicon, not a photograph. */
export const maxBrandBytes = 2 * 1024 * 1024;

const hashKey = (kind: BrandKind): string => `branding.${kind}`;
const typeKey = (kind: BrandKind): string => `branding.${kind}_type`;

/**
 * The raster types images.ts knows, plus ICO for the favicon alone: a favicon is the one place
 * browsers still expect the format, and nothing else should serve one.
 */
export function brandImageType(kind: BrandKind, bytes: Uint8Array): string | null {
  if (kind === "favicon" && bytes.length >= 6 && bytes[0] === 0x00 && bytes[1] === 0x00 && bytes[2] === 0x01 && bytes[3] === 0x00) return "image/x-icon";
  return imageType(bytes);
}

export function readBrand(db: DatabaseSync): Brand {
  const rows = db.prepare("SELECT key, value FROM app_settings WHERE key LIKE 'branding.%'").all() as { key: string; value: string }[];
  const value = (key: string): string | null => rows.find((r) => r.key === key)?.value ?? null;
  const image = (kind: BrandKind): BrandImage | null => {
    const sha256 = value(hashKey(kind));
    const type = value(typeKey(kind));
    return sha256 && /^[0-9a-f]{64}$/.test(sha256) && type ? { sha256, type } : null;
  };
  return { logo: image("logo"), favicon: image("favicon") };
}

export type SaveBrandResult = { ok: true; sha256: string; type: string } | { ok: false; error: string };

export function saveBrandImage(db: DatabaseSync, dataDir: string, kind: BrandKind, bytes: Uint8Array, at: string): SaveBrandResult {
  if (bytes.length === 0) return { ok: false, error: "the file is empty" };
  if (bytes.length > maxBrandBytes) return { ok: false, error: "the file is larger than 2 MB" };
  const type = brandImageType(kind, bytes);
  if (!type) {
    return { ok: false, error: kind === "favicon" ? "a favicon must be ICO, PNG, JPEG, GIF, WebP or AVIF; SVG is never served" : "a logo must be PNG, JPEG, GIF, WebP or AVIF; SVG is never served" };
  }
  const blob = putBlob(dataDir, bytes);
  const set = db.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at");
  set.run(hashKey(kind), blob.sha256, at);
  set.run(typeKey(kind), type, at);
  return { ok: true, sha256: blob.sha256, type };
}

/** Back to the plain wordmark (or no favicon). The blob stays in the store, as every snapshot does. */
export function clearBrandImage(db: DatabaseSync, kind: BrandKind): void {
  const del = db.prepare("DELETE FROM app_settings WHERE key = ?");
  del.run(hashKey(kind));
  del.run(typeKey(kind));
}

/** One of the repo's own marks from docs/mockups/logo, offered ready-made on the Branding page. */
export interface BrandMark {
  id: string;
  title: string;
  sha256: string;
  bytes: Uint8Array;
}

/**
 * The marks the design work already produced (docs/mockups/logo: the twenty, the refinements
 * sheet, the detail sheet), read once at start. These are the one place SVG is allowed: the files
 * are the repo's own, carry a prefers-color-scheme rule and no script, and an upload can never
 * reach this path. A checkout without the docs folder simply offers no marks.
 */
export function readBrandMarks(dir: string): BrandMark[] {
  const marks: BrandMark[] = [];
  for (const folder of ["", "refined", "detail"]) {
    const at = path.join(dir, folder);
    if (!existsSync(at)) continue;
    for (const file of readdirSync(at).filter((f) => f.endsWith(".svg")).sort()) {
      const bytes = readFileSync(path.join(at, file));
      const title = /<title>([^<]*)<\/title>/.exec(bytes.toString("utf8"))?.[1]?.replace(/^BaselineWatch mark \d+:\s*/, "");
      const id = (folder ? `${folder}-` : "") + file.replace(/\.svg$/, "");
      marks.push({ id, title: title?.trim() || id, sha256: sha256Hex(bytes), bytes: new Uint8Array(bytes) });
    }
  }
  return marks;
}

export function applyBrandMark(db: DatabaseSync, dataDir: string, kind: BrandKind, mark: BrandMark, at: string): void {
  const blob = putBlob(dataDir, mark.bytes);
  const set = db.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at");
  set.run(hashKey(kind), blob.sha256, at);
  set.run(typeKey(kind), "image/svg+xml", at);
}
