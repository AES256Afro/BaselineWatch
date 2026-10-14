import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";

/**
 * Content-addressed snapshot store: <dataDir>/blobs/<first two hex>/<sha256>.
 * Writing the same bytes twice is a no-op, so a source that has not changed costs nothing.
 */
export interface StoredBlob {
  sha256: string;
  bytes: number;
  /** Relative to the data dir, the form the snapshots table records. */
  relativePath: string;
  absolutePath: string;
  /** False when the blob was already present. */
  created: boolean;
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function blobRelativePath(sha256: string): string {
  if (!/^[0-9a-f]{64}$/.test(sha256)) throw new Error("not a sha256 hex digest");
  return path.posix.join("blobs", sha256.slice(0, 2), sha256);
}

export function putBlob(dataDir: string, bytes: Uint8Array): StoredBlob {
  const sha256 = sha256Hex(bytes);
  const relativePath = blobRelativePath(sha256);
  const absolutePath = path.join(dataDir, relativePath);
  if (existsSync(absolutePath)) {
    return { sha256, bytes: bytes.byteLength, relativePath, absolutePath, created: false };
  }
  mkdirSync(path.dirname(absolutePath), { recursive: true });
  const temporary = `${absolutePath}.${process.pid}.tmp`;
  writeFileSync(temporary, bytes);
  renameSync(temporary, absolutePath);
  return { sha256, bytes: bytes.byteLength, relativePath, absolutePath, created: true };
}

export function getBlob(dataDir: string, sha256: string): Buffer | null {
  const absolutePath = path.join(dataDir, blobRelativePath(sha256));
  return existsSync(absolutePath) ? readFileSync(absolutePath) : null;
}
