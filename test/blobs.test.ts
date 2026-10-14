import { existsSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { blobRelativePath, getBlob, putBlob, sha256Hex } from "../src/blobs.ts";

let dir = "";
afterEach(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
  dir = "";
});

describe("blobs", () => {
  it("stores bytes once under their digest and reads them back", () => {
    dir = mkdtempSync(path.join(os.tmpdir(), "bw-blobs-"));
    const bytes = new TextEncoder().encode('{"catalog":{"uuid":"x"}}');
    const first = putBlob(dir, bytes);
    expect(first.created).toBe(true);
    expect(first.sha256).toBe(sha256Hex(bytes));
    expect(first.relativePath).toBe(blobRelativePath(first.sha256));
    expect(first.relativePath.startsWith("blobs/")).toBe(true);
    expect(existsSync(first.absolutePath)).toBe(true);

    const second = putBlob(dir, bytes);
    expect(second.created).toBe(false);
    expect(second.sha256).toBe(first.sha256);

    expect(getBlob(dir, first.sha256)?.toString()).toBe('{"catalog":{"uuid":"x"}}');
    expect(getBlob(dir, "0".repeat(64))).toBeNull();
  });

  it("refuses a path for anything that is not a digest", () => {
    expect(() => blobRelativePath("../etc/passwd")).toThrow(/sha256/);
  });
});
