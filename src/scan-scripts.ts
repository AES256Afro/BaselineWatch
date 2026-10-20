import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

/**
 * The downloadable scripts of the Scan area (M12.2): one PowerShell file for Windows and one
 * POSIX sh file for macOS and Linux, each doing by itself what the manual guide does by hand.
 * They are static files under public/scan/, served as plain text at /scan/scripts/<name> with
 * their SHA-256 shown beside every link, and public/scan/SHA256SUMS records the same sums in the
 * format `sha256sum -c` reads. The sums shown are computed from the bytes served, so they cannot
 * drift from the download; test/scan-scripts.test.ts holds the recorded file to the same bytes.
 */
export type ScriptPlatform = "windows" | "macos" | "linux";

export interface ScanScript {
  /** The file name, as downloaded and as served under /scan/scripts/. */
  file: string;
  /** The platforms it runs on, in the guide's words. */
  label: string;
  /** The interpreter it needs. */
  shell: string;
  /** The command that runs it. */
  run: string;
  /** The command that prints its SHA-256 on that platform. */
  verify: string;
  platforms: readonly ScriptPlatform[];
  sha256: string;
  bytes: number;
  content: Buffer;
}

const metadata: readonly Omit<ScanScript, "sha256" | "bytes" | "content">[] = [
  {
    file: "bw-check.ps1",
    label: "Windows",
    shell: "Windows PowerShell 5.1 or PowerShell 7",
    run: "powershell -ExecutionPolicy Bypass -File .\\bw-check.ps1",
    verify: "Get-FileHash .\\bw-check.ps1",
    platforms: ["windows"],
  },
  {
    file: "bw-check.sh",
    label: "macOS and Linux",
    shell: "POSIX sh: macOS's /bin/sh, dash, bash or zsh",
    run: "sh ./bw-check.sh",
    verify: "shasum -a 256 bw-check.sh (macOS) or sha256sum bw-check.sh (Linux)",
    platforms: ["macos", "linux"],
  },
];

/** The name of the sums file, served beside the scripts. */
export const sumsFile = "SHA256SUMS";

export const scanScriptFiles: readonly string[] = [...metadata.map((m) => m.file), sumsFile];

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Reads the scripts from `dir` (public/scan) once, with the sums of the bytes that will be served. */
export function readScanScripts(dir: string): ScanScript[] {
  return metadata.map((m) => {
    const content = readFileSync(path.join(dir, m.file));
    return { ...m, content, bytes: content.length, sha256: sha256Hex(content) };
  });
}

/** The sums file's lines for these scripts, the way `sha256sum` writes them. */
export function sumsText(scripts: readonly ScanScript[]): string {
  return scripts.map((s) => `${s.sha256}  ${s.file}`).join("\n") + "\n";
}

/** The scripts that run on a platform, for the guide page's download box. */
export function scriptsFor(scripts: readonly ScanScript[], platform: ScriptPlatform): ScanScript[] {
  return scripts.filter((s) => s.platforms.includes(platform));
}
