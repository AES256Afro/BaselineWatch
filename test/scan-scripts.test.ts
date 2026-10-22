import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readScanScripts, scanScriptFiles, sha256Hex, sumsFile, sumsText } from "../src/scan-scripts.ts";
import { startTestApp, type TestApp } from "./helpers.ts";

/**
 * The downloadable scripts: present, plain ASCII with LF endings, carrying the header that says
 * what they do and that they upload nothing, parsing in their interpreters where one is on this
 * machine (sh -n; PowerShell's parser), matching the sums recorded beside them, and served with
 * the same bytes and sums the pages show.
 */
const dir = path.join(import.meta.dirname, "..", "public", "scan");
const scripts = readScanScripts(dir);

/** The first command that runs `probe` without throwing, or null when none is on this machine. */
function findTool(candidates: string[], probe: string[]): string | null {
  for (const candidate of candidates) {
    try {
      execFileSync(candidate, probe, { stdio: "ignore", timeout: 20000 });
      return candidate;
    } catch {
      // not here; try the next
    }
  }
  return null;
}

const sh = findTool(["sh", "dash", "bash", "C:\\Program Files\\Git\\usr\\bin\\sh.exe"], ["-c", "true"]);
const powershell = findTool(["pwsh", "powershell"], ["-NoProfile", "-NonInteractive", "-Command", "exit 0"]);

let app: TestApp;

beforeAll(async () => {
  app = await startTestApp();
});

afterAll(async () => {
  await app.close();
});

describe("the device scripts", () => {
  it("exist as plain ASCII with LF endings and say what they do and that they upload nothing", () => {
    expect(scripts.map((s) => s.file)).toEqual(["bw-check.ps1", "bw-check.sh", "bw-inventory.ps1", "bw-inventory.sh"]);
    for (const script of scripts) {
      const text = script.content.toString("latin1");
      expect(text, script.file).not.toContain("\r");
      const nonAscii = [...text].filter((ch) => {
        const code = ch.charCodeAt(0);
        return !(code === 9 || code === 10 || (code >= 32 && code <= 126));
      });
      expect(nonAscii, `${script.file} is ASCII`).toEqual([]);
      expect(text, script.file).toContain("WHAT IT DOES");
      expect(text, script.file).toContain("uploads nothing");
      expect(text, script.file).toContain("No advertising domain is fetched");
      // A check script runs to hundreds of lines; an inventory script is short by nature. Either is far more than a stub.
      expect(script.bytes, script.file).toBeGreaterThan(script.file.startsWith("bw-inventory") ? 2500 : 4000);
    }
    expect(scripts[0]!.content.toString("latin1")).toMatch(/^#Requires -Version 5\.1\n/);
    expect(scripts[1]!.content.toString("latin1")).toMatch(/^#!\/bin\/sh\n/);
  });

  it("match the sums recorded in SHA256SUMS, line for line", () => {
    const recorded = readFileSync(path.join(dir, sumsFile), "utf8");
    expect(recorded).toBe(sumsText(scripts));
    for (const line of recorded.trim().split("\n")) {
      const [sum, name] = line.split("  ");
      const script = scripts.find((s) => s.file === name);
      expect(script, name).toBeDefined();
      expect(sha256Hex(script!.content), name).toBe(sum);
      expect(sha256Hex(readFileSync(path.join(dir, name!))), `${name} on disk`).toBe(sum);
    }
  });

  it.skipIf(!sh)("the sh script parses under sh -n", () => {
    execFileSync(sh!, ["-n", path.join(dir, "bw-check.sh")], { stdio: "pipe", timeout: 20000 });
  });

  it.skipIf(!powershell)("the PowerShell script parses in PowerShell's own parser", () => {
    const file = path.join(dir, "bw-check.ps1").replace(/'/g, "''");
    const command = `$errors = $null; [void][System.Management.Automation.Language.Parser]::ParseFile('${file}', [ref]$null, [ref]$errors); if ($errors.Count) { $errors | ForEach-Object { Write-Output ($_.Extent.StartLineNumber.ToString() + ': ' + $_.Message) }; exit 1 }; exit 0`;
    const output = execFileSync(powershell!, ["-NoProfile", "-NonInteractive", "-Command", command], { encoding: "utf8", timeout: 60000 });
    expect(output.trim()).toBe("");
  });

  it("are served as plain text with the same bytes, and the sums file beside them", async () => {
    for (const script of scripts) {
      const response = await fetch(`${app.base}/scan/scripts/${script.file}`);
      expect(response.status, script.file).toBe(200);
      expect(response.headers.get("content-type"), script.file).toBe("text/plain; charset=utf-8");
      expect(response.headers.get("content-disposition"), script.file).toBe(`inline; filename="${script.file}"`);
      expect(response.headers.get("x-content-type-options"), script.file).toBe("nosniff");
      const bytes = Buffer.from(await response.arrayBuffer());
      expect(bytes.equals(script.content), script.file).toBe(true);
      expect(sha256Hex(bytes), script.file).toBe(script.sha256);
    }
    const sums = await fetch(`${app.base}/scan/scripts/${sumsFile}`);
    expect(sums.status).toBe(200);
    expect(await sums.text()).toBe(sumsText(scripts));
    expect(scanScriptFiles).toEqual(["bw-check.ps1", "bw-check.sh", "bw-inventory.ps1", "bw-inventory.sh", sumsFile]);
    for (const missing of ["/scan/scripts/app.css", "/scan/scripts/bw-check.zsh", "/scan/scripts/"]) {
      expect((await fetch(`${app.base}${missing}`)).status, missing).toBe(404);
    }
  });

  it("show each script's sum beside its link on the guide pages", async () => {
    const [ps1, sh] = scripts;
    const index = await (await fetch(`${app.base}/scan/guide`)).text();
    expect(index).toContain(`<code class="sum">${ps1!.sha256}</code>`);
    expect(index).toContain(`<code class="sum">${sh!.sha256}</code>`);
    const windows = await (await fetch(`${app.base}/scan/guide/windows`)).text();
    expect(windows).toContain(`<code class="sum">${ps1!.sha256}</code>`);
    expect(windows).not.toContain(sh!.sha256);
    for (const platform of ["macos", "linux"]) {
      const text = await (await fetch(`${app.base}/scan/guide/${platform}`)).text();
      expect(text, platform).toContain(`<code class="sum">${sh!.sha256}</code>`);
      expect(text, platform).not.toContain(ps1!.sha256);
    }
  });
});
