// Every test-plan template cites the vendor page its step comes from (docs/PLAN.md, M11). Vendors
// move their documentation and nothing tells us; a step whose source 404s is a step a reader
// cannot check, so this asks each URL whether it still answers. Network: the nightly probe
// workflow runs it, never `npm run test`.
//   node scripts/probe-templates.mjs
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { parse } from "yaml";
import { userAgent } from "../src/http.ts";

const dir = path.join(import.meta.dirname, "..", "data", "test-plans");

/** Every `url:` under a `source:` in a template, with the file and the step that cites it. */
function citations(doc, file) {
  const found = [];
  const walk = (node, step) => {
    if (Array.isArray(node)) return node.forEach((n) => walk(n, step));
    if (!node || typeof node !== "object") return;
    const title = typeof node.title === "string" ? node.title : step;
    if (node.source && typeof node.source === "object" && typeof node.source.url === "string") {
      found.push({ file, step: title ?? "(untitled step)", url: node.source.url, name: node.source.name ?? null });
    }
    for (const value of Object.values(node)) walk(value, title);
  };
  walk(doc, null);
  return found;
}

async function probe(url) {
  // HEAD first: a documentation page is large and we only want the status. Some vendors refuse
  // HEAD (405) while serving GET, so fall back rather than reporting a page as gone.
  for (const method of ["HEAD", "GET"]) {
    try {
      const response = await fetch(url, { method, redirect: "follow", headers: { "user-agent": userAgent, accept: "text/html,*/*" }, signal: AbortSignal.timeout(20_000) });
      if (response.ok) return { ok: true, status: response.status, final: response.url };
      if (method === "HEAD" && (response.status === 405 || response.status === 403)) continue;
      return { ok: false, status: response.status, final: response.url };
    } catch (error) {
      if (method === "GET") return { ok: false, status: 0, error: error.cause?.code ?? error.message };
    }
  }
  return { ok: false, status: 0, error: "no answer" };
}

const files = (await readdir(dir)).filter((f) => f.endsWith(".yaml")).sort();
const cites = [];
for (const file of files) cites.push(...citations(parse(await readFile(path.join(dir, file), "utf8")), file));

// One request per distinct URL: templates cite the same vendor page from several steps.
const byUrl = new Map();
for (const c of cites) byUrl.set(c.url, [...(byUrl.get(c.url) ?? []), c]);
console.log(`${files.length} template(s), ${cites.length} citation(s), ${byUrl.size} distinct URL(s)`);

const dead = [];
for (const [url, where] of byUrl) {
  const result = await probe(url);
  const mark = result.ok ? "ok  " : "DEAD";
  console.log(`${mark} ${String(result.status || result.error).padEnd(12)} ${url}`);
  if (!result.ok) dead.push({ url, where, result });
  await new Promise((r) => setTimeout(r, 300));
}

if (dead.length) {
  console.error(`\n${dead.length} citation URL(s) no longer answer:`);
  for (const d of dead) {
    console.error(`  ${d.url}  (${d.result.status || d.result.error})`);
    for (const w of d.where) console.error(`      ${w.file}: ${w.step}`);
  }
  process.exitCode = 1;
} else {
  console.log(`\nevery cited page still answers.`);
}
