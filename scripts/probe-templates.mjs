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
      // A 401, 403 or 429 on GET is the vendor's edge refusing this client (docs.redhat.com's
      // Akamai answers "Access Denied" to anything that is not a browser), not word that the page
      // has gone. Reported, never counted as dead.
      if ([401, 403, 429].includes(response.status)) return { ok: false, refused: true, status: response.status, final: response.url };
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
const refused = [];
for (const [url, where] of byUrl) {
  const result = await probe(url);
  const mark = result.ok ? "ok  " : result.refused ? "SKIP" : "DEAD";
  console.log(`${mark} ${String(result.status || result.error).padEnd(12)} ${url}`);
  if (result.refused) refused.push(url);
  else if (!result.ok) dead.push({ url, where, result });
  await new Promise((r) => setTimeout(r, 300));
}

if (refused.length) {
  console.log(`\n${refused.length} citation URL(s) refused this client and went unchecked (a person in a browser can still check them):`);
  for (const url of refused) console.log(`  ${url}`);
}

if (dead.length) {
  console.error(`\n${dead.length} citation URL(s) no longer answer:`);
  for (const d of dead) {
    console.error(`  ${d.url}  (${d.result.status || d.result.error})`);
    for (const w of d.where) console.error(`      ${w.file}: ${w.step}`);
  }
  process.exitCode = 1;
} else {
  console.log(refused.length ? `\nno cited page is dead; the refused ones above went unchecked.` : `\nevery cited page still answers.`);
}
