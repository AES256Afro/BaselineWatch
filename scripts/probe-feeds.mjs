// Probes every enabled rss/atom source's URL and reports which no longer answer with XML, so a
// dead feed (Ars, Sophos) or a bot-blocked form (Reddit's JSON listing) is caught before it
// ships. Network: run by hand or in a scheduled CI job, never from `npm run test`.
//   node scripts/probe-feeds.mjs
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { adapterFor, feedAdapter, hnAdapter, redditAdapter } from "../src/adapters/index.ts";
import { migrate, openDatabase } from "../src/db.ts";
import { userAgent } from "../src/http.ts";

const dir = mkdtempSync(path.join(os.tmpdir(), "bw-probe-"));
const db = openDatabase(":memory:");
migrate(db);
// Only sources whose URL is itself the fetched document: feeds, subreddits, the HN search. Pull
// adapters (NVD, OSV, cvelist) build their own requests, so their base URLs prove nothing.
const sources = db
  .prepare("SELECT id, name, url, format FROM sources WHERE enabled = 1 AND url LIKE 'http%' ORDER BY id")
  .all()
  .filter((s) => [feedAdapter, redditAdapter, hnAdapter].includes(adapterFor(s)));
db.close();
rmSync(dir, { recursive: true, force: true });

async function probe(s) {
  const res = await fetch(s.url, {
    headers: { "user-agent": userAgent, accept: "application/rss+xml, application/atom+xml, application/xml, text/xml, application/json;q=0.9, */*;q=0.5" },
    redirect: "follow",
    signal: AbortSignal.timeout(30_000),
  });
  const head = (await res.text()).slice(0, 200).trimStart();
  const looksRight = s.format === "json" ? head.startsWith("{") || head.startsWith("[") : head.startsWith("<?xml") || head.startsWith("<rss") || head.startsWith("<feed");
  if (res.status === 429) return "rate-limited (fine on a probe burst)";
  if (!res.ok) return `HTTP ${res.status}`;
  if (!looksRight) return `answers ${res.status} but not ${s.format} (first bytes: ${head.slice(0, 40).replace(/\s+/g, " ")})`;
  return "ok";
}

let failures = 0;
for (const s of sources) {
  let verdict = "ok";
  try {
    verdict = await probe(s);
  } catch {
    // One retry covers a slow or flaky answer; a second miss is worth reporting.
    try {
      verdict = await probe(s);
    } catch (error) {
      verdict = error instanceof Error ? error.message : String(error);
    }
  }
  const bad = verdict !== "ok" && !verdict.startsWith("rate-limited");
  if (bad) failures += 1;
  console.log(`${bad ? "FAIL" : "  ok"} ${s.id.padEnd(26)} ${verdict === "ok" ? "" : verdict}`);
  await new Promise((r) => setTimeout(r, 400));
}
console.log(failures ? `\n${failures} feed(s) need attention` : "\nevery feed answers");
process.exit(failures ? 1 : 0);
