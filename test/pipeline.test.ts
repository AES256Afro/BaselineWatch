import type { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { getSource, ingestSource } from "../src/ingest.ts";
import { alertAfterHours, checkLatestRelease, compareVersions, failingSources, knownRelease, markAlerted, pipelineHealth, pipelineSummary, sourcesToAlert, staleCveHours } from "../src/pipeline.ts";
import { fakeHttp, formPost, startTestApp } from "./helpers.ts";

/**
 * M13.2: the pipeline says when it has stopped. The NVD stall is the case these numbers are
 * written from — three days of nothing, reported by no one, because "failing" said nothing about
 * "since when".
 */

const now = new Date("2026-10-21T12:00:00Z");
const ago = (hours: number): string => new Date(now.getTime() - hours * 3_600_000).toISOString();

let db: DatabaseSync;

/** Puts a source into a failing or answering state the way an ingest run would. */
async function fetchOnce(id: string, route: { text?: string; status?: number }, at: Date): Promise<void> {
  const source = getSource(db, id);
  if (!source) throw new Error(`no such source: ${id}`);
  const http = fakeHttp({ [source.url]: route });
  await ingestSource(db, "/tmp/bw-unused", source, { http, now: () => at });
}

beforeEach(() => {
  db = openDatabase(":memory:");
  migrate(db);
});
afterEach(() => db.close());

describe("a failure episode", () => {
  it("starts at the first failure, survives later ones, and ends the moment the source answers", async () => {
    await fetchOnce("bleeping", { status: 503 }, new Date(now.getTime() - 30 * 3_600_000));
    const first = failingSources(db, now)[0];
    expect(first?.id).toBe("bleeping");
    expect(first?.since).toBe(ago(30));
    expect(first?.hours).toBe(30);

    // A second failure keeps the episode's start: it is one outage, not two.
    await fetchOnce("bleeping", { status: 503 }, new Date(now.getTime() - 2 * 3_600_000));
    expect(failingSources(db, now)[0]?.since).toBe(ago(30));

    await fetchOnce("bleeping", { text: "<rss><channel><title>back</title></channel></rss>" }, now);
    expect(failingSources(db, now)).toEqual([]);
    const row = db.prepare("SELECT failing_since AS since, failing_alerted_at AS alerted FROM sources WHERE id = 'bleeping'").get();
    expect(row).toEqual({ since: null, alerted: null });
  });

  it("is notified once, not once a tick, and again only after it recovers and breaks anew", async () => {
    await fetchOnce("bleeping", { status: 503 }, new Date(now.getTime() - 26 * 3_600_000));
    const due = sourcesToAlert(db, now);
    expect(due.map((d) => d.id)).toEqual(["bleeping"]);
    expect(due[0]?.hours).toBeGreaterThanOrEqual(alertAfterHours);

    markAlerted(db, "bleeping", now.toISOString());
    expect(sourcesToAlert(db, now)).toEqual([]);
    // Still failing an hour later: still silent.
    expect(sourcesToAlert(db, new Date(now.getTime() + 3_600_000))).toEqual([]);

    await fetchOnce("bleeping", { text: "<rss><channel><title>back</title></channel></rss>" }, now);
    await fetchOnce("bleeping", { status: 503 }, new Date(now.getTime() + 2 * 3_600_000));
    // A new episode, a day in, speaks again.
    expect(sourcesToAlert(db, new Date(now.getTime() + 30 * 3_600_000)).map((d) => d.id)).toEqual(["bleeping"]);
  });

  it("says nothing about a source that has failed for an hour", async () => {
    await fetchOnce("bleeping", { status: 503 }, new Date(now.getTime() - 3_600_000));
    expect(failingSources(db, now)[0]?.hours).toBe(1);
    expect(sourcesToAlert(db, now)).toEqual([]);
  });
});

describe("what the tile says", () => {
  it("is ok when every source answers and the CVE stream is moving", () => {
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-1', ?, 'cvss')").run(ago(2));
    const health = pipelineHealth(db, now);
    expect(health.state).toBe("ok");
    expect(health.failing).toEqual([]);
    expect(health.cveAgeHours).toBe(2);
    expect(pipelineSummary(health)).toBe("CVEs 2 h ago · every source answering");
  });

  it("warns on a fresh failure and goes bad once one has lasted a day", async () => {
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-1', ?, 'cvss')").run(ago(1));
    await fetchOnce("bleeping", { status: 503 }, new Date(now.getTime() - 2 * 3_600_000));
    expect(pipelineHealth(db, now).state).toBe("warn");
    expect(pipelineSummary(pipelineHealth(db, now))).toContain("failing");

    await fetchOnce("krebs", { status: 403 }, new Date(now.getTime() - 40 * 3_600_000));
    const health = pipelineHealth(db, now);
    expect(health.state).toBe("bad");
    // The worst thing true is what it says, and it names the source and the hours.
    expect(pipelineSummary(health)).toBe("Krebs on Security has failed for 40 h");
  });

  it("goes bad when the CVE stream stops, which is the stall it was written for", () => {
    db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-1', ?, 'cvss')").run(ago(staleCveHours + 24));
    const health = pipelineHealth(db, now);
    expect(health.state).toBe("bad");
    expect(health.cveAgeHours).toBe(staleCveHours + 24);
    expect(pipelineSummary(health)).toBe("the CVE pull is 2 day(s) behind");
  });

  it("counts the article images it has against the ones it looked for", () => {
    const insert = db.prepare("INSERT INTO items (source_id, kind, external_id, title, fetched_at, image_blob, image_checked_at) VALUES ('bleeping', 'article', ?, 't', ?, ?, ?)");
    insert.run("a", ago(5), "a".repeat(64), ago(5));
    insert.run("b", ago(5), null, ago(5));
    insert.run("c", ago(5), null, null);
    expect(pipelineHealth(db, now).images).toEqual({ have: 1, checked: 2 });
  });

  it("says so plainly before the first CVE has ever arrived", () => {
    const health = pipelineHealth(db, now);
    expect(health.cveAgeHours).toBeNull();
    expect(health.images).toBeNull();
    expect(pipelineSummary(health)).toBe("every source answering");
  });
});

describe("the sources table", () => {
  it("no longer carries the NVD history endpoint, which nothing reads", () => {
    expect(db.prepare("SELECT COUNT(*) AS n FROM sources WHERE id = 'nvd-cve-history'").get()).toEqual({ n: 0 });
    // The history it would have fetched is computed between sightings instead, and that still works.
    expect(db.prepare("SELECT COUNT(*) AS n FROM sources WHERE id = 'nvd-cves'").get()).toEqual({ n: 1 });
  });
});

describe("/metrics", () => {
  it("serves the same figures in the one format a dashboard scrapes", async () => {
    const app = await startTestApp({ now: () => now });
    try {
      app.db.prepare("INSERT INTO vuln_changes (cve_id, observed_at, field) VALUES ('CVE-2026-1', ?, 'cvss')").run(new Date(now.getTime() - 3_600_000).toISOString());
      const text = await (await fetch(`${app.base}/metrics`)).text();
      expect(text).toContain('baselinewatch_build_info{version=');
      expect(text).toContain("baselinewatch_sources{state=\"enabled\"}");
      expect(text).toContain("baselinewatch_rows{table=\"vulns\"} 0");
      app.db.prepare("INSERT INTO device_readings (device, os, read_at, worst, findings_json) VALUES ('laptop', 'windows', ?, 'ok', '[]')").run(now.toISOString());
      expect(await (await fetch(`${app.base}/metrics`)).text()).toContain("baselinewatch_rows{table=\"device_readings\"} 1");
      for (const table of ["exploits", "msrc_vulns", "ct_certs"]) expect(text).toContain(`baselinewatch_rows{table="${table}"} 0`);
      expect(text).toContain("baselinewatch_cve_age_seconds 3600");
      expect(text).toContain("baselinewatch_pipeline_state 0");
      // Prometheus wants a HELP and a TYPE above every metric; a dashboard refuses the file without them.
      for (const name of ["baselinewatch_build_info", "baselinewatch_rows", "baselinewatch_bytes"]) {
        expect(text).toContain(`# HELP ${name} `);
        expect(text).toContain(`# TYPE ${name} gauge`);
      }
      const response = await fetch(`${app.base}/metrics`);
      expect(response.headers.get("content-type")).toContain("text/plain");
      expect(response.headers.get("cache-control")).toBe("no-store");
    } finally {
      await app.close();
    }
  });

  it("tells a closed instance's monitor the version and nothing else", async () => {
    const app = await startTestApp({ env: { BW_PUBLIC_READ: "false", BW_ADMIN_PASSWORD: "x" }, now: () => now });
    try {
      const text = await (await fetch(`${app.base}/metrics`)).text();
      expect(text).toContain("baselinewatch_build_info{version=");
      expect(text).not.toContain("baselinewatch_rows");
      expect(text).not.toContain("baselinewatch_source_failing_seconds");
    } finally {
      await app.close();
    }
  });
});

describe("is a newer version published", () => {
  const api = "https://api.github.com/repos/AES256Afro/BaselineWatch/releases/latest";

  it("is unknown until the owner asks, because nothing polls for it", () => {
    expect(knownRelease(db)).toEqual({ version: null, checkedAt: null, newer: false });
  });

  it("keeps what the check saw, and says whether it is ahead of what runs", async () => {
    const http = fakeHttp({ [api]: { text: JSON.stringify({ tag_name: "v99.0.0" }) } });
    const result = await checkLatestRelease(db, http, now);
    expect(result).toEqual({ version: "99.0.0", checkedAt: now.toISOString(), newer: true });
    expect(knownRelease(db).newer).toBe(true);
    // One request, to one address, and only this one.
    expect(http.calls.map((c) => c.url)).toEqual([api]);
  });

  it("is not newer when it is the version running", async () => {
    const http = fakeHttp({ [api]: { text: JSON.stringify({ tag_name: `v${pipelineHealth(db, now).version}` }) } });
    expect((await checkLatestRelease(db, http, now)).newer).toBe(false);
  });

  it("forgets the old answer when a check gets none, rather than showing yesterday's", async () => {
    await checkLatestRelease(db, fakeHttp({ [api]: { text: JSON.stringify({ tag_name: "v99.0.0" }) } }), now);
    const later = new Date(now.getTime() + 86_400_000);
    const result = await checkLatestRelease(db, fakeHttp({ [api]: { status: 503 } }), later);
    expect(result).toEqual({ version: null, checkedAt: later.toISOString(), newer: false });
  });

  it("orders versions, and treats nonsense as not newer", () => {
    expect(compareVersions("0.39.0", "0.38.0")).toBe(1);
    expect(compareVersions("0.9.1", "0.10.0")).toBe(-1);
    expect(compareVersions("1.0.0", "1.0.0")).toBe(0);
    expect(compareVersions("not-a-version", "1.0.0")).toBe(0);
  });

  it("is on the Sources page, with the button for the owner alone", async () => {
    const app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "x" }, now: () => now, http: fakeHttp({ [api]: { text: JSON.stringify({ tag_name: "v99.0.0" }) } }) });
    try {
      const anonymous = await (await fetch(`${app.base}/sources`)).text();
      expect(anonymous).toContain("running");
      expect(anonymous).toContain("never checked");
      expect(anonymous).not.toContain('action="/sources/check-version"');
      // A visitor cannot make this instance call out.
      const refused = await formPost(app.base, "/sources/check-version", {});
      expect(refused.status).toBe(403);
    } finally {
      await app.close();
    }
  });
});
