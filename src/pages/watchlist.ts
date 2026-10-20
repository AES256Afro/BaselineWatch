import type { DatabaseSync } from "node:sqlite";
import { html } from "../html.ts";
import { loadWatchlist } from "../vulns.ts";
import type { LookState } from "../look.ts";
import { page } from "./layout.ts";

export function renderWatchlist(options: { db: DatabaseSync; owner: boolean; open: boolean; notice?: string | undefined; look: LookState }): string {
  const { db, owner, open, notice, look } = options;
  const entries = loadWatchlist(db);
  const counts = new Map<number, number>();
  for (const e of entries) {
    const label = e.label?.trim() || e.value;
    const n = (db.prepare("SELECT COUNT(*) AS n FROM vulns WHERE watch_labels_json LIKE ?").get(`%${JSON.stringify(label).slice(1, -1)}%`) as { n: number }).n;
    counts.set(e.id, n);
  }

  const kindLabel: Record<string, string> = { product: "Product", keyword: "Keyword", baseline: "Baseline", family: "Control family", package: "Package", platform: "Platform" };

  const content = html`
    <h1>Watchlist</h1>
    <p class="lede">What you own. A CVE that touches a product here is marked as your stack, goes in the News however small its score, and can be filtered to on the Vulnerabilities page. Baselines and control families are used by the Register from M3.</p>
    ${notice ? html`<div class="notice ok">${notice}</div>` : ""}
    <div class="cols">
      <section class="main">
        ${entries.length === 0
          ? html`<div class="empty"><b>Nothing watched yet.</b><p>Add a vendor or product name (<code>fortinet</code>, <code>fortios</code>), a vendor:product pair (<code>cisco:ios_xe</code>), a CPE prefix (<code>cpe:2.3:o:microsoft:windows_server_2025</code>), or a keyword that should match a description.</p></div>`
          : html`<div class="table-wrap"><table>
              <thead><tr><th>Kind</th><th>Value</th><th>Label</th><th>CVEs matched</th>${owner ? html`<th></th>` : ""}</tr></thead>
              <tbody>${entries.map(
                (e) => html`<tr>
                  <td>${kindLabel[e.kind] ?? e.kind}</td>
                  <td><code>${e.value}</code></td>
                  <td>${e.label ?? ""}</td>
                  <td class="n"><a href="/vulnerabilities?watch=1&q=${encodeURIComponent(e.label?.trim() || e.value)}">${counts.get(e.id) ?? 0}</a></td>
                  ${owner ? html`<td><form method="post" action="/watchlist/${e.id}/delete" class="inline"><button type="submit">Remove</button></form></td>` : ""}
                </tr>`,
              )}</tbody>
            </table></div>`}
      </section>
      <aside class="side">
        ${owner
          ? html`<section class="box" id="add">
              <h2><a href="#add">Add to the watchlist</a></h2>
              <form method="post" action="/watchlist" class="stack">
                <label for="kind">Kind</label>
                <select id="kind" name="kind">
                  <option value="product">Product: vendor, product, vendor:product or CPE prefix</option>
                  <option value="package">Package: ecosystem:name (npm:express, PyPI:django, Maven:group:artifact, Debian:12:openssl), advisories from OSV and GitHub</option>
                  <option value="platform">Platform: windows, apple, linux, android, chrome, firefox, edge or network, so every CVE on it is your stack</option>
                  <option value="keyword">Keyword in the description</option>
                  <option value="baseline">Baseline I follow (Register, M3)</option>
                  <option value="family">Control family I own (Register, M3)</option>
                </select>
                <label for="value">Value</label>
                <input type="text" id="value" name="value" required maxlength="200" placeholder="fortinet:fortios">
                <label for="label">Label (optional)</label>
                <input type="text" id="label" name="label" maxlength="60" placeholder="Edge firewalls">
                <button type="submit" class="primary">Add</button>
              </form>
            </section>`
          : html`<section class="box"><h2><a href="/login">Owner only</a></h2><p class="small"><a href="/login">Sign in</a> to change the watchlist.</p></section>`}
        <section class="box">
          <h2><a href="/vulnerabilities?watch=1">How matching works</a></h2>
          <p class="small">Product entries match the CPE criteria NVD attaches to a CVE: a bare name matches the vendor or the product field, <code>vendor:product</code> matches both, and a <code>cpe:2.3:</code> prefix matches literally. A platform entry matches by the CPE's operating system or browser, then NVD's vendor and product, then the way the description names the platform for a CVE NVD has not analysed yet, so a new macOS CVE reaches the News, the alerts ("New Apple CVE") and the digest at once. CVEs that have no CPE yet otherwise match only by keyword. Every CVE is re-checked when the list changes.</p>
        </section>
      </aside>
    </div>`;

  return page({ title: "Watchlist", active: "watchlist", content, meta: html`${entries.length} entries`, owner, open, look });
}
