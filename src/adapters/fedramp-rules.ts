/**
 * FedRAMP Consolidated Rules for 2026: one JSON file FedRAMP publishes on GitHub with its rules
 * (FRR, by family and subset), Key Security Indicators (KSI), definitions (FRD) and the
 * parameter values and guidance it sets on NIST SP 800-53 controls (CTL). Every entry is a
 * requirement here, and each entry's dated "updated" notes are FedRAMP's own words beside the
 * changes they explain. The file replaces the Rev5 OSCAL baselines, whose repository is gone.
 */
import type { NormalizedRequirement } from "../oscal.ts";
import type { Adapter, DocumentTarget, ParsedDocument, RequirementNote, SourceRow } from "./types.ts";
import { isoDate } from "./types.ts";

export const rulesRepository = "https://github.com/FedRAMP/rules";
const raw = "https://raw.githubusercontent.com/FedRAMP/rules";
const file = "fedramp-consolidated-rules.json";

/** Commits of FedRAMP/rules that changed the file, oldest first, for the backfill; the daily fetch reads `main`. */
const history = ["083137da3b", "58487bda77", "1c33385a06", "6eb376782a"] as const;

type Json = Record<string, unknown>;

function obj(v: unknown): Json {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Json) : {};
}

function text(v: unknown): string | null {
  return typeof v === "string" && v.trim() !== "" ? v.trim() : null;
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.trim() !== "").map((x) => x.trim()) : [];
}

function lines(parts: (string | null)[]): string | null {
  const kept = parts.filter((p): p is string => p !== null && p !== "");
  return kept.length ? kept.join("\n") : null;
}

/** The newest dated note on an entry, as "date: comment". */
function latestNote(updated: unknown): string | null {
  const entries = (Array.isArray(updated) ? updated : [])
    .map((u) => obj(u))
    .filter((u) => text(u.comment))
    .sort((a, b) => String(b.date ?? "").localeCompare(String(a.date ?? "")));
  const first = entries[0];
  return first ? `${text(first.date) ?? "undated"}: ${text(first.comment)}` : null;
}

function notesOn(updated: unknown, date: string | null): string[] {
  if (!date) return [];
  return (Array.isArray(updated) ? updated : [])
    .map((u) => obj(u))
    .filter((u) => text(u.date) === date)
    .map((u) => text(u.comment))
    .filter((c): c is string => c !== null);
}

/** Only the fields worth keeping on the requirement's extra, and only when present. */
function compact(fields: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (v === null || v === undefined || v === "" || (Array.isArray(v) && v.length === 0)) continue;
    out[k] = v;
  }
  return out;
}

const base = { parentRef: null, params: [] as NormalizedRequirement["params"], related: [] as string[], status: "active" as const };

export function normalizeRules(doc: unknown): ParsedDocument {
  const root = obj(doc);
  const info = obj(root.info);
  const version = text(info.version) ?? "unversioned";
  const lastUpdated = text(info.last_updated);
  const requirements: NormalizedRequirement[] = [];
  const notes: RequirementNote[] = [];
  const releaseNotes = new Set<string>();

  const note = (ref: string, updated: unknown): void => {
    const latest = latestNote(updated);
    if (latest) notes.push({ ref, text: latest });
    for (const c of notesOn(updated, lastUpdated)) releaseNotes.add(c);
  };

  // FRR: families, each with subsets, each with rules.
  for (const [famKey, famValue] of Object.entries(obj(root.FRR))) {
    if (famKey === "info") continue;
    const fam = obj(famValue);
    const famInfo = obj(fam.info);
    const short = text(famInfo.short_name) ?? famKey;
    const family = `${short}: ${text(famInfo.name) ?? famKey}`;
    const subsets = obj(famInfo.subsets);
    for (const [subsetKey, subsetRules] of Object.entries(obj(obj(fam.data).all))) {
      const subsetName = text(obj(subsets[subsetKey]).name) ?? subsetKey;
      for (const [id, ruleValue] of Object.entries(obj(subsetRules))) {
        const rule = obj(ruleValue);
        const ref = id.toLowerCase();
        const timeframe = rule.timeframe_num !== undefined && text(rule.timeframe_type) ? `${String(rule.timeframe_num)} ${text(rule.timeframe_type)}` : null;
        requirements.push({
          ...base,
          ref,
          family,
          label: id,
          title: text(rule.name) ?? id,
          statement: lines([text(rule.statement), ...[...strings(rule.following_information), ...strings(rule.following_information_bullets)].map((l) => `- ${l}`)]),
          guidance: lines([text(rule.note), ...strings(rule.notes), ...strings(rule.examples).map((e) => `Example: ${e}`), ...strings(rule.corrective_actions).map((c) => `Corrective action: ${c}`)]),
          related: [...new Set([...strings(rule.controls), ...strings(rule.related)].map((r) => r.toLowerCase()))].sort(),
          sortKey: `1-${short}-${subsetKey}-${id}`.toLowerCase(),
          extra: compact({
            force: text(rule.force),
            subset: subsetName,
            affects: strings(rule.affects),
            terms: strings(rule.terms),
            timeframe,
            notification: text(rule.notification),
            variesByClass: rule.varies_by_class === true ? true : null,
            reference: text(rule.reference_url) ?? text(rule.reference),
          }),
        });
        note(ref, rule.updated);
      }
    }
  }

  // KSI: families of indicators.
  for (const [famKey, famValue] of Object.entries(obj(root.KSI))) {
    if (famKey === "info") continue;
    const fam = obj(famValue);
    const famId = text(fam.id) ?? `KSI-${famKey}`;
    const family = `${famId}: ${text(fam.name) ?? famKey}`;
    for (const [id, indicatorValue] of Object.entries(obj(fam.indicators))) {
      const indicator = obj(indicatorValue);
      const ref = id.toLowerCase();
      requirements.push({
        ...base,
        ref,
        family,
        label: id,
        title: text(indicator.name) ?? id,
        statement: text(indicator.statement),
        guidance: lines([text(indicator.note), ...strings(indicator.notes)]),
        related: [...new Set(strings(indicator.controls).map((r) => r.toLowerCase()))].sort(),
        sortKey: `2-${famKey}-${id}`.toLowerCase(),
        extra: compact({ terms: strings(indicator.terms), status: text(fam.status) }),
      });
      note(ref, indicator.updated);
    }
  }

  // FRD: definitions.
  for (const [id, defValue] of Object.entries(obj(obj(obj(root.FRD).data).all))) {
    const def = obj(defValue);
    const ref = id.toLowerCase();
    requirements.push({
      ...base,
      ref,
      family: "FRD: Definitions",
      label: id,
      title: text(def.term) ?? id,
      statement: text(def.definition),
      guidance: null,
      sortKey: `3-${id}`.toLowerCase(),
      extra: compact({ tag: text(def.tag), alsoKnownAs: strings(def.alts) }),
    });
    note(ref, def.updated);
  }

  // CTL: FedRAMP's parameter values and guidance on NIST controls, by family.
  for (const [famKey, famValue] of Object.entries(obj(root.CTL))) {
    if (famKey === "info") continue;
    for (const [label, entryValue] of Object.entries(obj(famValue))) {
      const entry = obj(entryValue);
      const params = (Array.isArray(entry.parameters) ? entry.parameters : [])
        .map((p) => obj(p))
        .filter((p) => text(p.parameterId))
        .map((p) => ({ id: text(p.parameterId) as string, label: text(p.value) }));
      const ref = `ctl-${label.toLowerCase()}`;
      requirements.push({
        ...base,
        ref,
        family: `CTL-${famKey}: FedRAMP parameters and guidance, ${famKey}`,
        label,
        title: `${label} as FedRAMP applies it`,
        statement: params.length ? params.map((p) => `${p.id}: ${p.label ?? ""}`).join("\n") : null,
        guidance: lines(strings(entry.guidance)),
        params,
        sortKey: `4-${famKey}-${label}`.toLowerCase(),
        extra: {},
      });
      note(ref, entry.updated);
    }
  }

  const rationale = releaseNotes.size
    ? { text: `FedRAMP's change notes dated ${lastUpdated} (version ${version}): ${[...releaseNotes].join(" ")}`, url: `${rulesRepository}/commits/main/${file}` }
    : null;
  return {
    title: text(info.title) ?? "FedRAMP Consolidated Rules",
    versionLabel: version,
    publishedAt: isoDate(lastUpdated),
    requirements,
    rationale,
    notes,
  };
}

export const fedrampRulesAdapter: Adapter = {
  id: "fedramp-rules",
  headers: { accept: "application/json" },
  documents(source: SourceRow): DocumentTarget[] {
    return [{ key: "rules", url: source.url }];
  },
  history(): DocumentTarget[] {
    return history.map((sha) => ({ key: "rules", url: `${raw}/${sha}/${file}`, rationale: null }));
  },
  async parseDocument(bytes): Promise<ParsedDocument> {
    return normalizeRules(JSON.parse(new TextDecoder("utf-8").decode(bytes)));
  },
};
