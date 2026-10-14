/**
 * OSCAL (NIST's Open Security Controls Assessment Language) catalogs and profiles, as NIST
 * publishes SP 800-53, 800-53A and 800-53B. A catalog is groups of controls, each with nested
 * enhancements; a profile (baseline) lists the control ids it includes.
 */

export interface OscalParam {
  id: string;
  label?: string;
  props?: { name: string; value: string; class?: string }[];
  select?: { "how-many"?: string; choice?: string[] };
  guidelines?: { prose: string }[];
  values?: string[];
}

export interface OscalPart {
  id?: string;
  name: string;
  prose?: string;
  props?: { name: string; value: string; class?: string }[];
  parts?: OscalPart[];
}

export interface OscalControl {
  id: string;
  class?: string;
  title: string;
  params?: OscalParam[];
  props?: { name: string; value: string; class?: string; ns?: string }[];
  links?: { href: string; rel?: string }[];
  parts?: OscalPart[];
  controls?: OscalControl[];
}

export interface OscalGroup {
  id: string;
  class?: string;
  title: string;
  controls?: OscalControl[];
  groups?: OscalGroup[];
}

export interface OscalCatalog {
  catalog: {
    uuid?: string;
    metadata: { title: string; version: string; "last-modified"?: string; "oscal-version"?: string };
    groups?: OscalGroup[];
    controls?: OscalControl[];
  };
}

export interface OscalProfile {
  profile: {
    uuid?: string;
    metadata: { title: string; version: string; "last-modified"?: string };
    imports: { href?: string; "include-controls"?: { "with-ids"?: string[] }[] }[];
  };
}

/** One control, enhancement, requirement or rule in the shape the Register stores and diffs. */
export interface NormalizedRequirement {
  ref: string;
  parentRef: string | null;
  family: string | null;
  /** The label people use: SI-07(12). */
  label: string;
  title: string;
  statement: string | null;
  guidance: string | null;
  /** [{id, label, choices?}] */
  params: { id: string; label: string | null; choices?: string[] }[];
  related: string[];
  /** Sort key such as si-07.12. */
  sortKey: string;
  status: "active" | "withdrawn";
  extra: Record<string, unknown>;
}

export interface NormalizedDocument {
  title: string;
  version: string;
  lastModified: string | null;
  requirements: NormalizedRequirement[];
}

function prop(props: { name: string; value: string; class?: string }[] | undefined, name: string, klass?: string): string | null {
  const found = props?.find((p) => p.name === name && (klass === undefined || p.class === klass)) ?? props?.find((p) => p.name === name);
  return found?.value ?? null;
}

function paramText(param: OscalParam | undefined, id: string): string {
  if (!param) return `[Assignment: ${id}]`;
  if (param.select?.choice?.length) {
    const many = param.select["how-many"] === "one-or-more" ? "Selection (one or more)" : "Selection";
    return `[${many}: ${param.select.choice.join("; ")}]`;
  }
  if (param.values?.length) return `[${param.values.join(", ")}]`;
  return `[Assignment: ${param.label ?? id}]`;
}

/** Replaces `{{ insert: param, id }}` with the parameter's label or choices, the way the PDF reads. */
export function resolveParams(prose: string, params: Map<string, OscalParam>): string {
  return prose.replace(/\{\{\s*insert:\s*param,\s*([^\s}]+)\s*\}\}/g, (_m, id: string) => paramText(params.get(id), id));
}

function partText(part: OscalPart, params: Map<string, OscalParam>, depth = 0): string {
  const label = prop(part.props, "label");
  const own = part.prose ? resolveParams(part.prose.trim(), params) : "";
  const lines: string[] = [];
  if (own) lines.push(`${label ? `${label} ` : ""}${own}`.trim());
  for (const child of part.parts ?? []) {
    if (child.name === "item" || child.name === "statement") {
      const text = partText(child, params, depth + 1);
      if (text) lines.push(text);
    }
  }
  return lines.join("\n");
}

function findPart(control: OscalControl, name: string): OscalPart | undefined {
  return control.parts?.find((p) => p.name === name);
}

function normalizeControl(control: OscalControl, parent: OscalControl | null, family: string | null, params: Map<string, OscalParam>): NormalizedRequirement {
  for (const p of control.params ?? []) params.set(p.id, p);
  const statement = findPart(control, "statement");
  const guidance = findPart(control, "guidance");
  const objective = findPart(control, "assessment-objective");
  const status = prop(control.props, "status") === "withdrawn" ? "withdrawn" : "active";
  const related = (control.links ?? []).filter((l) => l.rel === "related" && l.href.startsWith("#")).map((l) => l.href.slice(1));
  const incorporatedInto = (control.links ?? []).filter((l) => l.rel === "incorporated-into").map((l) => l.href.replace(/^#/, ""));
  return {
    ref: control.id,
    parentRef: parent?.id ?? null,
    family,
    label: prop(control.props, "label", "zero-padded") ?? prop(control.props, "label") ?? control.id.toUpperCase(),
    title: control.title.trim(),
    statement: statement ? partText(statement, params) || null : null,
    guidance: guidance?.prose ? resolveParams(guidance.prose.trim(), params) : null,
    params: (control.params ?? []).map((p) => ({ id: p.id, label: p.label ?? null, ...(p.select?.choice ? { choices: p.select.choice } : {}) })),
    related,
    sortKey: prop(control.props, "sort-id") ?? control.id,
    status,
    extra: {
      ...(objective ? { assessmentObjective: partText(objective, params) } : {}),
      ...(incorporatedInto.length ? { incorporatedInto } : {}),
      ...(prop(control.props, "implementation-level") ? { implementationLevel: (control.props ?? []).filter((p) => p.name === "implementation-level").map((p) => p.value) } : {}),
    },
  };
}

function walkGroups(groups: OscalGroup[], out: NormalizedRequirement[], params: Map<string, OscalParam>, family: string | null = null): void {
  for (const group of groups) {
    const groupFamily = group.id ? group.id.toUpperCase() : family;
    for (const control of group.controls ?? []) {
      out.push(normalizeControl(control, null, groupFamily, params));
      for (const enhancement of control.controls ?? []) out.push(normalizeControl(enhancement, control, groupFamily, params));
    }
    if (group.groups) walkGroups(group.groups, out, params, groupFamily);
  }
}

export function normalizeCatalog(doc: OscalCatalog): NormalizedDocument {
  const catalog = doc.catalog;
  if (!catalog?.metadata || !catalog.metadata.version) throw new Error("not an OSCAL catalog");
  const params = new Map<string, OscalParam>();
  const requirements: NormalizedRequirement[] = [];
  walkGroups(catalog.groups ?? [], requirements, params);
  for (const control of catalog.controls ?? []) {
    requirements.push(normalizeControl(control, null, null, params));
    for (const enhancement of control.controls ?? []) requirements.push(normalizeControl(enhancement, control, null, params));
  }
  return {
    title: catalog.metadata.title,
    version: catalog.metadata.version,
    lastModified: catalog.metadata["last-modified"] ?? null,
    requirements,
  };
}

/** A baseline profile becomes one requirement per included control, so membership diffs as added/removed refs. */
export function normalizeProfile(doc: OscalProfile, titles: Map<string, string> = new Map()): NormalizedDocument {
  const profile = doc.profile;
  if (!profile?.metadata || !Array.isArray(profile.imports)) throw new Error("not an OSCAL profile");
  const ids = new Set<string>();
  for (const imp of profile.imports) for (const include of imp["include-controls"] ?? []) for (const id of include["with-ids"] ?? []) ids.add(id);
  const requirements: NormalizedRequirement[] = [...ids].map((id) => ({
    ref: id,
    parentRef: id.includes(".") ? id.split(".")[0]! : null,
    family: id.split("-")[0]?.toUpperCase() ?? null,
    label: id.toUpperCase().replace(/^([A-Z]+)-(\d+)(?:\.(\d+))?$/, (_m, f: string, n: string, e?: string) => `${f}-${n.padStart(2, "0")}${e ? `(${e.padStart(2, "0")})` : ""}`),
    title: titles.get(id) ?? id.toUpperCase(),
    statement: null,
    guidance: null,
    params: [],
    related: [],
    sortKey: id,
    status: "active",
    extra: {},
  }));
  return {
    title: profile.metadata.title,
    version: profile.metadata.version,
    lastModified: profile.metadata["last-modified"] ?? null,
    requirements,
  };
}
