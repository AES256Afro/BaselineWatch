import type { HttpGet } from "./http.ts";

/**
 * An optional local model (Ollama's API) that writes a short summary of a release beside the
 * publisher's own words. It only ever sees text already on screen, and what it writes is stored
 * as an explanation of kind `generated`, which the pages badge. Off unless BW_LLM_URL is set.
 */
export interface LlmSettings {
  url: string | null;
  model: string;
}

export interface ReleaseForSummary {
  standard: string;
  version: string;
  previousVersion: string | null;
  rationale: string | null;
  changes: { label: string; title: string; kind: string; field: string | null; before: string | null; after: string | null }[];
}

const clip = (s: string | null, n: number): string => (s ? (s.length > n ? `${s.slice(0, n - 1)}…` : s) : "");

export function releasePrompt(r: ReleaseForSummary): string {
  const lines = r.changes.slice(0, 40).map((c) => {
    const what = c.kind === "added" ? "added" : c.kind === "removed" ? "removed" : `${c.field ?? "changed"}: "${clip(c.before, 300)}" → "${clip(c.after, 300)}"`;
    return `- ${c.label} ${c.title}: ${what}`;
  });
  return [
    `You summarise changes to security standards for a practitioner. Write 2 to 4 plain sentences, no bullet points, no preamble.`,
    `Say what changed in ${r.standard} ${r.version}${r.previousVersion ? ` compared with ${r.previousVersion}` : ""} and what someone who follows this standard should check. Do not invent reasons the publisher did not give.`,
    r.rationale ? `The publisher's own release note:\n${clip(r.rationale, 2000)}` : "The publisher gave no release note.",
    `The changes:\n${lines.join("\n")}${r.changes.length > 40 ? `\n(and ${r.changes.length - 40} more)` : ""}`,
  ].join("\n\n");
}

/** Asks the model once; returns the text or null when the model is off or fails. Never throws. */
export async function summarizeRelease(settings: LlmSettings, http: HttpGet, release: ReleaseForSummary): Promise<string | null> {
  if (!settings.url) return null;
  try {
    const response = await http(`${settings.url.replace(/\/+$/, "")}/api/generate`, {
      body: JSON.stringify({ model: settings.model, prompt: releasePrompt(release), stream: false, options: { temperature: 0.2, num_predict: 400 } }),
      headers: { "content-type": "application/json", accept: "application/json" },
      timeoutMs: 180_000,
    });
    const body = JSON.parse(new TextDecoder("utf-8").decode(response.bytes)) as { response?: string };
    const text = body.response?.trim();
    return text ? text : null;
  } catch {
    return null;
  }
}
