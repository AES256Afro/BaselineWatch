import type { DatabaseSync } from "node:sqlite";
import type { Config } from "./config.ts";
import { parseNotifyUrl } from "./notify.ts";

/**
 * The owner's first-run list, on Today until it is done. It completes itself: each step is read
 * from the instance's own state, never ticked by hand, so it cannot say "done" about something
 * that is not. Without it an empty Today reads as "nothing touches you" when the truth is "this
 * instance has not been told what you run".
 */
export interface SetupStep {
  id: string;
  label: string;
  done: boolean;
  state: string;
  href: string;
  optional?: boolean;
}

// The fleet is not a step yet: data/platforms.yaml ships with releases in it, so its count says
// nothing about whether the owner has told this instance what they run. It joins the list when the
// fleet can be set on the running instance (M20's overlay).
export function setupSteps(db: DatabaseSync, config: Pick<Config, "adminPassword" | "notifyUrl" | "nvdApiKey" | "digest">): SetupStep[] {
  const watched = (db.prepare("SELECT COUNT(*) AS n FROM watchlist").get() as { n: number }).n;
  const notify = parseNotifyUrl(config.notifyUrl) !== null;
  return [
    { id: "password", label: "A password for writes", done: config.adminPassword !== null, state: config.adminPassword ? "set" : "not set: anyone who can reach this instance can change it", href: "/login" },
    { id: "watchlist", label: "A watchlist of products and packages", done: watched > 0, state: watched ? `${watched} ${watched === 1 ? "entry" : "entries"}` : "empty", href: "/watchlist" },
    { id: "digest", label: "Where the digest and alerts go", done: notify || config.digest === "off", state: notify ? "set" : config.digest === "off" ? "turned off" : "not set: alerts are kept here and sent nowhere", href: "/digest" },
    { id: "nvd", label: "An NVD key", done: config.nvdApiKey !== null, state: config.nvdApiKey ? "set" : "not set: keyless works, more slowly", href: "/sources#src-nvd-cves", optional: true },
  ];
}

/** Whether the list still has something to show: any step that is not optional and not done. */
export function setupPending(steps: SetupStep[]): boolean {
  return steps.some((s) => !s.done && !s.optional);
}
