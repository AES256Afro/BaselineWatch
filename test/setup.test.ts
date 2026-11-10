import { describe, expect, it } from "vitest";
import { migrate, openDatabase } from "../src/db.ts";
import { setupPending, setupSteps } from "../src/setup.ts";

describe("the first-run list", () => {
  it("ticks each step from the instance's own state and leaves once the required ones are done", () => {
    const db = openDatabase(":memory:");
    migrate(db);
    const bare = setupSteps(db, { adminPassword: null, notifyUrl: null, nvdApiKey: null, digest: "daily" });
    expect(bare.map((s) => s.done)).toEqual([false, false, false, false]);
    expect(setupPending(bare)).toBe(true);

    db.prepare("INSERT INTO watchlist (kind, value, label, created_at) VALUES ('product', 'openssl', NULL, '2026-11-10T00:00:00Z')").run();
    const done = setupSteps(db, { adminPassword: "x", notifyUrl: null, nvdApiKey: null, digest: "off" });
    expect(done.find((s) => s.id === "watchlist")?.state).toBe("1 entry");
    // The NVD key is optional: its absence alone keeps nothing on Today.
    expect(done.find((s) => s.id === "nvd")?.done).toBe(false);
    expect(setupPending(done)).toBe(false);
  });
});
