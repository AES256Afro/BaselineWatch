import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { httpGet, pinnedRequest } from "../src/http.ts";

/**
 * The public-only path connects to the address it vetted (DNS rebinding, closed after the
 * night's security read): the socket goes where the check looked, and the name stays on the
 * wire. A loopback server under a name that resolves nowhere proves the pin.
 */

let server: Server | null = null;
afterEach(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  server = null;
});

async function serve(): Promise<string> {
  server = createServer((req, res) => {
    if (req.url === "/slow") return; // never answers
    if (req.url === "/big") {
      res.writeHead(200, { "content-type": "application/octet-stream" });
      res.end(Buffer.alloc(64 * 1024, 1));
      return;
    }
    res.writeHead(200, { "content-type": "text/plain", "set-cookie": ["a=1", "b=2"] });
    res.end(`${req.method} ${req.headers.host ?? "no host"}`);
  });
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  return String((server.address() as AddressInfo).port);
}

describe("a request to a vetted address", () => {
  it("connects to the address it was given and sends the name, which resolves nowhere", async () => {
    const port = await serve();
    const reply = await pinnedRequest(`http://pinned.invalid:${port}/hello`, "127.0.0.1", { method: "GET", headers: { "user-agent": "t" }, timeoutMs: 2000 });
    expect(reply.status).toBe(200);
    expect(reply.header("Content-Type")).toBe("text/plain");
    expect(reply.headers["set-cookie"]).toBe("a=1, b=2");
    expect(new TextDecoder().decode(await reply.body(1024, "x"))).toBe(`GET pinned.invalid:${port}`);
  });

  it("caps the body and gives up on a server that never answers", async () => {
    const port = await serve();
    const big = await pinnedRequest(`http://pinned.invalid:${port}/big`, "127.0.0.1", { method: "GET", headers: {}, timeoutMs: 2000 });
    await expect(big.body(1024, "big")).rejects.toThrow(/exceeds the 1024 byte limit/);
    await expect(pinnedRequest(`http://pinned.invalid:${port}/slow`, "127.0.0.1", { method: "GET", headers: {}, timeoutMs: 300 })).rejects.toMatchObject({ code: "timeout" });
  });

  it("is the path every public-only fetch takes, behind the same guard", async () => {
    const port = await serve();
    // The guard runs before the pin: a loopback name never reaches the server.
    await expect(httpGet(`http://127.0.0.1:${port}/hello`, { publicOnly: true })).rejects.toThrow(/not a public host/);
    await expect(httpGet(`http://localhost:${port}/hello`, { publicOnly: true })).rejects.toThrow(/not a public host/);
  });
});
