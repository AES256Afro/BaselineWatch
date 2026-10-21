import { describe, expect, it } from "vitest";
import { purlToWatch, readSbom } from "../src/sbom.ts";
import { cookieFrom, formPost, startTestApp } from "./helpers.ts";

/** An SBOM into watchlist entries (N6): purl types to the ecosystem names the advisories use. */

describe("a purl", () => {
  it("becomes the watchlist's ecosystem:name, with the shapes each ecosystem has", () => {
    expect(purlToWatch("pkg:npm/express@4.19.2")).toBe("npm:express");
    expect(purlToWatch("pkg:npm/%40babel/core@7.0.0")).toBe("npm:@babel/core");
    expect(purlToWatch("pkg:pypi/django@5.0")).toBe("PyPI:django");
    expect(purlToWatch("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1")).toBe("Maven:org.apache.logging.log4j:log4j-core");
    expect(purlToWatch("pkg:golang/github.com/gin-gonic/gin@v1.9.0")).toBe("Go:github.com/gin-gonic/gin");
    expect(purlToWatch("pkg:cargo/serde@1.0")).toBe("crates.io:serde");
    expect(purlToWatch("pkg:composer/laravel/framework@10.0")).toBe("Packagist:laravel/framework");
    expect(purlToWatch("pkg:github/actions/checkout@v4")).toBe("GitHub Actions:actions/checkout");
    expect(purlToWatch("pkg:deb/debian/openssl@3.0.11?arch=amd64&distro=debian-12")).toBe("Debian:12:openssl");
    expect(purlToWatch("pkg:deb/debian/openssl@3.0.11")).toBe("Debian:openssl");
    expect(purlToWatch("pkg:deb/ubuntu/curl@8.5.0?distro=ubuntu-24.04")).toBe("Ubuntu:24.04:curl");
    expect(purlToWatch("pkg:apk/alpine/busybox@1.36?distro=alpine-3.20.1")).toBe("Alpine:v3.20:busybox");
    expect(purlToWatch("pkg:rpm/redhat/openssl@3.0.7?distro=rhel-9.2")).toBe("Red Hat:openssl");
  });

  it("is refused when its type is not one an advisory feed covers", () => {
    expect(purlToWatch("pkg:docker/library/nginx@1.25")).toBeNull();
    expect(purlToWatch("pkg:generic/zlib@1.3")).toBeNull();
    expect(purlToWatch("pkg:maven/log4j-core@2.17.1")).toBeNull();
    expect(purlToWatch("not a purl")).toBeNull();
  });
});

describe("a document", () => {
  it("reads CycloneDX components, nested ones too, once each", () => {
    const bom = JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      metadata: { component: { name: "shop-api", version: "2.3.0" } },
      components: [
        { name: "express", purl: "pkg:npm/express@4.19.2", components: [{ name: "qs", purl: "pkg:npm/qs@6.11.0" }] },
        { name: "Express", purl: "pkg:npm/express@4.18.0" },
        { name: "base image", purl: "pkg:docker/library/node@20" },
        { name: "no purl" },
      ],
    });
    const read = readSbom(bom);
    expect(read).toEqual({ name: "shop-api", format: "cyclonedx", packages: [{ value: "npm:express", name: "express" }, { value: "npm:qs", name: "qs" }], skipped: 2 });
  });

  it("reads SPDX packages by their purl reference", () => {
    const spdx = JSON.stringify({
      spdxVersion: "SPDX-2.3",
      name: "billing-service",
      packages: [
        { name: "django", externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: "pkg:pypi/django@5.0.3" }] },
        { name: "openssl", externalRefs: [{ referenceType: "purl", referenceLocator: "pkg:deb/debian/openssl@3.0.11?distro=debian-12" }] },
        { name: "unknown", externalRefs: [{ referenceType: "cpe23Type", referenceLocator: "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*" }] },
      ],
    });
    expect(readSbom(spdx)).toEqual({ name: "billing-service", format: "spdx", packages: [{ value: "PyPI:django", name: "django" }, { value: "Debian:12:openssl", name: "openssl" }], skipped: 1 });
  });

  it("refuses what is neither, saying why", () => {
    expect(() => readSbom("{}")).toThrow(/Not a CycloneDX or SPDX/);
    expect(() => readSbom("<xml/>")).toThrow(/Not a CycloneDX or SPDX/);
  });
});

describe("on the watchlist", () => {
  async function upload(base: string, cookie: string | undefined, text: string, filename = "bom.json"): Promise<Response> {
    const boundary = "----bwsbom";
    const body = `--${boundary}\r\nContent-Disposition: form-data; name="sbom"; filename="${filename}"\r\nContent-Type: application/json\r\n\r\n${text}\r\n--${boundary}--\r\n`;
    const headers: Record<string, string> = { "content-type": `multipart/form-data; boundary=${boundary}`, origin: base, "sec-fetch-site": "same-origin" };
    if (cookie) headers.cookie = cookie;
    return fetch(`${base}/watchlist/sbom`, { method: "POST", headers, body, redirect: "manual" });
  }

  it("imports the packages for the owner, once each, and refuses a reader or a file that is not one", async () => {
    const app = await startTestApp({ env: { BW_ADMIN_PASSWORD: "hunter2hunter2" } });
    try {
      const bom = JSON.stringify({ bomFormat: "CycloneDX", metadata: { component: { name: "shop-api" } }, components: [{ name: "express", purl: "pkg:npm/express@4.19.2" }, { name: "django", purl: "pkg:pypi/django@5.0" }, { name: "nginx", purl: "pkg:docker/library/nginx@1.25" }] });
      expect((await upload(app.base, undefined, bom)).status).toBe(403);
      const cookie = cookieFrom(await formPost(app.base, "/login", { password: "hunter2hunter2", next: "/" }));
      const first = await upload(app.base, cookie, bom);
      expect(first.status).toBe(303);
      expect(first.headers.get("location")).toBe("/watchlist");
      const rows = app.db.prepare("SELECT kind, value, label FROM watchlist WHERE kind = 'package' ORDER BY value").all();
      expect(rows).toEqual([{ kind: "package", value: "PyPI:django", label: "shop-api" }, { kind: "package", value: "npm:express", label: "shop-api" }]);
      const page = await (await fetch(`${app.base}/watchlist`, { headers: { cookie: `${cookie}; ${cookieFrom(first)}` } })).text();
      expect(page).toContain("Imported 2 package(s) from shop-api (0 already listed, 1 component(s) without a package URL");
      // Again: nothing new.
      const again = await upload(app.base, cookie, bom);
      expect(cookieFrom(again)).toContain("Imported%200%20package");
      expect((await upload(app.base, cookie, "{\"hello\": 1}")).status).toBe(400);
      expect(await (await upload(app.base, cookie, "<xml/>")).text()).toMatch(/Not a CycloneDX or SPDX/);
    } finally {
      await app.close();
    }
  });
});
