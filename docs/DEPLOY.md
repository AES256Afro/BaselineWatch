# BaselineWatch on cybercard.net

*Written 2026-10-14 as a plan; rewritten 2026-10-15 after the switch, as a description of what
runs and how to change it.*

cybercard.net is BaselineWatch's public home: a read-only information, learning and teaching
site with no private data. Until 2026-10-15 the domain served the FinancialAuthority demo from
GitHub Pages; it now serves BaselineWatch from BigBox through a Cloudflare Tunnel.

## What is there

| Piece | State since 2026-10-15 |
| --- | --- |
| App | BaselineWatch from `ghcr.io/aes256afro/baselinewatch:<version>` in `/opt/baselinewatch` on BigBox, started with `docker compose`, data in `/opt/baselinewatch/data`, port 8790 on loopback and the LAN. |
| Tunnel | Cloudflare Tunnel named `Baseline Watch`, dashboard-managed, run by BoxPilot's Cloudflare Tunnel app (container `bp-cloudflared`, host network). Routes: `cybercard.net` and `www.cybercard.net` → `http://127.0.0.1:8790`. |
| DNS in Cloudflare | Proxied `CNAME` records for the apex and `www` to the tunnel, created by the tunnel's routes. The old GitHub Pages `A` records and the `www` CNAME are gone. `_dmarc` TXT stays. |
| Zone settings | Always Use HTTPS on. Encryption mode left at Cloudflare's Automatic (reads "Full"); tunnel traffic does not use it, cloudflared speaks plain HTTP to the container on loopback. Redirect rule 1 "Redirect from WWW to root" active (`www` → apex); redirect rule 2 "cybercard.net to rustyschool.com" **disabled, not deleted**: re-enabling it sends the whole site to rustyschool.com. |
| Demo | GitHub Pages for `AES256Afro/financialauthority-demo-cybercard` has no custom domain any more; `FinancialAuthority/scripts/publish-demo.sh` and `docs/DEMO.md` name only demo.aes256afro.com. |
| Categorisation | Requested 2026-10-15 in Security Center → Investigate: Education and Information Security. Cloudflare reviews it. |

## How it was set up

### 1. The code and the image (from the development machine)

```bash
git push -u origin main && git tag v0.10.0 && git push origin v0.10.0
```

CI (`.github/workflows/ci.yml`) runs the checks, boots the container and on a tag pushes
`ghcr.io/aes256afro/baselinewatch:<version>`. The package is public, so BigBox pulls without a
token.

### 2. Running it on BigBox (an SSH session as `bigbox@bigbox`)

```bash
sudo mkdir -p /opt/baselinewatch/data && sudo chown 1000:1000 /opt/baselinewatch/data
```

Docker creates a missing bind-mount directory as root and the image runs as `node` (uid 1000),
so without this the database cannot be opened. Then:

```bash
cd /opt/baselinewatch && sudo curl -fsSLo docker-compose.yml https://raw.githubusercontent.com/AES256Afro/BaselineWatch/main/docker-compose.yml && sudo sed -i 's#build: \.#pull_policy: always#' docker-compose.yml && printf 'BW_BASE_URL=https://cybercard.net\nTZ=America/New_York\n' | sudo tee .env >/dev/null && docker compose up -d
```

```bash
curl -s http://127.0.0.1:8790/health
```

The `bigbox` user is in the `docker` group, so `docker compose` needs no sudo; the files under
`/opt` do. Then the history, in either order relative to the first scheduled fetch (versions are
linked by publication date since 0.10.2):

```bash
docker compose exec baselinewatch node --disable-warning=ExperimentalWarning src/cli.ts backfill nist-sp-800-53
```

```bash
docker compose exec baselinewatch node --disable-warning=ExperimentalWarning src/cli.ts backfill nist-sp-800-53b
```

A chain loaded by an earlier version in the wrong order is put right with
`... src/cli.ts relink all`.

### 3. The tunnel (BoxPilot and the Cloudflare dashboard)

A tunnel made in the dashboard (Networking → Tunnels → Create, token copied into BoxPilot → Apps →
Cloudflare Tunnel → Install) runs as BoxPilot's app. Its public hostnames are routes on the
tunnel in the dashboard ("Add route" → "Published application"): subdomain empty and `www`,
domain `cybercard.net`, service `http://127.0.0.1:8790`. Each route creates its proxied DNS record.

BoxPilot's own Tunnel tab (Connect with an API token, then Publish) was not used for this site:
its Publish takes only an app BoxPilot installed and a single DNS label, never the bare domain
(BoxPilot ADR-011). It would do for a subdomain of another zone once BaselineWatch is installed
from the catalog.

### 4. DNS and the zone (Cloudflare dashboard)

The GitHub Pages `A` records and the `www` CNAME were deleted by hand before the tunnel routes
were added, which is why the routes could create their CNAMEs. Then Always Use HTTPS was turned
on, and the dormant redirect to rustyschool.com, which only fired once the zone became proxied,
was disabled.

### 5. The demo

```bash
gh api -X PUT repos/AES256Afro/financialauthority-demo-cybercard/pages -f cname=
```

and the two FinancialAuthority files edited; the repo holds only built files and still exists.

### 6. Categorisation

Security Center → Investigate → `cybercard.net` → Add category → Education and Information
Security → Submit. The guide is
https://developers.cloudflare.com/security-center/investigate/change-categorization/.

## Upgrading

A release is a tag; CI publishes the image. On BigBox:

```bash
cd /opt/baselinewatch && sudo sed -i 's#baselinewatch:OLD#baselinewatch:NEW#' docker-compose.yml && docker compose up -d && sleep 8 && curl -s http://127.0.0.1:8790/health
```

`pull_policy: always` fetches the new image; the data directory carries over and migrations run
at start. The `sudo` is only for the root-owned compose file: after a one-time
`sudo chown -R bigbox:bigbox /opt/baselinewatch` the whole roll runs as the `bigbox` user, who is
in the `docker` group. A one-off command against the data directory without touching the running
container looks like
`docker run --rm -v /opt/baselinewatch/data:/data ghcr.io/aes256afro/baselinewatch:NEW node --disable-warning=ExperimentalWarning src/cli.ts relink all`.

After a version that adds a standard, load it: `docker compose exec baselinewatch node
--disable-warning=ExperimentalWarning src/cli.ts backfill fedramp-rules` (0.11.0); 800-171
(0.14.0) loads itself on the next daily fetch. Package advisories (0.12.0) start once a package
is on the watchlist. Once the catalog entry
([AES256Afro/BoxPilot#472](https://github.com/AES256Afro/BoxPilot/pull/472)) is merged and
released, BoxPilot can install, back up and update it instead.

## Checks

```bash
curl -sI https://cybercard.net/ | grep -i "^HTTP\|content-security-policy\|strict-transport"
```

The answer is `200` with the app's `Content-Security-Policy` and `Strict-Transport-Security`
headers; `https://cybercard.net/health` reports the running version. A browser that visited the
domain while the rustyschool redirect was active may replay the cached 301 until its cache is
cleared; a private window shows the live answer.

## Access needed, and from where

| Step | Needs | From |
| --- | --- | --- |
| Image | push rights on AES256Afro/BaselineWatch | the development machine (`gh` and git signed in) |
| BigBox | sudo for files under `/opt`; docker without it | an SSH session |
| Tunnel, DNS, zone settings, categorisation | Cloudflare dashboard, signed in | a browser signed in to Cloudflare |
| Demo | `gh` with `repo` scope | the development machine |
