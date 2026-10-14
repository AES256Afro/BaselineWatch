# Putting BaselineWatch on cybercard.net

*Written 2026-10-14. Nothing in this runbook has been done yet; each step says who does it.*

cybercard.net becomes BaselineWatch's public home: a read-only information, learning and
teaching site with no private data. Today the domain serves the FinancialAuthority demo from
GitHub Pages. The switch is: get the app running on BigBox, publish it through a Cloudflare
Tunnel, move the DNS, retire the demo, then tell Cloudflare what kind of site it is.

## What is there now

| Piece | State on 2026-10-14 |
| --- | --- |
| Demo files | GitHub Pages from `AES256Afro/financialauthority-demo-cybercard` (public, branch `main`, CNAME `cybercard.net`, HTTPS not enforced). |
| DNS in Cloudflare | DNS-only (grey cloud): four apex `A` records to GitHub Pages (185.199.108.153, .109.153, .110.153, .111.153) and `CNAME www` → `aes256afro.github.io`. |
| Publisher | `FinancialAuthority/scripts/publish-demo.sh` pushes to that repo; `FinancialAuthority/docs/DEMO.md` documents it. |
| BaselineWatch | M0 committed locally; not pushed, no image built, not running anywhere. |

## Order of work

Keep the demo live until BaselineWatch answers on the tunnel, so the domain is never dark.

### 1. Publish the code and the image (from this machine)

```bash
git push -u origin main
```

```bash
git tag v0.1.0 && git push origin v0.1.0
```

CI (`.github/workflows/ci.yml`) runs the checks, boots the container, and on the tag pushes
`ghcr.io/aes256afro/baselinewatch:0.1.0`. The package is private by default on first push: open
https://github.com/users/AES256Afro/packages/container/baselinewatch/settings and set it to
public so BigBox can pull without a token (BoxPilot's catalog expects a public image).

### 2. Run it on BigBox (from your SSH session as `bigbox@bigbox`)

Fastest, before the BoxPilot catalog entry exists:

```bash
sudo mkdir -p /opt/baselinewatch && cd /opt/baselinewatch && sudo curl -fsSLo docker-compose.yml https://raw.githubusercontent.com/AES256Afro/BaselineWatch/main/docker-compose.yml
```

```bash
cd /opt/baselinewatch && sudo sed -i 's#build: \.#pull_policy: always#' docker-compose.yml && printf 'BW_BASE_URL=https://cybercard.net\nTZ=America/New_York\n' | sudo tee .env >/dev/null && sudo docker compose up -d
```

```bash
curl -s http://127.0.0.1:8790/health
```

The compose file binds `8790:8790` on every interface; BigBox's firewall (BoxPilot → Firewall)
should leave 8790 closed to the LAN unless you want it reachable there too. The tunnel reaches it
over loopback.

Through BoxPilot instead (once `boxpilot/baselinewatch.yaml` is merged into
`AES256Afro/BoxPilot/catalog/` and released): Apps → BaselineWatch → Install. BoxPilot then owns
backups and updates for it.

### 3. Publish through a Cloudflare Tunnel (BoxPilot or cloudflared)

BoxPilot way: Apps → Cloudflare Tunnel → Tunnel tab → add a public hostname `cybercard.net` →
`http://localhost:8790` (and `www.cybercard.net` the same). BoxPilot creates the tunnel route
and the proxied DNS record in the zone.

cloudflared way, on BigBox:

```bash
cloudflared tunnel login && cloudflared tunnel create baselinewatch
```

```bash
cloudflared tunnel route dns baselinewatch cybercard.net && cloudflared tunnel route dns baselinewatch www.cybercard.net
```

with `/etc/cloudflared/config.yml` sending both hostnames to `http://localhost:8790`, then
`cloudflared service install`.

Either way the result is a proxied (orange cloud) `CNAME cybercard.net` → `<tunnel-id>.cfargotunnel.com`.
Cloudflare refuses to create it while the apex `A` records exist, which is step 4.

### 4. Move the DNS (Cloudflare dashboard, DNS → Records)

1. Delete the four apex `A` records (the GitHub Pages addresses).
2. Delete `CNAME www` → `aes256afro.github.io`.
3. Let the tunnel create (or create by hand) proxied `CNAME @` and `CNAME www` → the tunnel.
4. SSL/TLS → Overview: **Full (strict)** is fine; the tunnel terminates TLS at Cloudflare and
   speaks plain HTTP to the container on loopback.
5. SSL/TLS → Edge Certificates: **Always Use HTTPS** on.

Check:

```bash
curl -sI https://cybercard.net | head -5
```

The response should carry the app's `Content-Security-Policy` header, which GitHub Pages never
sent.

### 5. Retire the demo (from this machine, `gh` is signed in)

1. Remove the custom domain so GitHub stops serving `cybercard.net`:

   ```bash
   gh api -X PUT repos/AES256Afro/financialauthority-demo-cybercard/pages -f cname=
   ```

   or simply delete the repo's `CNAME` file. Archiving or deleting the repo is your call; it
   holds only built files.
2. In `FinancialAuthority/scripts/publish-demo.sh` remove the
   `AES256Afro/financialauthority-demo-cybercard cybercard.net` line from `sites`, and update
   `docs/DEMO.md` so it names only demo.aes256afro.com.

### 6. Tell Cloudflare what the site is (dashboard, needs a signed-in session)

Cloudflare's content categories are what Gateway, 1.1.1.1 for Families and Radar show for a
domain. The two that fit: **Education** (category 6, subcategory Education 90) and
**Information Security** (subcategory 108). **Information Technology** (109) is a reasonable
third.

Security Center → Investigate → search `cybercard.net` → **Change categorization** → request
Education and Information Security, with a one-line reason ("Public security-education site:
security news, CVE and NIST baseline change tracking; no user data"). Cloudflare reviews the
request; the guide is https://developers.cloudflare.com/security-center/investigate/change-categorization/.

### 7. Done when

- `https://cybercard.net/health` returns `{"ok":true,...}` with the BaselineWatch version.
- `https://cybercard.net/` shows the Register with the strict CSP header.
- GitHub Pages for the demo repo no longer lists `cybercard.net`.
- The categorization request shows as submitted in Security Center.

## Access needed, and from where

| Step | Needs | From |
| --- | --- | --- |
| 1 | push rights on AES256Afro/BaselineWatch | this machine (`gh` and git are signed in) |
| 2, 3 (cloudflared) | sudo on BigBox | your SSH session |
| 3 (BoxPilot), 4, 6 | Cloudflare dashboard, signed in | the browser pane in this app, once you sign in there, or Claude in Chrome |
| 5 | `gh` with `repo` scope | this machine |

The wrangler login on this machine can read the zone and manage Workers, Pages and Tunnels, but
it has no DNS-write scope, so step 4 is dashboard work.
