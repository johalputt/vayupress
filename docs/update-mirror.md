# The official release mirror — one-time setup, dashboard only

Some hosting providers block or blackhole traffic to GitHub's API edges. A
VayuPress install on such a host saw every "Check for updates" click end in
`dial tcp 140.82.121.5:443: i/o timeout` — DNS answered, the local firewall
allowed outbound, but the route to GitHub was dead and nothing on that box
could change it. VayuPress's rule is that an operator without a shell must
never be stuck, so the console resolves this itself:

1. **The resilient transport** (`internal/safefetch`): every update check dials
   *all* of the host's resolved addresses for GitHub (IPv6 first, RFC 8305
   order) and, if every one fails, re-resolves through DNS-over-HTTPS — often
   reaching a different GitHub edge that does connect.
2. **The endpoint chain** (`internal/update`): GitHub → the official mirror →
   a metadata-only CDN. The panel shows a small "via mirror / via CDN" note so
   the operator can see which path answered.
3. **The mirror** (this document): a Cloudflare Worker that relays GitHub's
   releases API and release files. Because every install verifies the release's
   Sigstore signature and SHA-256 before applying, the mirror can only relay —
   it cannot replace what gets installed.

## What the operator does once (≈5 minutes, no terminal)

1. Sign in at <https://dash.cloudflare.com> → **Workers & Pages** → **Create** →
   **Worker**. Name it `vayupress-updates` and deploy the placeholder.
2. Click **Edit code**, delete the placeholder, paste the contents of
   [`deploy/updates-worker.js`](../deploy/updates-worker.js), and click
   **Deploy**.
3. *(Recommended)* Worker → **Settings → Variables and Secrets** → add a secret
   named `GITHUB_TOKEN` holding a GitHub personal-access token with **no
   scopes**. The worker's egress IP is shared across Cloudflare, so the token
   lifts the API limit from 60 to 5000 requests/hour. Edge caching already
   absorbs most traffic, so this is comfort, not a requirement.
4. Worker → **Settings → Domains & Routes** → **Add Custom Domain** → e.g.
   `updates.johal.in`. Cloudflare creates the DNS record.
5. Visit `https://updates.<your-domain>/health` — it should answer
   `{"ok":true,"service":"vayupress-release-mirror"}`.

Nothing else. Every install already falls back to `https://updates.johal.in`
automatically; there is no per-install setting, and users who installed
v3.17.64 or later get the fallback without doing anything.

## Pointing a self-hosted install at its own mirror

`VAYU_UPDATE_MIRROR` (environment) overrides the official mirror URL; set it
to `off` to disable the mirror layer entirely (GitHub-only, as before).

## Guarantees

- The mirror **relays** the releases API JSON and streams release files; it
  never publishes its own artifacts.
- Bytes are edge-cached (API 5 min, files 1 hour); release files are immutable
  at a tag, so caching cannot serve a wrong version.
- A tampering mirror is useless: `ApplyVerified` refuses any binary whose
  Sigstore signature (pinned to the release workflow identity) or SHA-256 does
  not verify. The failure mode of a hostile mirror is "no update", never "a
  different binary".
- In a Tor Space (onion mode) the whole clearnet update path was already
  disabled and remains so; the mirror layer never activates there.
