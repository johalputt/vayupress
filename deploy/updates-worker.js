/**
 * updates-worker.js — the VayuPress official release mirror (Cloudflare Worker).
 *
 * WHY THIS EXISTS. Some hosting providers blackhole traffic to GitHub's API
 * edges (the reported case: `dial tcp 140.82.121.5:443: i/o timeout` from a
 * mail-server IP range). No code on the user's server can fix routing, and
 * VayuPress never asks an operator for a shell. This worker relays GitHub's
 * releases API and release downloads from Cloudflare's edge — a network that
 * is reachable from virtually every host on the internet, including the ones
 * GitHub is unreachable from.
 *
 * SAFETY. This is a relay, never a publisher. Every VayuPress install
 * verifies the Sigstore signature (pinned to the release workflow's identity)
 * and the published SHA-256 over whatever bytes it downloads, so a mirror can
 * serve stale bytes or refuse to serve — it cannot serve a modified binary
 * that will be installed.
 *
 * SETUP (dashboard only — no terminal, no CLI):
 *   1. Sign in at dash.cloudflare.com → Workers & Pages → Create → Worker.
 *   2. Name it `vayupress-updates`, click Deploy, then Edit code.
 *   3. Replace the editor's contents with this file, Deploy.
 *   4. (Optional but recommended) Settings → Variables and Secrets → add
 *      secret `GITHUB_TOKEN` with a GitHub personal-access token (read-only,
 *      no scopes) to raise the API limit from 60 to 5000 requests/hour — the
 *      worker's IP is shared across Cloudflare, so the token keeps the relay
 *      comfortable under load. Edge caching already does most of the work.
 *   5. Workers & Pages → the worker → Settings → Domains & Routes → Add
 *      Custom Domain → e.g. `updates.johal.in`. DNS is created for you.
 *   6. Done. VayuPress installs fall back to this domain automatically; no
 *      per-install configuration exists or is needed.
 *
 * RATE LIMITS. The /api/ routes are edge-cached for 5 minutes (identical
 * requests collapse), /download/ routes for 1 hour (release files are
 * immutable at a tag). A release-critical install therefore costs GitHub
 * almost nothing.
 */

const GITHUB_API = "https://api.github.com";
const GITHUB_WEB = "https://github.com";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Health/self-description, so an operator can confirm the mirror is live
    // from a browser address bar.
    if (url.pathname === "/" || url.pathname === "/health") {
      return json({ ok: true, service: "vayupress-release-mirror" });
    }

    // GET /api/github/<path> → https://api.github.com/<path>
    // Relays the releases API JSON (releases/latest, releases list).
    if (url.pathname.startsWith("/api/github/")) {
      const target = GITHUB_API + url.pathname.slice("/api/github".length) + url.search;
      const headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "vayupress-updates-mirror",
      };
      if (env && env.GITHUB_TOKEN) {
        headers["Authorization"] = "Bearer " + env.GITHUB_TOKEN;
      }
      return relay(target, headers, 300);
    }

    // GET /download/github/<path> → https://github.com/<path>
    // Streams a release file (browser_download_url target), following
    // GitHub's redirect to its object store server-side so the CLIENT box
    // never needs to reach any GitHub host.
    if (url.pathname.startsWith("/download/github/")) {
      const target = GITHUB_WEB + url.pathname.slice("/download/github".length);
      const headers = { "User-Agent": "vayupress-updates-mirror" };
      return relay(target, headers, 3600, true);
    }

    return json({ ok: false, error: "unknown path — see /health" }, 404);
  },
};

async function relay(target, headers, cacheSeconds, stream) {
  // Edge cache: identical lookups collapse onto one origin request per TTL.
  const cache = caches.default;
  const cacheKey = new Request(target, { method: "GET" });
  let hit = await cache.match(cacheKey);
  if (hit) {
    return hit;
  }

  const origin = await fetch(target, { headers, redirect: "follow", cf: { cacheTtl: cacheSeconds } });
  const respHeaders = new Headers();
  for (const h of ["Content-Type", "Content-Length", "Content-Disposition", "Etag"]) {
    const v = origin.headers.get(h);
    if (v) respHeaders.set(h, v);
  }
  respHeaders.set("Cache-Control", "public, max-age=" + cacheSeconds);
  respHeaders.set("X-VayuPress-Mirror", "1");

  let resp;
  if (stream) {
    // Large binaries: stream the body straight through.
    resp = new Response(origin.body, { status: origin.status, headers: respHeaders });
  } else {
    const body = await origin.text();
    resp = new Response(body, { status: origin.status, headers: respHeaders });
  }

  if (origin.ok) {
    ctx.waitUntil(cache.put(cacheKey, resp.clone()));
  }
  return resp;
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { "Content-Type": "application/json" },
  });
}
