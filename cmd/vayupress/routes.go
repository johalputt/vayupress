// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/cors"

	"github.com/johalputt/vayupress/internal/auth"
	"github.com/johalputt/vayupress/internal/config"
	"github.com/johalputt/vayupress/internal/health"
	"github.com/johalputt/vayupress/internal/vayushield/gossip"
)

// coreMiddleware is the base stack every request passes through, in order.
//
// RECOVERER RUNS SECOND, and the order is the point rather than a detail. A panic
// in a middleware registered BEFORE it is not recovered by it: the panic reaches
// net/http, which closes the connection without a response, and the reverse proxy
// in front turns that into a **502 Bad Gateway** for the visitor — no stack in
// the app log tied to a status, just a dead connection.
//
// Recoverer used to sit fourth, leaving realIPMiddleware and
// structuredLoggerMiddleware outside it. Both run on every single request, and
// realIPMiddleware has been growing: it resolves the client address, records
// proxy sightings, and now samples whether resolution reached the reader. That is
// exactly the code most likely to meet a request shape nobody anticipated, and it
// was the code least protected when it did.
//
// requestIDMiddleware stays first so a recovered panic is still logged against a
// request ID. It does nothing but read a header and generate random bytes.
func coreMiddleware() []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{
		requestIDMiddleware,
		chimw.Recoverer,
		// Proxy-aware client-IP resolution (audit F-3). Replaces chi's
		// middleware.RealIP, which trusts forwarding headers unconditionally and
		// is vulnerable to IP spoofing; realIPMiddleware honours them only from
		// configured trusted proxies (TRUSTED_PROXIES, default loopback).
		realIPMiddleware,
		structuredLoggerMiddleware,
		chimw.Timeout(30 * time.Second),
		securityHeadersMiddleware,
		// Origin compression for bare single-binary installs (Wave 3). Sits
		// inside the core chain so every downstream response — public pages,
		// /os console assets, feeds, API JSON — can be gzipped; SSE, Range and
		// already-encoded responses pass through untouched (see the file's
		// header for the full exclusion list).
		gzipMiddleware,
	}
}

// registerRoutes wires all HTTP routes onto r. Route registration is kept in
// one place so main() stays focused on lifecycle orchestration (ADR-0048).
func (a *App) registerRoutes(r chi.Router, staticDir string) {
	r.Use(coreMiddleware()...)
	// Maintenance mode — when the operator has taken the public site offline
	// (VayuOS → Power & Maintenance), serve the premium maintenance page to
	// visitors. A near-free pass-through when off; always lets /os, the health
	// probes and the signed-in operator through so the site can be recovered.
	r.Use(a.maintenanceMiddleware)
	// Search-engine / AI crawler block — when the operator has taken the public
	// site dark to indexers (VayuOS → Power & Maintenance), 403 known crawler
	// user-agents and mark every other public response noindex. A near-free
	// pass-through when off; never touches /os, health or well-known/MCP/OAuth.
	r.Use(a.crawlerBlockMiddleware)
	// VayuTor onion routing — maps an incoming <onion>.onion Host to the clearnet
	// domain it serves (so per-domain routing works over Tor), and advertises the
	// onion on clearnet responses via Onion-Location. Runs BEFORE the domain
	// resolver so the rewritten Host resolves normally. No-op unless VayuTor is
	// available; never affects clearnet routing.
	if a.vayuTor != nil {
		r.Use(a.torOnionMiddleware)
	}
	// VayuDomains host resolution — annotates each request with the registered
	// domain that owns its Host header (Stage 1). A pure pass-through: it only
	// adds context, so the primary domain is served byte-identically.
	if a.domains != nil {
		r.Use(a.domainMiddleware)
		// Must follow domainMiddleware: the strict baseline is set before the
		// domain is known, so the one hosted site that opted out of the no-eval
		// rule can only be honoured once activeDomain exists.
		r.Use(a.siteCSPMiddleware)
	}
	// Redirect middleware — runs after core middleware, serves 301/302 before routing.
	if a.redirectMgr != nil {
		r.Use(a.redirectMgr.Middleware)
	}
	// Aegis L0 — Admin Sovereignty Lane. Mounted BEFORE VayuShield (and thus
	// before classification, rendering and SQLite) so that under a volumetric
	// flood it caps PUBLIC concurrency and sheds the overflow with a couple of
	// atomic ops, guaranteeing the admin control plane (VayuOS, Save, refresh)
	// and verified readers always keep CPU/goroutine headroom. Near-zero cost
	// when traffic is nowhere near the cap.
	if a.sovereign != nil {
		r.Use(a.sovereignMiddleware)
	}
	// VayuShield bot protection — classifies every request and issues the
	// escalating challenge ladder. A transparent pass-through when protection is
	// disabled (VAYUSHIELD=off, the default) and for all bypassed prefixes
	// (/os, /api, feeds, health). Registered before routing so it can short
	// -circuit a blocked/challenged request before any handler runs.
	if a.vayuShield != nil {
		r.Use(a.vayuShield.Middleware)
	}
	r.Use(cors.New(cors.Options{
		AllowedOrigins:   []string{"https://" + config.Cfg.Domain},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "X-API-Key", "Authorization", "X-Request-ID", "X-CSRF-Token"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
	}).Handler)

	// Public health endpoints. Liveness/readiness stay anonymous (load
	// balancers, and the connector docs promise curl-able JSON); the DETAIL
	// probes — DB internals, worker queues, storage, migrations, dependency
	// graph — are recon (audit) and answer loopback/API-key callers only.
	gateHealth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !isLoopbackPeer(r) && !auth.HasValidAPIKey(r) {
				http.NotFound(w, r)
				return
			}
			h(w, r)
		}
	}
	r.Get("/health", health.HandleHealthLiveness)
	r.Get("/health/live", health.HandleHealthLiveness)
	r.Get("/health/ready", health.HandleHealthReady)
	r.Get("/health/db", gateHealth(health.HandleHealthDB))
	r.Get("/health/search", gateHealth(health.HandleHealthSearch))
	// Kept as an alias, not revived: it points at the same built-in engine. An
	// operator's monitoring may still call it, and silently 404ing a health check
	// is a worse failure than an inaccurate path.
	r.Get("/health/meilisearch", gateHealth(health.HandleHealthSearchLegacy))
	r.Get("/health/workers", gateHealth(health.HandleHealthWorkers))
	r.Get("/health/storage", gateHealth(health.HandleHealthStorage))
	r.Get("/health/benchmarks", gateHealth(a.handleHealthBenchmarks))
	r.Get("/health/migrations", gateHealth(health.HandleHealthMigrations))
	r.Get("/health/ethics", gateHealth(health.HandleHealthEthics))
	r.Get("/health/dependencies", gateHealth(health.HandleHealthDependencies))
	r.Get("/health/queue", gateHealth(health.HandleHealthQueue))

	// Static files + feeds. Per-domain scoped when a secondary domain is
	// registered (VayuDomains Stage 2c); byte-identical global artefacts
	// otherwise.
	r.Get("/sitemap.xml", a.handleSitemap)
	// Children of the sitemap index: /sitemap-1.xml … /sitemap-N.xml, /sitemap-tags.xml
	r.Get("/sitemap-{part}.xml", a.handleSitemapChild)
	r.Get("/feed.xml", a.handleFeed)
	r.Get("/robots.txt", a.handleRobots)
	r.Get("/llms.txt", a.handleLLMsTxt)
	// Public documentation site: guides, operations runbooks, the security model
	// and every ADR, rendered from markdown embedded in the binary for public
	// audit. Hosted at a path (no docs subdomain). /doc redirects to /docs.
	r.Get("/docs", a.handleDocs)
	r.Get("/docs/*", a.handleDocs)
	r.Get("/doc", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs", http.StatusMovedPermanently)
	})
	r.Get("/doc/*", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs/"+chi.URLParam(r, "*"), http.StatusMovedPermanently)
	})
	// Dynamic per-site theme stylesheet (operator palette + custom CSS).
	// Served same-origin so it satisfies the strict style-src 'self' CSP.
	r.Get("/theme.css", a.handleThemeCSS)
	// Public theme toggle script (same-origin → script-src 'self', no nonce).
	r.Get("/static/js/theme-toggle.js", a.handleThemeToggleJS)
	// Self-hosted HTMX (embedded in the binary via StaticFS, written to
	// STATIC_DIR on boot). Same-origin → satisfies script-src 'self' with no
	// nonce and no external host; powers hx-* progressive enhancement in VayuOS.
	r.Get("/static/js/htmx.min.js", a.handleHTMXJS)
	r.Get("/static/js/video-facade.js", a.handleVideoFacadeJS)
	r.Get("/static/js/comments.js", a.handleCommentsJS)
	r.Get("/static/js/contact.js", a.handleContactJS)
	r.Get("/static/js/post-card-media.js", a.handlePostCardMediaJS)
	// Trending & pinned posts widget (hydrates [data-vayu-trending] from
	// /api/trending). Same-origin → script-src 'self', no nonce.
	r.Get("/static/js/trending.js", a.handleTrendingWidgetJS)
	// VayuFind instant-search modal (hydrates from /api/search-index.json).
	// Same-origin → script-src 'self', no nonce.
	r.Get("/static/js/search.js", a.handleSearchWidgetJS)
	// VayuPortal — the reader membership overlay widget (same-origin → script-src 'self').
	r.Get("/static/js/portal.js", a.handleMemberPortalJS)
	// Service-worker registration. Without this the worker below is never
	// registered, the site fails Chrome's installability check, and "Install"
	// degrades to a launcher shortcut that a device restart can discard.
	r.Get("/static/js/pwa.js", a.handlePWARegisterJS)
	// Public web-app icons (a real 192, a real 512, and a padded maskable 512).
	// These serve the OPERATOR's uploaded logo, rendered to the exact size the
	// manifest promises, falling back to the embedded mark when none is set: the
	// installed app is the operator's site, so it must wear the site's identity,
	// not the software's. (The VayuOS console app is the opposite case and keeps
	// its own mark — see handlers_pwa_os.go.)
	r.Get("/static/icons/webapp-192.png", a.serveAppIcon(192, false, webAppIcon192PNG))
	r.Get("/static/icons/webapp-512.png", a.serveAppIcon(512, false, webAppIcon512PNG))
	r.Get("/static/icons/webapp-maskable-512.png", a.serveAppIcon(512, true, webAppIconMaskablePNG))
	r.Get("/static/icons/webapp-apple-180.png", a.serveAppIcon(180, false, webAppIconApplePNG))
	// Favicon routes serve the operator's uploaded brand mark when one is stored
	// (see /admin/theme branding), falling back to the embedded default per scheme.
	r.Get("/static/favicon-dark.png", a.serveFavicon(faviconDarkPNG))
	r.Get("/static/favicon-light.png", a.serveFavicon(faviconLightPNG))
	// Self-hosted web fonts (OFL Space Grotesk) for the Vayu theme — same-origin
	// (CSP font-src 'self'), embedded in the binary, allowlisted filenames only.
	r.Get("/static/fonts/{file}", a.handleStaticFont)
	// First-party web-building assets for hand-built site bundles: same-origin, so
	// the strict CSP admits them without widening a single directive.
	r.Get("/static/vayuweb/{file}", a.handleVayuWebAsset)
	r.Get("/favicon.ico", a.serveFavicon(faviconDarkPNG))
	// Operator-uploaded hero/cover image (same-origin → img-src 'self'); 404s
	// gracefully when none is set so the "Hero background: Image" option degrades.
	r.Get("/theme-assets/hero", a.serveHeroImage)
	// Operator-uploaded social/share image (og:image). 404s gracefully when unset.
	r.Get("/theme-assets/og", a.serveOGImage)
	// cssAllowlist maps the URL parameter to its canonical on-disk name.
	// The path passed to http.ServeFile comes from the *value* (a string literal),
	// not from the user-supplied key, so there is no path-traversal vector.
	cssAllowlist := map[string]string{
		"article.css":       "article.css",
		"admin.css":         "admin.css",
		"high-contrast.css": "high-contrast.css",
		"pico.min.css":      "pico.min.css",
		"custom.css":        "custom.css",
		"signup.css":        "signup.css",
		"portal.css":        "portal.css",
		"docs.css":          "docs.css",
	}
	r.Get("/static/css/{file}", func(w http.ResponseWriter, r *http.Request) {
		canon, ok := cssAllowlist[chi.URLParam(r, "file")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, immutable, max-age=31536000")
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		http.ServeFile(w, r, filepath.Join(staticDir, "css", canon))
	})

	// Chroma syntax-highlighting stylesheet (generated from github-dark theme).
	r.Get("/static/chroma.css", a.handleChromaCSS)
	// PWA manifest and service worker.
	r.Get("/manifest.json", a.handlePWAManifest)
	r.Get("/sw.js", a.handleServiceWorker)

	// Public: same-origin media (editor image uploads). Name is strictly
	// validated in the handler — no path-traversal surface.
	r.Get("/media/{file}", a.serveMedia)

	// Public API
	r.Get("/api/v1/graphql", a.handleGraphQL)          // read-only GraphQL (GET)
	r.Post("/api/v1/graphql", a.handleGraphQL)         // read-only GraphQL (POST)
	r.Get("/api/v1/i18n/{lang}", a.handleI18nMessages) // i18n message bundle
	r.Get("/api/v1/articles", a.handleListArticles)
	r.Get("/api/v1/articles/{slug}", a.handleGetArticle)
	r.Get("/api/v1/articles/{slug}/comments", a.handleCommentList)
	r.Get("/api/v1/articles/{slug}/toc", a.handleArticleTOC)
	r.Post("/api/v1/articles/{slug}/comments", a.handleCommentSubmit)
	r.Patch("/api/v1/articles/{slug}/comments/{id}", a.handleCommentEdit)    // edit your own comment
	r.Delete("/api/v1/articles/{slug}/comments/{id}", a.handleCommentDelete) // delete own (member) / any (operator)
	r.Post("/api/v1/contact", a.handleContactSubmit)
	r.Get("/api/v1/search", a.handleSearch)
	r.Get("/api/v1/tags", a.handleListTags)
	r.Get("/api/v1/stats", a.handleStats)
	r.Get("/api/v1/collections", a.handleCollectionList)
	r.Get("/api/v1/collections/{id}", a.handleCollectionGet)
	r.Get("/api/v1/preview/verify", a.handlePreviewVerify)
	r.Get("/metrics", a.handleMetrics)
	r.Post("/csp-report", a.handleCSPReport)
	r.Get("/smoke-test", a.handleSmokeTest)
	// Webmention receiver (W3C standard, public endpoint)
	r.Post("/webmention", a.handleWebmentionReceive)
	// Newsletter (public subscribe/confirm/unsubscribe flows)
	r.Post("/api/v1/newsletter/subscribe", a.handleNewsletterSubscribe)
	r.Get("/api/v1/newsletter/confirm", a.handleNewsletterConfirm)
	r.Get("/api/v1/newsletter/unsubscribe", a.handleNewsletterUnsubscribe)
	r.Get("/api/v1/openapi.json", a.handleOpenAPISpec)

	// VayuAnalytics — public ingest + tracking script (no auth; body-capped and per-IP rate-limited).
	r.Post("/api/v1/analytics/collect", a.handleAnalyticsCollect)
	r.Get("/static/vp-analytics.js", a.handleAnalyticsScript)

	// VayuShield challenge surface + VayuAnalytics Enterprise engagement beacons
	// (all public, body-capped, per-IP rate-limited, cookieless/no-PII). The PoW
	// solver script and the engagement beacon are served same-origin to satisfy
	// script-src 'self'. The privacy report documents the GDPR posture.
	r.Get("/__vayushield/challenge.js", a.handleVayuShieldJS)
	r.Post("/__vayushield/pow", a.handleVayuShieldPoW)
	// Multi-node verdict sharing. Mounted only when peers are configured: an
	// install with no fleet should not expose the route at all, rather than
	// exposing one that always refuses and invites probing.
	if h := a.vayuShield.GossipHandler(); h != nil {
		r.Post(gossip.Path, h.ServeHTTP)
	}
	r.Post("/__vayuanalytics/enter", a.handleVAEnter)
	r.Post("/__vayuanalytics/event", a.handleVAEvent)
	r.Get("/static/js/vp-engagement.js", a.handleVAEngagementJS)
	r.Get("/.well-known/privacy-report.json", a.handlePrivacyReport)

	// VayuMCP OAuth 2.1 authorization server (ADR-0140) — the one-click Connect
	// flow on claude.ai. Discovery metadata (RFC 8414 + RFC 9728), dynamic client
	// registration (RFC 7591), the consent screen, and the token exchange. The
	// consent GET is a session-authenticated admin page; its POST and the token/
	// register endpoints are public (the token endpoint authenticates the caller by
	// the authorization code + PKCE verifier it presents, not a session).
	r.With(auth.PublicDiscoveryRateLimit).Get("/.well-known/oauth-authorization-server", a.handleOAuthASMetadata)
	r.With(auth.PublicDiscoveryRateLimit).Get("/.well-known/oauth-protected-resource", a.handleOAuthResourceMetadata)
	r.With(auth.PublicDiscoveryRateLimit).Post("/oauth/register", a.handleOAuthRegister)
	r.Get("/oauth/authorize", a.handleOAuthAuthorize)
	r.Post("/oauth/authorize/consent", a.handleOAuthConsent)
	r.With(auth.PublicDiscoveryRateLimit).Post("/oauth/token", a.handleOAuthToken)

	// Libravatar/Gravatar-compatible federated avatar: so a recipient's mail
	// client/service can fetch a sender's profile picture. Rate-limited because
	// the handler scans the account list per request (same posture as WKD).
	r.With(auth.PublicDiscoveryRateLimit).Get("/avatar/{hash}", a.handleFederatedAvatar)

	// VayuPGP Web Key Directory — public key discovery (RFC WKD advanced method).
	// Rate-limited: the handler scans the whole keystore per request, so an
	// unbounded query rate is a DoS amplifier (generous per-IP cap, legit
	// discovery unaffected).
	r.With(auth.PublicDiscoveryRateLimit).Get("/.well-known/openpgpkey/*", a.handleWKD)

	// Mozilla Autoconfig — Thunderbird and K-9 / Thunderbird-for-Android fetch
	// this to set up a mailbox from just the email address (no manual server
	// entry). Public; contains only hostnames/ports, never a secret.
	r.With(auth.PublicDiscoveryRateLimit).Get("/.well-known/autoconfig/mail/config-v1.1.xml", a.handleMailAutoconfig)
	// First-party VayuMail autoconfig (JSON). The VayuMail app fetches this to
	// onboard by email address alone. Public; same public server coordinates as
	// the Mozilla XML above, never a secret. Two path segments under
	// /.well-known/, so it does not collide with the /{file} catch-all below.
	r.With(auth.PublicDiscoveryRateLimit).Get("/.well-known/vayumail/autoconfig.json", a.handleVayuMailAutoconfigJSON)

	// IndexNow key verification file. Search engines fetch
	// /.well-known/<key>.txt and expect the body to equal <key>. We serve it
	// dynamically from the active IndexNow key (managed in the VayuOS API Keys
	// console, with env fallback) so enabling IndexNow needs no manual file
	// upload — the verification file simply exists once a key is configured.
	r.Get("/.well-known/{file}", a.handleIndexNowKeyFile)

	// VayuMail account recovery (ADR-0144) — public and unauthenticated, because
	// the people who need it are by definition locked out.
	//
	// These are deliberately NOT in shieldBypassPrefixes. That list exists for
	// callers that CANNOT solve a challenge (the WebAPK minting server, MCP
	// clients); recovery is always driven by a human in a real browser, so a
	// challenge is an inconvenience rather than an outage — and bot protection in
	// front of a credential-reset endpoint is exactly where it belongs.
	r.Get("/mail/recover", a.handleMailRecoverRequest)
	r.Post("/mail/recover", a.handleMailRecoverRequest)
	r.Get("/mail/recover/reset", a.handleMailRecoverReset)
	r.Post("/mail/recover/reset", a.handleMailRecoverReset)
	r.Get("/mail/recover/code", a.handleMailRecoverCode)
	r.Post("/mail/recover/code", a.handleMailRecoverCode)
	r.Get("/mail/recover/ask", a.handleMailRecoverAsk)
	r.Post("/mail/recover/ask", a.handleMailRecoverAsk)

	// Reader memberships (Tier 2) — public passwordless login + paywall.
	r.Get("/signup", a.handleMemberSignup)
	r.Post("/api/v1/members/login", a.handleMemberLogin)
	r.Post("/members/login", a.handleMemberLogin) // HTML form variant from the paywall
	r.Get("/members/verify", a.handleMemberVerify)
	r.Post("/members/logout", a.handleMemberLogout)
	// Premium membership: sign-in page, member portal/account, and the public
	// pricing page + tier catalogue.
	r.Get("/members", a.handleMemberSigninPage)
	r.Get("/members/account", a.handleMemberAccount)
	r.Post("/members/account", a.handleMemberAccountUpdate)
	// VayuPortal overlay backend — capability snapshot + VayuMail credential login.
	r.Get("/api/v1/members/me", a.handleMemberMe)
	r.Get("/api/v1/members/comments", a.handleMemberComments)
	// Member avatars: public serve (by opaque id, for comments), plus the
	// member-authed upload / choose. The member cookie is SameSite=Lax, so a
	// cross-site POST never carries it (CSRF-safe), matching the account endpoints.
	r.Get("/api/v1/members/avatar/{id}", a.handleMemberAvatarServe)
	r.Post("/api/v1/members/avatar", a.handleMemberAvatarUpload)
	r.Post("/api/v1/members/avatar/choose", a.handleMemberAvatarChoose)
	// Paid-member mailbox: entitlement/status, availability check, and claim
	// (provisions a real VayuMail mailbox with PGP + quota; reserved names refused).
	r.Get("/api/v1/members/mailbox", a.handleMemberMailboxStatus)
	r.Get("/api/v1/members/mailbox/available", a.handleMemberMailboxAvailable)
	r.Post("/api/v1/members/mailbox/claim", a.handleMemberMailboxClaim)
	r.Post("/api/v1/members/mailbox/premium/checkout", a.handleMemberMailIDCheckout)
	r.Post("/api/v1/members/mailbox/premium/activate", a.handleMemberMailIDActivate)
	r.Get("/api/v1/members/ads", a.handleMemberAdsStatus)
	r.Post("/api/v1/members/ads", a.handleMemberAdSubmit)
	// PublicDiscoveryRateLimit is the outermost of three controls on this route
	// (the handler adds a per-IP lockout and a per-mailbox throttle). It was
	// registered bare, outside every limiter group, and /api is in
	// shieldBypassPrefixes -- so nothing at all metered unauthenticated password
	// guessing against every mailbox on the install.
	r.With(auth.PublicDiscoveryRateLimit).Post("/api/v1/members/vayumail-login", a.handleMemberVayuMailLogin)
	// Member self-serve 2FA on their OWN VayuMail mailbox (member-session, SameSite
	// Lax + same-origin JSON — same protection model as the sibling member POSTs).
	// begin returns {secret,uri,qr}; the QR + otpauth label auto-fill the account
	// name when scanned into an authenticator app.
	r.Post("/api/v1/members/totp/begin", a.handleMemberTOTPBegin)
	r.Post("/api/v1/members/totp/verify", a.handleMemberTOTPVerify)
	r.Post("/api/v1/members/totp/disable", a.handleMemberTOTPDisable)
	// VayuMail-Mobile private-key sync — returns the authenticated caller's OWN
	// mailbox PGP private key (armored) so the app can import it and decrypt
	// received mail on-device (WKD only serves public keys). Same credential
	// check and anti-enumeration timing as vayumail-login above; the response is
	// audit-logged and no-store. See ADR-0128.
	//
	// NOT the same brute-force posture, and the comment used to claim it was: this
	// route carries no per-source lockout. It does not need one — it authenticates
	// in MAIL-SYNC scope, where verifyCredentialScoped refuses the raw mailbox
	// password outright for any mailbox requiring device approval (on by default),
	// so what reaches the KDF here is a ~119-bit server-generated device secret.
	// Stating that rather than asserting parity, because the parity claim is what
	// hid the device-register gap through a whole audit section.
	r.Post("/api/v1/members/vayumail-privkey", a.handleMemberVayuMailPrivKey)
	// VayuMail-Mobile device approval (ADR-0129): a new device registers with
	// the mailbox password and receives a pending device credential; it polls
	// its approval status until the operator approves it in the web console.
	// device-register is the ONE endpoint that takes the raw mailbox password in
	// web-bootstrap scope — that is its job — so it carries the same per-source
	// lockout as vayumail-login, on the same counter, plus the route limiter.
	// Anything less just moves a password spray one route over.
	r.With(auth.PublicDiscoveryRateLimit).Post("/api/v1/members/vayumail-device-register", a.handleMemberVayuMailDeviceRegister)
	r.Post("/api/v1/members/vayumail-device-status", a.handleMemberVayuMailDeviceStatus)
	// Trusted-device recovery (ADR-0144): a device whose app password still works
	// sets a new mailbox password without the old one. Uniform 401 on every
	// rejection, and the reset revokes every app password including this one.
	r.Post("/api/v1/members/vayumail-device-reset", a.handleMailDeviceReset)
	// VayuTalk — ephemeral, end-to-end-encrypted messaging relay (ADR-0131). The
	// server never sees plaintext and persists nothing; envelopes live in a
	// bounded in-memory store that a restart purges. /connect authenticates in
	// the same mail-sync credential scope with the same uniform-401
	// anti-enumeration as vayumail-login; the rest are Bearer-authenticated.
	r.Post("/api/v1/talk/connect", a.handleTalkConnect)
	r.Get("/api/v1/talk/stream", a.handleTalkStream)
	r.Post("/api/v1/talk/send", a.handleTalkSend)
	r.Post("/api/v1/talk/ack", a.handleTalkAck)
	r.Get("/api/v1/talk/pubkey", a.handleTalkPubkey)
	// Inbound onion-to-onion delivery (ADR-0142): a remote .onion posts a
	// ciphertext envelope for our anonymous code. Closed unless federation is on
	// (the handler 404s otherwise); rate-limited like the other public endpoints.
	r.With(auth.PublicDiscoveryRateLimit).Post("/api/v1/talk/onion/deliver", a.handleTalkOnionDeliver)
	// Inbound onion-to-onion receipt (ADR-0142): a peer we messaged tells us they
	// read it; we surface it on the sender's stream. Same closed-by-default gating.
	r.With(auth.PublicDiscoveryRateLimit).Post("/api/v1/talk/onion/receipt", a.handleTalkOnionReceipt)
	r.Get("/pricing", a.handlePricingPage)
	// Built-in legal page: the VayuMail app privacy policy (Google Play link).
	r.Get("/vayumail/privacy", a.handleVayuMailPrivacy)
	r.Get("/api/v1/tiers", a.handleTiersPublic)
	// Public author profile pages.
	r.Get("/author/{id}", a.handlePublicAuthor)
	// Stripe webhook for paid upgrades — verified by signature, not API key.
	r.Post("/api/v1/stripe/webhook", a.handleStripeWebhook)

	// Monetization — public checkout (built-in direct gateway) and the generic
	// signed webhook any connected third-party payment processor can call. Both
	// are no-ops until the Payments module is enabled / a gateway is configured.
	r.Get("/checkout", a.handleCheckoutPage)
	r.Post("/checkout", a.handleCheckoutPage)
	r.Get("/checkout/success", a.handleCheckoutSuccess)              // Stripe return: verify + fulfil server-side
	r.Get("/checkout/paypal/return", a.handleCheckoutPayPalReturn)   // PayPal return: verify + fulfil server-side
	r.Get("/checkout/crypto/return", a.handleCheckoutCryptoReturn)   // BTCPay return: show status (webhook fulfils)
	r.Post("/api/v1/payments/btcpay/webhook", a.handleBTCPayWebhook) // BTCPay settlement webhook (HMAC-verified)
	r.Post("/checkout/post/{slug}", a.handlePostCheckout)            // buy one-time access to a single paid post
	r.Post("/api/v1/payments/webhook/{gateway}", a.handlePaymentWebhook)

	// VayuMCP (ADR-0139): the Model Context Protocol connector at POST /mcp, so an
	// AI assistant (Claude, etc.) can drive VayuPress natively. Authenticated by
	// the same scoped keys; capability is enforced per tool, not per URL.
	a.mountMCP(r)

	// Protected admin + write API. RequireAPIKey authenticates and stamps the
	// caller's KeyInfo; requireAPIPermission enforces the fine-grained
	// section:action grant for the route (ADR-0134) — superuser keys (bootstrap,
	// internal, and pre-migration backfilled keys) pass everything, scoped keys
	// get exactly what they were granted, unmapped routes fail closed.
	r.Group(func(r chi.Router) {
		// Chain: authenticate (stamp KeyInfo) → enforce section:action grant →
		// coarse per-IP cap → per-key budget + WORM audit (only admitted
		// requests consume a key's budget and appear in its usage trail).
		r.Use(auth.RequireAPIKey, a.requireAPIPermission, auth.RateLimitMiddleware, a.apiUsageMiddleware)

		// VCB (ADR-0135): machine-readable contract discovery + manifest
		// validation against this running host. Read-only; plugins:read.
		r.Get("/api/v1/vcb/contract", a.handleVCBContract)
		r.Post("/api/v1/vcb/validate", a.handleVCBValidate)

		r.Post("/api/v1/articles", a.handleCreateArticle)
		r.Post("/api/v1/articles/bulk", a.handleBulkCreateArticles)
		r.Put("/api/v1/articles/{slug}", a.handleUpdateArticle)
		r.Delete("/api/v1/articles/{slug}", a.handleDeleteArticle)
		r.Get("/api/v1/queue", a.handleQueueStatus)
		r.Post("/api/v1/queue/replay", a.handleQueueReplay)

		// Plugin features — comments, versions, collections, newsletter, webmentions, redirects, preview.
		r.Get("/api/v1/admin/comments", a.handleCommentListAdmin)
		r.With(auth.CSRFTokenMiddleware).Put("/api/v1/admin/comments/{id}/status", a.handleCommentModerate)
		r.Get("/api/v1/admin/articles/{slug}/versions", a.handleVersionList)
		r.Get("/api/v1/admin/articles/{slug}/versions/{id}", a.handleVersionGet)
		// Editable source side-car (Admin v2 multi-format authoring).
		r.Get("/api/v1/admin/articles/{slug}/source", a.handleArticleSourceGet)
		r.With(auth.CSRFTokenMiddleware).Put("/api/v1/admin/articles/{slug}/source", a.handleArticleSourcePut)
		r.Post("/api/v1/collections", a.handleCollectionCreate)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/collections/{id}/articles", a.handleCollectionAddArticle)
		r.Get("/api/v1/admin/newsletter/subscribers", a.handleNewsletterList)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/newsletter/broadcast", a.handleNewsletterBroadcast)

		// Scheduled publishing (Tier 1).
		r.Get("/api/v1/admin/schedule", a.handleScheduleList)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/schedule", a.handleScheduleCreate)
		r.With(auth.CSRFTokenMiddleware).Delete("/api/v1/admin/schedule/{id}", a.handleScheduleCancel)

		// Multi-author accounts (Tier 1) — admin-role guarded.
		r.Get("/api/v1/admin/users", a.handleUserList)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/users", a.handleUserCreate)
		r.With(auth.CSRFTokenMiddleware).Put("/api/v1/admin/users/{email}/role", a.handleUserSetRole)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/users/{email}/mailbox", a.handleAssignMailbox)
		r.With(auth.CSRFTokenMiddleware).Delete("/api/v1/admin/users/{email}", a.handleUserDelete)

		// Privacy-first analytics (Tier 2).
		r.Get("/api/v1/admin/analytics", a.handleAnalytics)

		// VayuAnalytics — extended endpoints (Tier 2, protected).
		r.Get("/api/v1/analytics/overview", a.handleAnalyticsOverview)
		r.Get("/api/v1/analytics/pageviews", a.handleAnalyticsPageviews)
		r.Get("/api/v1/analytics/pages", a.handleAnalyticsPages)
		r.Get("/api/v1/analytics/referrers", a.handleAnalyticsReferrers)
		r.Get("/api/v1/analytics/browsers", a.handleAnalyticsBrowsers)
		r.Get("/api/v1/analytics/devices", a.handleAnalyticsDevices)
		r.Get("/api/v1/analytics/os", a.handleAnalyticsOS)
		r.Get("/api/v1/analytics/utm", a.handleAnalyticsUTM)
		r.Get("/api/v1/analytics/events", a.handleAnalyticsEvents)
		r.Get("/api/v1/analytics/realtime", a.handleAnalyticsRealtime)
		r.Get("/api/v1/analytics/sessions", a.handleAnalyticsSessions)
		r.Get("/api/v1/analytics/funnels", a.handleAnalyticsFunnels)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/analytics/funnels", a.handleAnalyticsCreateFunnel)
		r.Get("/api/v1/analytics/funnels/{id}", a.handleAnalyticsGetFunnel)
		r.Get("/api/v1/analytics/retention", a.handleAnalyticsRetention)
		r.Get("/api/v1/analytics/revenue", a.handleAnalyticsRevenue)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/analytics/revenue", a.handleAnalyticsRecordRevenue)

		// Goals (conversion targets) — list/create/delete + computed results.
		r.Get("/api/v1/analytics/goals", a.handleAnalyticsGoals)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/analytics/goals", a.handleAnalyticsCreateGoal)
		r.With(auth.CSRFTokenMiddleware).Delete("/api/v1/analytics/goals/{id}", a.handleAnalyticsDeleteGoal)

		// Visitor journey / path-flow analysis.
		r.Get("/api/v1/analytics/journey", a.handleAnalyticsJourney)

		// Report export (CSV/JSON download) for every report.
		r.Get("/api/v1/analytics/export", a.handleAnalyticsExport)

		// AI writing assistant — local Ollama, opt-in (Tier 2).
		r.Get("/api/v1/admin/ai/status", a.handleAIStatus)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/ai/assist", a.handleAIAssist)

		// Reader memberships & paywalls (Tier 2) — admin management.
		r.Get("/api/v1/admin/members", a.handleMemberListAdmin)
		r.Get("/api/v1/admin/members/stats", a.handleMemberStats)
		r.Get("/api/v1/admin/members/export.csv", a.handleMembersExportCSV)
		r.With(auth.CSRFTokenMiddleware).Put("/api/v1/admin/members/{email}/tier", a.handleMemberSetTier)
		r.With(auth.CSRFTokenMiddleware).Put("/api/v1/admin/members/{email}/cancel", a.handleMemberCancel)
		r.Get("/api/v1/admin/members/{email}", a.handleMemberDetail)
		// Clearing members who never confirmed their address. The store refuses to
		// delete a verified member, so neither endpoint can remove a real account.
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/members/unverified/purge", a.handleMembersPurgeUnverified)
		r.With(auth.CSRFTokenMiddleware).Delete("/api/v1/admin/members/{email}", a.handleMemberDeleteAdmin)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/members/{email}/labels", a.handleMemberLabelAdd)
		r.With(auth.CSRFTokenMiddleware).Delete("/api/v1/admin/members/{email}/labels/{label}", a.handleMemberLabelRemove)
		r.Get("/api/v1/admin/articles/{slug}/access", a.handleArticleAccessGet)
		r.With(auth.CSRFTokenMiddleware).Put("/api/v1/admin/articles/{slug}/access", a.handleArticleAccessSet)

		// Membership tiers (premium plans) — list / create / update / archive.
		r.Get("/api/v1/admin/tiers", a.handleTierListAdmin)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/tiers", a.handleTierCreate)
		r.With(auth.CSRFTokenMiddleware).Put("/api/v1/admin/tiers/{id}", a.handleTierUpdate)
		r.With(auth.CSRFTokenMiddleware).Delete("/api/v1/admin/tiers/{id}", a.handleTierDelete)

		// Outbound webhooks (Tier 2).
		r.Get("/api/v1/admin/webhooks", a.handleWebhookList)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/webhooks", a.handleWebhookCreate)
		r.With(auth.CSRFTokenMiddleware).Delete("/api/v1/admin/webhooks/{id}", a.handleWebhookDelete)
		r.Get("/api/v1/admin/webhooks/{id}/deliveries", a.handleWebhookDeliveries)
		r.Get("/api/v1/admin/webmentions", a.handleWebmentionList)
		r.With(auth.CSRFTokenMiddleware).Put("/api/v1/admin/webmentions/{id}/status", a.handleWebmentionModerate)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/preview", a.handlePreviewIssue)
		// Editor image upload — sovereign, same-origin, magic-number validated.
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/media", a.handleMediaUpload)
		// Remote-image import — SSRF-safe fetch + re-host (ADR-0070).
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/media/import", a.handleMediaImport)
		// Embed unfurl — server-side OG metadata fetch + thumbnail import (ADR-0070).
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/embed/unfurl", a.handleEmbedUnfurl)
		// Diagram live preview — pure-Go Mermaid→SVG, content-addressed (ADR-0070).
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/diagram/preview", a.handleDiagramPreview)
		r.Get("/api/v1/admin/redirects", a.handleRedirectList)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/redirects", a.handleRedirectCreate)
		r.With(auth.CSRFTokenMiddleware).Delete("/api/v1/admin/redirects/{id}", a.handleRedirectDelete)

		// Self-update — READ-ONLY check + history (ADR-0064). No web apply path.
		r.Get("/admin/api/updates/check", a.handleUpdateCheck)
		r.Get("/admin/api/updates/history", a.handleUpdateHistory)

		// Observability & correlation trace API (ADR-0053).
		r.Get("/api/v1/admin/outbox/stats", a.handleOutboxStats)
		r.Get("/api/v1/admin/outbox/events", a.handleOutboxEvents)
		r.Get("/api/v1/admin/outbox/events/{id}", a.handleOutboxEvent)
		r.Get("/api/v1/admin/trace/{correlation_id}", a.handleCorrelationTrace)

		// Structured span tracing API (ADR-0054).
		r.Get("/api/v1/admin/traces", a.handleTraceSpans)
		r.Get("/api/v1/admin/traces/{trace_id}", a.handleTraceByID)

		// Resource governance stats (ADR-0055).
		r.Get("/api/v1/admin/resource/stats", a.handleResourceStats)

		// Sandbox subprocess plugin stats (ADR-0056).
		r.Get("/api/v1/admin/sandbox/stats", a.handleSandboxStats)

		// Search reconciler: drift report (read) + rebuild (CSRF-protected write).
		r.Get("/api/v1/admin/search/drift", a.handleSearchDrift)

		// System mode state machine (Ω5/Ω6).
		r.Get("/api/v1/admin/mode", a.handleModeStatus)
		r.Get("/api/v1/admin/fault/status", a.handleFaultStatus)
		r.Get("/api/v1/admin/timeline", a.handleTimelineJSON)
		r.Get("/api/v1/admin/severity", a.handleSeverityTaxonomy)
		r.Get("/api/v1/admin/budgets", a.handleGovernanceBudgets)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/budgets/ack", a.handleGovernanceBudgetAck)

		// The classic console root permanently redirects to VayuOS (ADR-0069
		// Stage 3). The operator consoles now live inside the single VayuOS shell
		// under /os/*; the legacy /admin/* page URLs 301-redirect to them.
		r.Get("/admin", legacyRedirect())
		r.Get("/admin/backup/validate", a.handleAdminBackupValidate)

		// Legacy /admin/* operator page URLs 301-redirect into VayuOS (/os/*).
		opsRedirect := operatorLegacyRedirect()
		r.Get("/admin/modes", opsRedirect)
		r.Get("/admin/faults", opsRedirect)
		r.Get("/admin/topology", opsRedirect)
		r.Get("/admin/replay", opsRedirect)
		r.Get("/admin/policy", opsRedirect)
		r.Get("/admin/adr", opsRedirect)

		r.With(auth.CSRFTokenMiddleware).Post("/admin/benchmark", a.handleRunBenchmark)
		r.With(auth.CSRFTokenMiddleware).Post("/admin/cache-purge", a.handleAdminCachePurge)
		r.With(auth.CSRFTokenMiddleware).Post("/admin/vacuum", a.handleAdminVacuum)
		r.With(auth.CSRFTokenMiddleware).Post("/admin/mode/transition", a.handleModeTransition)
		r.With(auth.CSRFTokenMiddleware).Post("/admin/fault/simulate", a.handleFaultSimulate)
		r.With(auth.CSRFTokenMiddleware).Post("/admin/replay/job", a.handleReplayJob)
		r.With(auth.CSRFTokenMiddleware).Post("/admin/search/reindex", a.handleSearchReindex)

		// Theme & site settings editor.
		// /admin/theme is retired (Wave 2.7 orphans & naming): the classic page
		// 301s into the VayuOS Theme editor so old bookmarks land somewhere
		// real. The theme ACTION endpoints below stay — they are an
		// authenticated API surface, not a page.
		r.Get("/admin/theme", legacyRedirect())
		r.Get("/admin/theme/export", a.handleThemeExport)
		r.With(auth.CSRFTokenMiddleware).Post("/admin/theme", a.handleThemeSave)
		r.With(auth.CSRFTokenMiddleware).Post("/admin/theme/reset", a.handleThemeReset)
		r.With(auth.CSRFTokenMiddleware).Post("/admin/theme/favicon", a.handleFaviconUpload)

		// Tier 4: real-time SSE event stream.
		r.Get("/api/v1/stream", a.handleEventStream)
		// Tier 4: email template management.
		r.Get("/api/v1/admin/email-templates", a.handleEmailTemplateList)
		r.With(auth.CSRFTokenMiddleware).Put("/api/v1/admin/email-templates/{kind}", a.handleEmailTemplateSet)
		// Tier 4: i18n catalog management.
		r.Get("/api/v1/admin/i18n", a.handleI18nLanguageList)
		r.With(auth.CSRFTokenMiddleware).Put("/api/v1/admin/i18n/{lang}", a.handleI18nLanguageSet)

		// Theme Studio — design-token system (Phase 5).
		r.Get("/api/v1/admin/theme/presets", a.handleThemePresets)
		r.Get("/api/v1/admin/theme/tokens", a.handleThemeTokens)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/theme/preview", a.handleThemePreview)
		r.With(auth.CSRFTokenMiddleware).Post("/api/v1/admin/theme/apply", a.handleThemeApply)

		r.HandleFunc("/debug/pprof/", a.pprofHandler)
		r.HandleFunc("/debug/pprof/cmdline", a.pprofHandler)
		r.HandleFunc("/debug/pprof/profile", a.pprofHandler)
		r.HandleFunc("/debug/pprof/symbol", a.pprofHandler)
		r.HandleFunc("/debug/pprof/trace", a.pprofHandler)
		r.HandleFunc("/debug/pprof/*", a.pprofHandler)
	})

	// Admin v2 was removed in v1.6.0 (ADR-0069 Stage 3). Its old URLs permanently
	// redirect into VayuOS; the redirect handler maps /admin/v2[/...] -> /os[/...].
	v2Redirect := legacyRedirect()
	r.Get("/admin/v2", v2Redirect)
	r.Handle("/admin/v2/*", v2Redirect)

	// VayuOS — the single admin, mounted at /os (ADR-0068, ADR-0069).
	a.registerAdminOSUIRoutes(r)

	r.Get("/", a.handleHome)
	// Business website: always previewable at /site; served at "/" in business mode.
	r.Get("/site", a.handleBizSite)
	r.Get("/site.css", a.handleBizSiteCSS)
	// Paginated homepage feed: /page/2, /page/3, … (page 1 is canonical at "/").
	// Two-segment, so it never collides with the single-segment "/{slug}".
	r.Get("/page/{page}", a.handleHomePaged)
	// business_subpath mode: the website owns "/", so the blog homepage lives at
	// /blog and its pagination at /blog/page/N — while posts keep their /slug
	// URLs. chi matches the static "/blog" ahead of "/{slug}"; in other modes
	// these handlers serve "/blog" as a normal article slug / 404 (see handlers).
	r.Get("/blog", a.handleBlogIndex)
	r.Get("/blog/page/{page}", a.handleBlogPaged)
	// Public, cookieless JSON for the Trending & pinned-posts widget on the
	// homepage and under every post (hydrated client-side by trending.js).
	r.Get("/api/trending", a.handleTrendingJSON)
	// Public, cookieless compact index for the VayuFind instant-search modal
	// (downloaded once, filtered client-side; ETag-revalidated).
	r.Get("/api/search-index.json", a.handleSearchIndex)
	// Public site search page (the nav search box submits here). chi matches this
	// static route ahead of the "/{slug}" catch-all.
	r.Get("/search", a.handleSearchPage)
	// Public taxonomy pages — the topic index and per-tag listings. Registered
	// before the single-segment "/{slug}" catch-all so "/tags" and "/tags/{tag}"
	// resolve here instead of falling through to a 404 (the two-segment form
	// previously matched no route).
	r.Get("/tags", a.handleTagIndex)
	r.Get("/tags/{tag}", a.handleTagPage)
	r.NotFound(a.handleNotFound)
	r.Get("/{slug}", a.handleArticlePage)
}
