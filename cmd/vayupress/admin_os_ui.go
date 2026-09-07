// SPDX-License-Identifier: Apache-2.0

package main

// admin_os_ui.go — VayuPress VayuOS, mounted under /os.
//
// Design goals (ADR-0068): surpass Ghost/WordPress/Substack in UI beauty,
// feature depth, and security while remaining a sovereign single-binary with
// zero CDN dependencies and strict-CSP compliance.
//
// CSP posture (inherited from middleware.go — non-negotiable):
//   default-src 'self'; style-src 'self'; script-src 'self' 'nonce-<N>';
//   font-src 'self'; img-src 'self' data:; form-action 'self'
//
// Rules honoured:
//   - No inline <style> or style="" attributes. All CSS lives in admin-os.css.
//   - The only inline <script> block carries the per-request CSP nonce.
//   - No external CDNs. All assets served same-origin under /os/static/.
//   - All user-originated strings escaped with html.EscapeString before HTML emit.
//   - DOM mutations in admin-os.js use textContent / createElement; no innerHTML
//     with untrusted data.
//
// Phase 1 implements: login page redesign, new grouped sidebar, stat-card
// dashboard, posts table, editor wrapper, settings page, SEO page.
// Phases 2-7 add block editor, media library, members, TOTP security, i18n,
// GraphQL admin, command palette, and all remaining intelligence features.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html"
	htmpl "html/template"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/johalputt/vayupress/internal/auth"
	"github.com/johalputt/vayupress/internal/blockrender"
	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/render"
	"github.com/johalputt/vayupress/internal/settings"
	"github.com/johalputt/vayupress/internal/users"
)

// ── Static asset path ────────────────────────────────────────────────────────

func adminOSStaticDir() string {
	return config.EnvOr("STATIC_DIR", "/var/www/vayupress/static")
}

// ── Route registration ───────────────────────────────────────────────────────

// registerAdminOSUIRoutes mounts VayuOS under /os.
// Follows the same auth/CSP/CSRF patterns as Admin v2 (admin_ui.go).
func (a *App) registerAdminOSUIRoutes(r chi.Router) {
	// VayuOS is now a legacy surface (ADR-0069 Stage 3 in progress): the
	// canonical admin is VayuOS at /os. Old /admin/v3[/...] URLs 302-redirect
	// into the /os equivalent, joining /admin and /admin/v2.
	osRedirect := legacyRedirect()
	r.Get("/admin/v3", osRedirect)
	r.Handle("/admin/v3/*", osRedirect)

	// Public static assets (served same-origin so CSP 'self' covers them).
	r.Get("/os/static/css/admin-os.css", serveAdminOSAsset("css/admin-os.css", "text/css; charset=utf-8"))
	r.Get("/os/static/js/admin-os.js", serveAdminOSAsset("js/admin-os.js", "application/javascript; charset=utf-8"))
	// VayuOS installable app (PWA): manifest, service worker (scoped /os/), and app
	// icons. Served here without auth — like the other /os/static assets — so the
	// browser can fetch them to offer + keep the install; they carry no user data.
	r.Get("/os/manifest.webmanifest", a.handleOSManifest)
	r.Get("/os/sw.js", a.handleOSServiceWorker)
	r.Get("/os/static/icons/vayuos-192.png", servePNG(osIcon192PNG))
	r.Get("/os/static/icons/vayuos-512.png", servePNG(osIcon512PNG))
	r.Get("/os/static/icons/vayuos-maskable-512.png", servePNG(osIconMaskablePNG))
	r.Get("/os/static/icons/vayuos-apple-180.png", servePNG(osIconApplePNG))
	// Alpine.js CSP build + the VayuOS island registry (ADR-0136). Self-hosted,
	// eval-free, served same-origin so they satisfy script-src 'self' with no
	// unsafe-eval.
	r.Get("/os/static/js/alpine-csp.min.js", serveAdminOSAsset("js/alpine-csp.min.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/vayu-islands.js", serveAdminOSAsset("js/vayu-islands.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-editor.js", serveAdminOSAsset("js/admin-os-editor.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-security.js", serveAdminOSAsset("js/admin-os-security.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-members.js", serveAdminOSAsset("js/admin-os-members.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-pwa.js", serveAdminOSAsset("js/admin-os-pwa.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-mail-recovery.js", serveAdminOSAsset("js/admin-os-mail-recovery.js", "application/javascript; charset=utf-8"))
	// The sign-in shell's light/dark switcher. It had no route at all, so the
	// three theme buttons on the login page have been inert since they shipped —
	// found by the guard in console_assets_test.go, not by anyone using it.
	r.Get("/os/static/js/os-theme.js", serveAdminOSAsset("js/os-theme.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-newsletter.js", serveAdminOSAsset("js/admin-os-newsletter.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-profile.js", serveAdminOSAsset("js/admin-os-profile.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-intel.js", serveAdminOSAsset("js/admin-os-intel.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-pages.js", serveAdminOSAsset("js/admin-os-pages.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-tools.js", serveAdminOSAsset("js/admin-os-tools.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-theme.js", serveAdminOSAsset("js/admin-os-theme.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/theme-preview-frame.js", serveAdminOSAsset("js/theme-preview-frame.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-theme-store.js", serveAdminOSAsset("js/admin-os-theme-store.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-mail.js", serveAdminOSAsset("js/admin-os-mail.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-talk.js", serveAdminOSAsset("js/admin-os-talk.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-tor.js", serveAdminOSAsset("js/admin-os-tor.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-update.js", serveAdminOSAsset("js/admin-os-update.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-storage.js", serveAdminOSAsset("js/admin-os-storage.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/admin-os-website.js", serveAdminOSAsset("js/admin-os-website.js", "application/javascript; charset=utf-8"))
	r.Get("/os/static/js/purify.min.js", serveAdminOSAsset("js/purify.min.js", "application/javascript; charset=utf-8"))

	// Fonts are NOT served from /os. This route used to allowlist three names —
	// space-grotesk.woff2, inter.woff2, jetbrains-mono.woff2 — and read them from
	// STATIC_DIR on disk. None of those files exists in this repository or in any
	// binary, so the route could only ever 404, and admin-os.css referenced all
	// three: every console page load fired three failed requests and silently fell
	// back to the system font stack.
	//
	// Unlike serveAdminOSAsset it had no embedded fallback, which is why the CSS
	// and JS survived a binary-only update and the fonts did not. Rather than ship
	// ~200 KB of typefaces inside a single-binary product to fix cosmetics that
	// already looked right, admin-os.css now points at the Space Grotesk weights
	// the public theme already embeds (/static/fonts, handleStaticFont) and leaves
	// the rest to the system stack.

	// Country flag SVGs (flag-icons, MIT) compiled into the binary and served
	// on demand from /os/static/flags/<cc>.svg. Path-traversal is impossible:
	// the filename is validated to be exactly a two-letter lowercase ISO code,
	// and the bytes come from the embedded FS — never the live filesystem.
	r.Get("/os/static/flags/{file}", func(w http.ResponseWriter, req *http.Request) {
		file := chi.URLParam(req, "file")
		if !isFlagFile(file) {
			http.NotFound(w, req)
			return
		}
		data, err := flagFS.ReadFile("flags/" + file)
		if err != nil {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(data)
	})

	// Public: login page and credential forms.
	r.Get("/os/login", a.handleOSLogin)
	r.Post("/os/login", a.handleOSLoginSubmit)
	r.Post("/os/logout", a.handleOSLogout)

	// Protected pages and APIs — require session or API key.
	r.Group(func(pr chi.Router) {
		pr.Use(a.requireSessionOrAPIKey)
		// Enter-the-Tor-world bridge (ADR-0141): while the operator's view is set to
		// Tor, this proxies /os/* into the separate Tor-world instance so they manage
		// its data (its own database), never clearnet's. Mounted after auth so only a
		// signed-in admin can reach the proxy; /os/world and /os/logout are exempt so
		// the operator can always flip back or sign out.
		pr.Use(a.torWorldMiddleware)
		// The world switch itself: a light GET that sets/clears the per-browser view
		// cookie (enabling the Tor world is the separate CSRF-checked space toggle).
		pr.Get("/os/world", a.handleWorldSwitch)

		// Pages
		pr.Get("/os", a.handleOSDashboard)
		// "/os/" serves the dashboard directly rather than redirecting to "/os".
		// It is the installed app's start_url, and it has to be inside the service
		// worker's "/os/" scope for the browser to mint a real app instead of a
		// shortcut (see handleOSManifest). A redirect here would not do: the
		// installability check follows the start URL, and answering it with a 30x
		// is what a shortcut-only install looks like from the browser's side.
		pr.Get("/os/", a.handleOSDashboard)
		pr.Get("/os/change-password", a.handleOSChangePassword)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/change-password", a.handleOSChangePasswordSubmit)
		pr.Get("/os/posts", a.handleOSPosts)
		pr.Get("/os/comments", a.handleOSComments)
		// Session-friendly comment moderation. The /api/v1/admin/comments originals
		// require an API key; VayuOS operators hold a session cookie.
		pr.With(auth.CSRFTokenMiddleware).Put("/os/api/comments/{id}/status", a.handleCommentModerate)
		// HTMX in-place moderation: returns an HTML fragment (new action buttons +
		// out-of-band status pill and pending/approved counts) instead of JSON, so
		// the Comments manager updates the row without a full-page reload.
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/comments/{id}/status-fragment", a.handleOSCommentModerateFragment)
		// Custom pages — standalone articles flagged is_page (no post chrome),
		// managed separately from the blog feed (Tumblr-style "Add a page").
		pr.Get("/os/pages", a.handleOSPages)
		pr.Get("/os/website", a.handleOSWebsite)
		// VayuDomains registry (migration 059) — manage every hostname this
		// install answers on. Writes are CSRF-protected session-friendly APIs.
		pr.Get("/os/domains", a.handleOSDomains)
		// Per-site manager — the "control every part of this site" surface reached
		// from a domain card and from the Optimize hub's "Your websites" row.
		pr.Get("/os/domains/{id}", a.handleOSDomainManage)

		// ── Per-domain console (ADR-0153 Phase 3) ──────────────────────────────
		//
		// The scope is the URL. /os/d/{id}/theme edits {id}; /os/theme edits the
		// primary. The middleware resolves {id} to a settings.Scope and refuses by
		// NOT ROUTING, so no handler downstream can run against a domain nobody
		// proved exists — and a write cannot be addressed by a stale switcher,
		// because there is no switcher.
		pr.Route("/os/d/{id}", func(dr chi.Router) {
			dr.Use(a.scopedDomainMiddleware)
			dr.Get("/", a.handleOSScopedHome)
			// Re-run the certificate checks on demand. A read, so no CSRF token
			// and no state change — see ADR-0160.
			dr.Get("/diagnose/live", a.handleOSScopedDiagnoseLive)
			dr.Get("/settings", a.handleOSScopedSettings)
			dr.With(auth.CSRFTokenMiddleware).Post("/api/settings", a.handleOSScopedSettingsSave)
			// Content (ADR-0154 D4). The move endpoint takes "site" or "primary"
			// and resolves it against the domain in the PATH, so a caller cannot
			// name a third site.
			dr.Get("/content", a.handleOSScopedContent)
			dr.With(auth.CSRFTokenMiddleware).Post("/api/content/move", a.handleOSScopedContentMove)
			dr.With(auth.CSRFTokenMiddleware).Post("/api/content/new", a.handleOSScopedContentNew)
			// Website (ADR-0154 D9): what this domain serves at "/", and the
			// content of that site when it serves a website.
			dr.Get("/website", a.handleOSScopedWebsite)
			dr.With(auth.CSRFTokenMiddleware).Post("/api/website", a.handleOSScopedWebsiteSave)
			// A whole hand-built site for this domain (ADR-0154 D12). Both go
			// through customsite.Deploy, which confines every write to an
			// os.Root and refuses traversal in archive entries.
			dr.With(auth.CSRFTokenMiddleware).Post("/api/website/bundle", a.handleOSScopedBundleUpload)
			dr.Get("/api/website/preview", a.handleOSScopedWebsitePreview)
			dr.With(auth.CSRFTokenMiddleware).Post("/api/website/bundle/rollback", a.handleOSScopedBundleRollback)
			// THEME STUDIO IS NO LONGER MOUNTED PER SITE, and the comment that
			// used to sit here is why it took so long to notice: it said the
			// handler "reads its scope from the request, so one code path serves
			// both". The HANDLER does. The PAGE does not — its script posts to
			// absolute /os/api/theme/* and /os/api/settings paths, so every write
			// from /os/d/{id}/theme landed on the primary. Beneath that,
			// theme_tokens is CHECK(id=1) and applying a theme sets a process
			// global, so there is no per-site theme for a scoped route to write.
			//
			// The old address REDIRECTS rather than 404s — it is in bookmarks and
			// in this console's own history — and lands on the per-site settings
			// page, which is where a hosted site's identity genuinely lives
			// (ADR-0154 D3). Theme Studio is now named in sharedTools as
			// install-wide, alongside the media library and the newsletter.
			dr.Get("/theme", a.handleOSScopedThemeRetired)
			// This domain's own mark. The SAME upload handler as the operator's
			// branding page, mounted a second time — it takes its scope from the
			// request, so one code path stores both and a per-domain copy cannot
			// drift from the primary's.
			dr.With(auth.CSRFTokenMiddleware).Post("/api/branding/favicon", a.handleFaviconUpload)
			// Read side, for the console. A hosted domain's mark is already public
			// at that domain's own /favicon.ico; this exists because the panel is
			// served from a DIFFERENT origin and cannot ask another host for it.
			dr.Get("/branding/mark", a.handleOSScopedBrandMark)
			dr.Get("/seo", a.handleOSScopedSEO)
			dr.Get("/analytics", a.handleOSScopedAnalytics)
			dr.With(auth.CSRFTokenMiddleware).Post("/api/copy-from-primary", a.handleOSScopedCopyFromPrimary)
		})
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/domains", a.handleOSDomainCreate)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/domains/assign", a.handleOSDomainAssign)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/domains/sync-all", a.handleOSDomainSyncAll)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/domains/{id}/status", a.handleOSDomainStatus)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/domains/{id}/allowance", a.handleOSDomainAllowance)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/domains/{id}/serves", a.handleOSDomainServes)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/domains/{id}/client", a.handleOSDomainClient)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/domains/{id}/sync", a.handleOSDomainSync)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/domains/{id}/brand", a.handleOSDomainBrand)
		pr.With(auth.CSRFTokenMiddleware).Delete("/os/api/domains/{id}", a.handleOSDomainDelete)
		// One-click "Add Tor site" (ADR-0141): Tor-world only. add-site registers a
		// placeholder site the operator can serve blog/mail on; sites/assign are the
		// parent↔child control channel that mints and hands back each site's .onion
		// (bearer-authed from the parent, so CSRF-exempt).
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/torworld/add-site", a.handleTorWorldAddSite)
		pr.Get("/os/api/torworld/sites", a.handleTorWorldSites)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/torworld/assign", a.handleTorWorldAssign)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/website/save", a.handleOSWebsiteSave)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/website/custom-upload", a.handleOSWebsiteCustomUpload)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/website/custom-rollback", a.handleOSWebsiteCustomRollback)
		pr.Get("/os/api/website/custom-guide", a.handleOSWebsiteCustomGuide)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/pages/quick-create", a.handleOSQuickCreatePage)
		// Contact-form inbox — durable record of public contact submissions.
		pr.Get("/os/messages", a.handleOSMessages)
		pr.Get("/os/messages/{id}", a.handleOSMessageDetail)
		pr.With(auth.CSRFTokenMiddleware).Put("/os/api/messages/{id}/read", a.handleOSMessageRead)
		pr.With(auth.CSRFTokenMiddleware).Delete("/os/api/messages/{id}", a.handleOSMessageDelete)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/messages/read-all", a.handleOSMessagesReadAll)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/messages/delete-read", a.handleOSMessagesDeleteRead)
		pr.Get("/os/api/messages/export.csv", a.handleOSMessagesExportCSV)
		pr.Get("/os/media", a.handleOSMedia)
		pr.Get("/os/api/media", a.handleOSMediaList)
		// Session-friendly media upload + import. The /api/v1/admin/media originals
		// require an API key; VayuOS operators hold a session cookie, so the browser
		// Media library must POST here instead (same handlers, CSRF-protected).
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/media/upload", a.handleMediaUpload)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/media/delete", a.handleOSMediaDelete)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/media/alt", a.handleOSMediaAlt)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/media/import", a.handleMediaImport)
		// Growth hub: consolidates Members / Newsletter / Monetization / Advertising
		// (+ My Profile) into one dashboard-style card page (admin-only).
		pr.Get("/os/growth", a.handleOSGrowth)
		// Operations hub: consolidates System Modes / Policy / Topology / Replay /
		// Fault Engine / ADR Registry into one dashboard-style card page (admin-only).
		pr.Get("/os/operations", a.handleOSOperations)
		// Power & Maintenance: take the public site offline behind a premium
		// maintenance page, restart, or shut down. Preview renders that page.
		pr.Get("/os/power", a.handleOSPower)
		pr.Get("/os/vayukeep", a.handleOSVayuKeep)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayukeep/backup", a.handleOSVayuKeepBackup)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayukeep/drill", a.handleOSVayuKeepDrill)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayukeep/verify", a.handleOSVayuKeepVerify)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayukeep/setup", a.handleOSVayuKeepSetup)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayukeep/disable", a.handleOSVayuKeepDisable)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayukeep/restore", a.handleOSVayuKeepRestore)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayukeep/delete", a.handleOSVayuKeepDelete)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayukeep/retention", a.handleOSVayuKeepRetention)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayukeep/prune", a.handleOSVayuKeepPrune)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayukeep/backup", a.handleOSVayuKeepBackup)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayukeep/drill", a.handleOSVayuKeepDrill)
		pr.Get("/os/power/preview", a.handleOSPowerPreview)
		// Optimize hub: consolidates SEO / Analytics / VayuShield / Theme Studio /
		// Theme Store + Tools / Domains / Settings / VayuAPI / VayuMCP into one
		// dashboard-style card page (editor+; admin-only cards hidden from editors).
		pr.Get("/os/optimize", a.handleOSOptimize)
		// System hub: Storage & System / Settings / My Profile as a card page —
		// gives the Tor-world console the same minimal hub treatment (ADR-0141).
		pr.Get("/os/system", a.handleOSSystem)
		pr.Get("/os/members", a.handleOSMembers)
		// HTMX fragment: live-refresh the Members "Recent activity" feed.
		pr.Get("/os/members/activity", a.handleOSMembersActivityFragment)
		// Session-friendly membership management APIs (the /api/v1/admin/* originals
		// require an API key; VayuOS operators hold a session cookie).
		pr.Get("/os/api/members/stats", a.handleMemberStats)
		pr.Get("/os/api/members/export.csv", a.handleMembersExportCSV)
		pr.Get("/os/api/members/{email}", a.handleMemberDetail)
		pr.Get("/os/api/members/tiers", a.handleTierListAdmin)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/members/tiers", a.handleTierCreate)
		pr.With(auth.CSRFTokenMiddleware).Put("/os/api/members/tiers/{id}", a.handleTierUpdate)
		pr.With(auth.CSRFTokenMiddleware).Delete("/os/api/members/tiers/{id}", a.handleTierDelete)
		pr.With(auth.CSRFTokenMiddleware).Put("/os/api/members/{email}/tier", a.handleMemberSetTier)
		pr.With(auth.CSRFTokenMiddleware).Put("/os/api/members/{email}/cancel", a.handleMemberCancel)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/members/{email}/labels", a.handleMemberLabelAdd)
		pr.With(auth.CSRFTokenMiddleware).Delete("/os/api/members/{email}/labels/{label}", a.handleMemberLabelRemove)
		// Removing members who never confirmed their address. The store refuses to
		// delete a verified member, so neither route can remove a real account.
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/members/unverified/purge", a.handleMembersPurgeUnverified)
		pr.With(auth.CSRFTokenMiddleware).Delete("/os/api/members/{email}", a.handleMemberDeleteAdmin)
		// Newsletter console — the operator page plus session-friendly management
		// APIs (the /api/v1/admin/newsletter/* originals require an API key; os
		// operators hold a session cookie). Writes are CSRF-protected.
		pr.Get("/os/newsletter", a.handleOSNewsletter)
		pr.Get("/os/api/newsletter/stats", a.handleOSNewsletterStats)
		pr.Get("/os/api/newsletter/subscribers", a.handleOSNewsletterSubscribers)
		pr.Get("/os/api/newsletter/broadcasts", a.handleOSNewsletterBroadcasts)
		pr.Get("/os/api/newsletter/export.csv", a.handleOSNewsletterExport)
		pr.With(auth.CSRFTokenMiddleware).Delete("/os/api/newsletter/subscribers/{id}", a.handleOSNewsletterDelete)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/newsletter/test", a.handleOSNewsletterSendTest)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/newsletter/broadcast", a.handleOSNewsletterBroadcastSend)
		// Self-service author profile + admin team/role management (session mirrors).
		pr.Get("/os/profile", a.handleOSProfile)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/profile", a.handleProfileSave)
		pr.Get("/os/api/users", a.handleUserList)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/users", a.handleUserCreate)
		pr.With(auth.CSRFTokenMiddleware).Put("/os/api/users/{email}/role", a.handleUserSetRole)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/users/{email}/mailbox", a.handleAssignMailbox)
		pr.With(auth.CSRFTokenMiddleware).Delete("/os/api/users/{email}", a.handleUserDelete)
		pr.Get("/os/security", a.handleOSSecurity)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/totp/begin", a.handleOSTOTPBegin)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/totp/verify", a.handleOSTOTPVerify)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/totp/disable", a.handleOSTOTPDisable)
		pr.Get("/os/editor", a.handleOSEditor)
		pr.Get("/os/editor/{slug}", a.handleOSEditor)
		pr.Get("/os/monitoring", a.handleOSMonitoring)
		pr.Get("/os/monitoring/live", a.handleOSMonitoringLive)
		pr.Get("/os/governance", a.handleOSGovernance)
		pr.Get("/os/theme", a.handleOSTheme)
		pr.Get("/os/theme/store", a.handleOSThemeStore)
		pr.Get("/os/theme/preview", a.handleOSThemePreview)
		pr.Get("/os/theme/preview.css", a.handleOSThemePreviewCSS)
		// Session-friendly mirrors of the Theme Studio JSON API (the /api/v1/admin
		// originals require an API key; os operators hold a session cookie).
		pr.Get("/os/api/theme/presets", a.handleThemePresets)
		pr.Get("/os/api/theme/tokens", a.handleThemeTokens)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/theme/preview", a.handleThemePreview)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/theme/preview-draft", a.handleOSThemePreviewDraft)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/theme/apply", a.handleThemeApply)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/theme/harmony", handleThemeHarmony)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/theme/nearest", handleThemeNearest)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/theme/draft", a.handleThemeDraftSave)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/theme/code", a.handleOSThemeCode)
		pr.Get("/os/api/theme/export", a.handleOSThemeExport)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/theme/import", a.handleOSThemeImport)
		// Session-friendly read-only mirrors of the operator JSON APIs (the
		// /api/v1/admin/* originals require an API key; os operators hold a
		// session cookie). Same handlers, no CSRF needed for GETs.
		pr.Get("/os/api/mode", a.handleModeStatus)
		pr.Get("/os/api/budgets", a.handleGovernanceBudgets)
		pr.Get("/os/tools", a.handleOSTools)
		pr.Get("/os/api/tools", a.handleOSToolsList)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/tools/toggle", a.handleOSToolToggle)
		// Power & Maintenance actions (admin-only, CSRF-protected).
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/power/maintenance", a.handleOSPowerMaintenance)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/power/restart", a.handleOSPowerRestart)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/power/shutdown", a.handleOSPowerShutdown)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/power/crawlers", a.handleOSPowerCrawlers)

		// Monetization — payment order ledger + gateway config, and the
		// activation-gated advertising surface.
		pr.Get("/os/monetization", a.handleOSMonetization)
		pr.Get("/os/api/orders", a.handleOSOrdersList)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/orders/{id}/paid", a.handleOSOrderMarkPaid)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/orders/{id}/cancel", a.handleOSOrderCancel)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/orders/{id}/refund", a.handleOSOrderRefund)
		// One-click card gateways (Stripe now; PayPal in a later phase).
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/payments/stripe/connect", a.handleStripeConnect)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/payments/stripe/test", a.handleStripeTest)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/payments/stripe/disconnect", a.handleStripeDisconnect)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/payments/paypal/connect", a.handlePayPalConnect)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/payments/paypal/test", a.handlePayPalTest)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/payments/paypal/disconnect", a.handlePayPalDisconnect)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/payments/btcpay/connect", a.handleBTCPayConnect)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/payments/btcpay/test", a.handleBTCPayTest)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/payments/btcpay/disconnect", a.handleBTCPayDisconnect)
		// Premium Mail-ID management console (see/approve/disapprove sales + the
		// operator's premium-name list).
		pr.Get("/os/monetization/mailids", a.handleOSMailIDs)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/mailids/{id}/approve", a.handleOSMailIDApprove)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/mailids/{id}/revoke", a.handleOSMailIDRevoke)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/mailids/premium-names/add", a.handleOSMailIDNameAdd)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/mailids/premium-names/remove", a.handleOSMailIDNameRemove)
		pr.Get("/os/ads", a.handleOSAds)
		pr.Get("/os/api/ads", a.handleOSAdsList)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/ads", a.handleOSAdCreate)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/ads/{id}/toggle", a.handleOSAdToggle)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/ads/{id}/approve", a.handleOSAdReviewApprove)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/ads/{id}/reject", a.handleOSAdReviewReject)
		pr.With(auth.CSRFTokenMiddleware).Delete("/os/api/ads/{id}", a.handleOSAdDelete)

		// Update & Backup — one-click signature-verified self-update plus full
		// site (database + settings) export/import. Writes are CSRF-protected and
		// admin-role gated inside each handler; export/import lift the server
		// read/write deadlines so transfers have no size limit.
		pr.Get("/os/update", a.handleOSUpdate)
		pr.Get("/os/api/update/check", a.handleOSUpdateCheck)
		pr.Get("/os/api/update/history", a.handleOSUpdateHistory)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/update/apply", a.handleOSUpdateApply)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/update/restart", a.handleOSUpdateRestart)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/update/rollback", a.handleOSUpdateRollback)
		// Subdomain provisioning: the console asks, a root-side systemd unit acts.
		// CSRF-protected because it makes the server run certbot on demand, and
		// Let's Encrypt rate limits are a finite resource worth not letting an
		// off-origin page burn.
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/provision/run", a.handleOSProvisionRequest)
		pr.Get("/os/api/provision/status", a.handleOSProvisionStatus)
		// Domains & DNS — which records an install needs and whether each is
		// actually pointed here. Every subdomain fails quietly when its record is
		// missing, so this is the page that makes a half-configured install visible.
		pr.With(auth.CSRFTokenMiddleware).Get("/os/dns", a.handleOSDNS)
		pr.Get("/os/api/backup/export", a.handleOSBackupExport)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/backup/import", a.handleOSBackupImport)

		// Storage & System — admin-only resource usage (RAM/disk) plus managed
		// files (backups/logs/temp) with per-file download + delete. The
		// download/delete validate the path against the live managed-file set, so
		// path traversal is impossible and the live DB can never be touched.
		pr.Get("/os/storage", a.handleOSStorage)
		pr.Get("/os/api/storage/download", a.handleOSStorageDownload)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/storage/delete", a.handleOSStorageDelete)
		pr.Get("/os/seo", a.handleOSSEONative)
		pr.Get("/os/analytics", a.handleOSAnalytics)
		// VayuAnalytics: export downloads + goal management (session-authed).
		pr.Get("/os/api/analytics/export", a.handleAnalyticsExport)
		pr.Get("/os/api/analytics/export-parquet", a.handleAnalyticsParquetExport)
		pr.Get("/os/api/analytics/realtime", a.handleAnalyticsRealtime)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/analytics/goals", a.handleAnalyticsCreateGoal)
		pr.With(auth.CSRFTokenMiddleware).Delete("/os/api/analytics/goals/{id}", a.handleAnalyticsDeleteGoal)
		// VayuShield operator panel (admin-gated).
		// Both the page load AND the section poll re-issue the vp_csrf cookie
		// (CSRFTokenMiddleware) so it never goes stale while the panel is open.
		// The hero polls the section route every 10s, so within 10s of a CSRF
		// secret rotation (every deploy/restart) or the 1h cookie lifetime, the
		// token is refreshed — without this, Save / Tier / Verify POSTs silently
		// 403 after a deploy until the operator hard-reloads (the "Save button
		// does nothing" report). Mirrors the VayuMail fix below.
		pr.With(auth.CSRFTokenMiddleware).Get("/os/shield", a.handleOSShield)
		// Per-section HTMX fragment refresh (no whole-page reload).
		pr.With(auth.CSRFTokenMiddleware).Get("/os/shield/section/{name}", a.handleOSShieldSection)
		pr.Get("/os/api/shield/export", a.handleOSShieldExport)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/shield/verify", a.handleOSShieldVerify)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/shield/dismiss", a.handleOSShieldDismiss)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/shield/release", a.handleOSShieldRelease)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/shield/settings", a.handleOSShieldSettings)
		// Tier 2/3 in-panel toggle — records intent (a flag file); a root agent applies it.
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/shield/tier", a.handleOSShieldTier)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/shield/cdn-allow", a.handleOSShieldCDNAllow)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/shield/agent-upgrade", a.handleOSShieldAgentUpgrade)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/shield/fix", a.handleOSShieldFix)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/shield/rescue", a.handleOSShieldRescue)
		// VayuOS — native control layer (Phase 2): Publishing · Mail · PGP.
		// GET pages are wrapped in CSRFTokenMiddleware so each load (re)issues the
		// vp_csrf cookie the panel's POSTs read back; without this the token
		// expires (1h) and Send / Save-as-draft / message actions start 403ing.
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayumail", a.handleVayuOSDashboard)
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayumail/pgp", a.handleVayuOSPGP)
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayumail/dns", a.handleVayuOSMail)
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayumail/dns/verify", a.handleVayuOSMailDNSVerify)
		// Legacy /os/vayuos/* URLs (pre-2.8 layout) redirect permanently to the
		// clean /os/vayumail/* namespace so bookmarks and muscle memory keep working.
		pr.Get("/os/vayuos", redirectLegacyVayuOS)
		pr.Get("/os/vayuos/*", redirectLegacyVayuOS)
		pr.Post("/os/vayuos/*", redirectLegacyVayuOS)
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayumail/inbox", a.handleVayuOSInbox)
		pr.Get("/os/vayumail/inbox/fragment", a.handleVayuOSInboxFragment)
		pr.Get("/os/vayumail/unseen", a.handleVayuOSUnseen)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/inbox/action", a.handleVayuOSInboxAction)
		pr.Get("/os/vayumail/attachment", a.handleVayuOSAttachment)
		pr.Get("/os/vayumail/search/fragment", a.handleVayuOSSearchFragment)
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayumail/search", a.handleVayuOSSearch)
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayumail/message", a.handleVayuOSMessage)
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayumail/sent", a.handleVayuOSSent)
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayumail/compose", a.handleVayuOSCompose)
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayumail/accounts", a.handleVayuOSAccounts)
		// PUBLIC key download only. There is no private-key counterpart to this
		// route and there must never be one — an administrator has no business
		// holding another mailbox's private key. The owner's own device fetches it
		// via /api/v1/members/vayumail-privkey under the MAIL-SYNC device scope.
		pr.Get("/os/vayumail/accounts/pubkey", a.handleVayuOSAccountPubKey)
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayumail/connect", a.handleVayuOSConnect)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/send", a.handleVayuOSSend)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/draft", a.handleVayuOSDraft)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/message/action", a.handleVayuOSMessageAction)
		// Split reading pane: load a message beside the list + act on it in place.
		pr.Get("/os/vayumail/inbox/readpane", a.handleVayuOSReadpane)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/message/pane-action", a.handleVayuOSMessagePaneAction)
		// Aliases & auto-forwarding (admin-only; HTMX card on the Accounts page).
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/aliases/action", a.handleVayuOSAliasAction)
		// Vacation autoresponder (admin-only; HTMX card on the Accounts page).
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/autoreply/action", a.handleVayuOSAutoreplyAction)
		// Server-side filter rules (admin-only; HTMX card on the Accounts page).
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/filters/action", a.handleVayuOSFilterAction)
		// Outbox: HTMX auto-refresh fragment + per-message Resend/Delete/Retry-all.
		pr.Get("/os/vayumail/outbox/fragment", a.handleVayuOSOutboxFragment)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/outbox/action", a.handleVayuOSOutboxAction)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/outbox/retention", a.handleVayuOSOutboxRetention)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/accounts/create", a.handleVayuOSAccountCreate)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/accounts/delete", a.handleVayuOSAccountDelete)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/accounts/update", a.handleVayuOSAccountUpdate)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/accounts/totp", a.handleVayuOSAccountTOTP)
		// Account recovery enrolment + readiness (ADR-0144). Admin-only; the
		// generate endpoint issues credentials, so it is CSRF-protected like every
		// other console write.
		pr.With(auth.CSRFTokenMiddleware).Get("/os/api/vayuos/mail/recovery/status", a.handleVayuOSRecoveryStatus)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayuos/mail/recovery/codes", a.handleVayuOSRecoveryCodes)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayuos/mail/recovery/contact", a.handleVayuOSRecoveryContact)
		pr.With(auth.CSRFTokenMiddleware).Get("/os/api/vayuos/mail/recovery/requests", a.handleVayuOSRecoveryRequests)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayuos/mail/recovery/decide", a.handleVayuOSRecoveryDecide)
		// Accounts redesign: HTMX list fragment + inline action swap (enable/disable,
		// role, quota, retention, delete) so the page never full-reloads.
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayumail/accounts/fragment", a.handleVayuOSAccountsFragment)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/accounts/avatar", a.handleVayuOSAvatarUpload)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/accounts/avatar/remove", a.handleVayuOSAvatarRemove)
		// Prebuilt cartoon avatars: pick one instead of uploading (POST sets it),
		// with a GET preview endpoint that renders each option for this address.
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/accounts/avatar/cartoon", a.handleVayuOSAvatarCartoon)
		pr.Get("/os/vayumail/accounts/avatar/cartoon", a.handleVayuOSAvatarCartoonPreview)
		pr.Get("/os/vayumail/accounts/avatar", a.handleVayuOSAvatarServe)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/accounts/action", a.handleVayuOSAccountsAction)
		// Per-mailbox address book: view panel + add/delete + one-click save from a
		// message. Every route resolves the owning mailbox (contactOwner), so a
		// non-admin can only ever touch their own contacts.
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayumail/contacts", a.handleVayuOSContacts)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/contacts/add", a.handleVayuOSContactAdd)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/contacts/delete", a.handleVayuOSContactDelete)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/contacts/save", a.handleVayuOSContactSave)
		// Devices: GET fragment backs the self-refresh poller so a newly-registered
		// pending device surfaces without a reload.
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayumail/devices/fragment", a.handleVayuOSDevicesFragment)
		// App passwords — device credentials for VayuMail Mobile (and any
		// IMAP/SMTP/POP3 client). Created/revoked from the Connect tab; an admin
		// manages any mailbox, a mailbox holder only their own (enforced in the
		// handlers). Same session+CSRF chain as the TOTP route above.
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/accounts/apppassword", a.handleVayuOSAppPasswordCreate)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/accounts/apppassword/delete", a.handleVayuOSAppPasswordDelete)
		// Device approval (ADR-0129) — approve/block/remove registered devices
		// and toggle per-mailbox enforcement. Admin-only (enforced in the
		// handler): the 2FA-protected console IS the approval anchor, so mailbox
		// holders can never approve their own devices.
		pr.With(auth.CSRFTokenMiddleware).Post("/os/vayumail/devices/action", a.handleVayuOSDeviceAction)

		// VayuTalk — its own top-level system (NOT a VayuMail sub-tab): ephemeral
		// E2E chat over the same relay the mobile app uses. The page + send POST
		// are CSRF/session guarded; the SSE stream is a GET authenticated by the
		// session cookie (EventSource can't set headers), server-side-decrypting
		// each envelope for the signed-in mailbox.
		pr.With(auth.CSRFTokenMiddleware).Get("/os/talk", a.handleVayuOSTalk)
		pr.Get("/os/talk/stream", a.handleVayuOSTalkStream)
		pr.Get("/os/talk/peer", a.handleVayuOSTalkPeer)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/talk/send", a.handleVayuOSTalkSend)
		// Tor world: mint a fresh anonymous chat handle (ADR-0141).
		pr.With(auth.CSRFTokenMiddleware).Post("/os/talk/rotate", a.handleVayuOSTalkRotate)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/talk/federation", a.handleVayuOSTalkFederationToggle)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/talk/read", a.handleVayuOSTalkRead)

		// VayuTor — onion services control page + one-click toggle + count JSON.
		// VayuVeil (ADR-0150) — the endpoint observation-control console. Admin-only
		// via osPathMinLevel: it enumerates device nodes, display sockets and kernel
		// tunables on the host, which is operator information rather than author
		// information.
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayuveil", a.handleOSVayuVeil)
		pr.With(auth.CSRFTokenMiddleware).Get("/os/vayuflow", a.handleOSVayuFlow)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayuveil/toggle", a.handleOSVayuVeilToggle)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayuveil/harden", a.handleOSVeilHardenRequest)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayuflow/arm", a.handleOSVayuFlowArm)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayuflow/run", a.handleOSVayuFlowRun)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayuflow/save", a.handleOSVayuFlowSave)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayuflow/enable", a.handleOSVayuFlowEnable)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayuflow/delete", a.handleOSVayuFlowDelete)
		pr.With(auth.CSRFTokenMiddleware).Get("/os/tor", a.handleOSTor)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/tor/toggle", a.handleOSTorToggle)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/tor/bridges", a.handleOSTorBridges)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/tor/pagestats", a.handleOSTorPageStats)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/tor/hardening", a.handleOSTorHardening)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/tor/vanity", a.handleOSTorVanity)
		pr.Get("/os/tor/stats", a.handleOSTorStats)

		pr.Get("/os/vayumail/security", a.handleVayuOSSecurity)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/vayuos/security/check", a.handleVayuOSSecurityCheck)
		pr.Get("/os/api/vayuos/health", a.handleVayuOSHealthJSON)
		// "My site" — the agency client's own page (ADR-0152). Declared in
		// clientSurface; every other /os route is refused to a client by default.
		pr.Get("/os/mysite", a.handleOSMySite)
		pr.Get("/os/mysite/traffic", a.handleOSMySiteTraffic)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/mysite/brand", a.handleOSMySiteBrand)
		pr.Get("/os/settings", a.handleOSSettings)
		pr.Get("/os/settings/{group}", a.handleOSSettings)

		// API Keys console — VayuPress's own rotatable bearer tokens plus
		// encrypted third-party service credentials (IndexNow, OpenRouter,
		// Ollama, n8n, custom).
		pr.Get("/os/apikeys", a.handleOSAPIKeys)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/apikeys/create", a.handleOSAPIKeyCreate)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/apikeys/rotate", a.handleOSAPIKeyRotate)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/apikeys/revoke", a.handleOSAPIKeyRevoke)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/apikeys/delete", a.handleOSAPIKeyDelete)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/apikeys/activate", a.handleOSAPIKeySetActive(true))
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/apikeys/deactivate", a.handleOSAPIKeySetActive(false))
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/credentials/save", a.handleOSCredentialSave)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/credentials/reveal", a.handleOSCredentialReveal)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/credentials/delete", a.handleOSCredentialDelete)

		// VayuMCP (ADR-0139, Stage 2): the one-click front door for
		// connecting Claude/MCP clients. GET-only — it mints and revokes through
		// the CSRF-protected API-key endpoints above, adding no new write surface.
		pr.Get("/os/connector", a.handleOSConnector)

		// Buzz connector (ADR-0146): the same MCP surface, walked through for a
		// Buzz agent. GET-only for the same reason — it mints through the
		// CSRF-protected API-key endpoints above and adds no write surface of
		// its own.
		pr.Get("/os/buzz", a.handleOSBuzz)

		// Claude Code connector (ADR-0147): the Claude-specific routes in, split
		// off /os/connector so the protocol page stops answering a question
		// nobody asked. GET-only, same reasoning as above.
		pr.Get("/os/claudecode", a.handleOSClaudeCode)

		// VayuOS Spaces (ADR-0141): the Clearnet/Tor worlds + the one-click
		// Anonymous Tor Space toggle. The GET is wrapped in CSRFTokenMiddleware so
		// loading the page (re)issues the vp_csrf cookie the toggle POST reads back
		// — without this the toggle 403s on a fresh session / after a restart or the
		// 1h cookie lifetime, and reloading never recovers it (mirrors /os/tor,
		// /os/shield). The toggle POST is CSRF-checked.
		pr.With(auth.CSRFTokenMiddleware).Get("/os/spaces", a.handleOSSpaces)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/spaces/toggle", a.handleOSSpaceToggle)

		// CSRF-protected writes
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/seo/regenerate", a.handleSEORegenerate)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/seo/indexnow-test", a.handleOSIndexNowTest)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/settings", a.handleOSSettingsAPI)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/posts/quick-create", a.handleOSQuickCreatePost)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/posts/status", a.handleOSPostStatus)
	// One-request bulk apply for the Posts manager (Wave 4): per-slug outcomes,
	// in-place row updates and honest tab counts instead of N parallel fetches
	// and a blind full-page reload.
	pr.With(auth.CSRFTokenMiddleware).Post("/os/api/posts/bulk", a.handleOSPostsBulk)
		// HTMX in-place publish/unpublish toggle: returns an HTML row fragment
		// (flipped button + out-of-band status pill) instead of JSON, so the
		// Posts manager updates the row without a full-page reload.
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/posts/{slug}/status-fragment", a.handleOSPostToggleFragment)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/posts/{slug}/indexnow-fragment", a.handleOSPostIndexNowFragment)
		// Signed draft-share link (Wave 4.4): the editor's Share button mints a
		// 48h preview token through the same signer the API uses, so a draft
		// reaches a reviewer without becoming public.
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/posts/{slug}/share", a.handleOSPostShare)
		// HTMX in-place pin/unpin: returns the flipped pin button + an out-of-band
		// "Pinned" badge, so the row updates without a full-page reload.
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/posts/{slug}/pin-fragment", a.handleOSPostPinFragment)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/posts/pin", a.handleOSPostPin)
		pr.With(auth.CSRFTokenMiddleware).Delete("/os/api/posts/{slug}", a.handleOSPostDelete)
		// Session-friendly branding (favicon) upload — the /admin/theme/favicon
		// original is in the API-key-only group, so a browser operator can't reach
		// it. This mirror is gated by requireSessionOrAPIKey + CSRF.
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/branding/favicon", a.handleFaviconUpload)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/branding/hero", a.handleHeroUpload)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/branding/og", a.handleOGUpload)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/editor/save", a.handleOSEditorSave)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/editor/preview", a.handleOSEditorPreview)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/editor/import", a.handleOSEditorImport)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/editor/slug", a.handleOSEditorSlug)
		// Session-friendly mirrors of the editor's block tools (the /api/v1/admin
		// originals require an API key; os operators hold a session cookie).
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/embed/unfurl", a.handleEmbedUnfurl)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/diagram/preview", a.handleDiagramPreview)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/editor/ai", a.handleOSEditorAI)
		pr.Get("/os/api/editor/ai-providers", a.handleOSEditorAIProviders)
		pr.Get("/os/api/editor/ai-models", a.handleOSEditorAIModels)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/editor/generate", a.handleOSEditorGenerate)
		// Generation is a background job; the panel polls this for the result. It is
		// a plain GET like the other editor reads — the job id is unguessable and
		// owner-checked, so there is no state change to protect with a CSRF token.
		pr.Get("/os/api/editor/generate/status", a.handleOSEditorGenerateStatus)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/editor/convert", a.handleOSEditorConvert)
		pr.Get("/os/api/editor/versions/{slug}", a.handleOSEditorVersionList)
		pr.Get("/os/api/editor/versions/{slug}/{id}", a.handleOSEditorVersionGet)
		// Restore rewinds the article to a snapshot — a write, so CSRF-gated like
		// the save it mirrors.
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/editor/versions/{slug}/{id}/restore", a.handleOSEditorVersionRestore)

		// Read-only APIs (no CSRF needed)
		pr.Get("/os/api/activity", a.handleOSActivity)
		pr.Get("/os/api/cmd-index", a.handleOSCmdIndex)
		pr.Get("/os/api/search/drift", a.handleSearchDrift)

		// Interactive operator consoles — rendered in the VayuOS shell.
		// These were previously in the RequireAPIKey group in routes.go, which
		// caused a 401 JSON error when visited from a browser (no API key header).
		// They belong here under requireSessionOrAPIKey so a browser session works.
		pr.Get("/os/modes", a.handleModesPage)
		pr.Get("/os/faults", a.handleFaultPage)
		pr.Get("/os/topology", a.handleTopologyPage)
		pr.Get("/os/replay", a.handleReplayPage)
		pr.Get("/os/policy", a.handlePolicyPage)
		pr.Get("/os/adr", a.handleAdminADR)

		// Operator-initiated actions. API-key callers hold no browser session and
		// bypass CSRF (auth.CSRFTokenMiddleware exempts API-key auth); these two
		// endpoints have no browser-form caller (the panel's regenerate button hits
		// /os/api/seo/regenerate), so wrapping them in CSRF middleware hardens the
		// session lane without SameSite being the sole control (audit L2).
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/search/reindex", a.handleOSSearchReindex)
		pr.With(auth.CSRFTokenMiddleware).Post("/os/api/feed/regenerate", a.handleOSFeedRegenerate)
	})

	// Redirect bare /os/* to dashboard if hitting unknown paths
	r.Get("/os/*", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/os", http.StatusSeeOther)
	})
}

func serveAdminOSAsset(rel, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=3600")
		diskPath := filepath.Join(adminOSStaticDir(), filepath.FromSlash(rel))
		if _, err := os.Stat(diskPath); err == nil {
			http.ServeFile(w, req, diskPath)
			return
		}
		// The on-disk copy is missing — e.g. STATIC_DIR was never provisioned, or
		// is read-only under a hardened service sandbox so syncEmbeddedStatic
		// could not write it. Serve the copy compiled into the binary so the
		// panel always works, even immediately after a one-click self-update.
		if data, err := fs.ReadFile(embeddedStaticFS, rel); err == nil {
			http.ServeContent(w, req, filepath.Base(rel), time.Time{}, bytes.NewReader(data))
			return
		}
		http.NotFound(w, req)
	}
}

// assetVerCache memoises per-asset cache-busting tokens.
var assetVerCache sync.Map // rel -> string

// assetVer returns a cache-busting query value for a VayuOS static asset that
// combines the release Version with a short content hash of the file. Because
// it tracks file content, browsers refetch CSS/JS as soon as it actually
// changes — even between builds that share the same release Version — while
// still caching aggressively when nothing changed.
func assetVer(rel string) string {
	if v, ok := assetVerCache.Load(rel); ok {
		return v.(string)
	}
	v := Version
	b, err := os.ReadFile(filepath.Join(adminOSStaticDir(), filepath.FromSlash(rel)))
	if err != nil {
		// Fall back to the embedded copy so the cache-buster still tracks the
		// shipped asset content when STATIC_DIR is unavailable (ADR-0099).
		b, err = fs.ReadFile(embeddedStaticFS, rel)
	}
	if err == nil {
		sum := sha256.Sum256(b)
		v = Version + "-" + hex.EncodeToString(sum[:4])
	}
	assetVerCache.Store(rel, v)
	return v
}

// ── Shared layout ────────────────────────────────────────────────────────────

// navItem builds a sidebar nav link with an inline SVG icon.
func navItem(href, label, key, active, iconSVG string) string {
	return navItemBadge(href, label, key, active, iconSVG, 0)
}

// navItemBadge is navItem with an optional unread-count pill. A count <= 0
// renders no badge; counts over 99 cap at "99+" so the pill stays compact.
func navItemBadge(href, label, key, active, iconSVG string, count int) string {
	cls := "nav-link"
	if key == active {
		cls += " active"
	}
	badge := ""
	if count > 0 {
		txt := intToStr(count)
		if count > 99 {
			txt = "99+"
		}
		badge = `<span class="nav-badge" aria-label="` + txt + ` unread">` + txt + `</span>`
	}
	// data-nav carries the section key so the stylesheet can give each item its
	// own premium accent colour (icon-shaped glow on hover). key is an internal
	// constant, but escape it anyway — defence in depth for the attribute context.
	return `<a class="` + cls + `" href="` + href + `" data-nav="` + html.EscapeString(key) + `">` +
		`<span class="nav-link__ico">` + iconSVG + `</span>` +
		`<span class="nav-link__label">` + html.EscapeString(label) + `</span>` +
		badge +
		`</a>`
}

// spaceSwitch renders the one-click Clearnet⟷Tor world switch pinned to the top
// of the sidebar (ADR-0141). Admin-only — returns "" for every lower role. On a
// clearnet install it is interactive: clicking the inactive segment enables or
// disables the Anonymous Tor Space (the data-space-switch handler primes the CSRF
// cookie, then POSTs /os/spaces/toggle). On a whole-install Tor world it is a
// static indicator (you cannot turn a dedicated Tor install back to clearnet from
// here — that is a separate install). CSP-safe: no inline styles or handlers, all
// behaviour is wired by data attributes in the nonce-gated foot script.
func spaceSwitch(lvl int, _ *osSettings) string {
	if lvl < accessAdmin {
		return ""
	}
	if config.Cfg.OnionMode {
		// This install IS the Tor world. The Clearnet segment is ALWAYS a real link
		// back to /os/world?target=clearnet — when managed from the parent console
		// the parent intercepts it and drops the Tor view; opened directly at the
		// .onion in Tor Browser the child's own handler just redirects to /os (a
		// harmless no-op). Rendering it unconditionally guarantees there is never a
		// dead-end "stuck in Tor" state, regardless of how the child was launched.
		// The live .onion address itself is surfaced on the DASHBOARD now (world
		// card), not crammed under the switch — the toggle stays a clean control.
		return `<div class="space-switch-wrap">
  <div class="space-switch" data-active="tor" role="group" aria-label="Active world">
    <span class="space-switch__thumb" aria-hidden="true"></span>
    <a class="space-switch__seg" data-world="clearnet" href="/os/world?target=clearnet">` + iconWorldClearnet + `<span>Clearnet</span></a>
    <span class="space-switch__seg is-active" data-world="tor" aria-current="true">` + iconWorldTor + `<span>Tor</span></span>
  </div>
  <a class="space-switch__manage" href="/os/spaces">Manage worlds<span aria-hidden="true"> →</span></a>
</div>`
	}
	// This is the CLEARNET console (not OnionMode): rendering it at all means the
	// operator is currently VIEWING clearnet — viewing Tor proxies to the child's
	// own console instead. So Clearnet is ALWAYS the active segment and Tor is
	// ALWAYS the click-to-enter one, regardless of whether the Tor world happens to
	// be running. (Basing "active" on whether the Space was enabled made Tor look
	// selected while you were still on clearnet, so clicking it did nothing.)
	//
	// The anonymous world's live status + .onion address are shown on the DASHBOARD
	// (the world card), not under the switch — the toggle is just the world control.
	// data-space-switch on a segment = "clicking me switches to this world":
	// "on" enters the Tor world (this console proxies into it), "off" stays here.
	return `<div class="space-switch-wrap">
  <div class="space-switch" data-active="clearnet" role="group" aria-label="Switch world">
    <span class="space-switch__thumb" aria-hidden="true"></span>
    <button type="button" class="space-switch__seg is-active" data-space-switch="off" data-world="clearnet" aria-pressed="true">` + iconWorldClearnet + `<span>Clearnet</span></button>
    <button type="button" class="space-switch__seg" data-space-switch="on" data-world="tor" aria-pressed="false">` + iconWorldTor + `<span>Tor</span></button>
  </div>
  <a class="space-switch__manage" href="/os/spaces">Manage worlds<span aria-hidden="true"> →</span></a>
</div>`
}

// osGroupInt formats an integer with thousands separators (234465 → "234,465")
// so large counts read cleanly on the premium dashboard tiles.
func osGroupInt(n int) string {
	s := strconv.Itoa(n)
	neg := ""
	if n < 0 {
		neg, s = "-", s[1:]
	}
	var out []byte
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, s[i])
	}
	return neg + string(out)
}

// osBadgeCount renders a compact notification count, capping over 99 at "99+".
func osBadgeCount(n int) string {
	if n > 99 {
		return "99+"
	}
	return strconv.Itoa(n)
}

// osWorkCard renders one clickable workspace tile for the dashboard: an icon, a
// title with an optional count, a short description and an optional notification
// badge (pending comments / unread messages). These tiles ARE the content
// navigation — the areas that used to sit in the sidebar are reached from here.
func osWorkCard(href, title, desc, iconSVG string, count int, badge string, accent bool) string {
	iconCls := "work-card__icon"
	if accent {
		iconCls += " work-card__icon--accent"
	}
	countHTML := ""
	if count > 0 {
		countHTML = ` <span class="work-card__count">` + osGroupInt(count) + `</span>`
	}
	badgeHTML := ""
	if badge != "" {
		badgeHTML = ` <span class="work-card__badge">` + html.EscapeString(badge) + `</span>`
	}
	return `<a class="work-card" href="` + href + `">
  <span class="` + iconCls + `">` + iconSVG + `</span>
  <span class="work-card__body">
    <span class="work-card__title">` + html.EscapeString(title) + countHTML + badgeHTML + `</span>
    <span class="work-card__desc">` + html.EscapeString(desc) + `</span>
  </span>
  <svg class="work-card__arrow" width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M6 3l5 5-5 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
</a>`
}

// osWorkspaceGrid renders the dashboard's content workspace — the Posts, Pages,
// Comments, Messages, Media and New Post tiles (plus Website on clearnet) that
// used to live in the sidebar — each with its live count and, where relevant, a
// notification badge. The clearnet-only Website tile is omitted in the Tor world.
//
// accessLevel gates every tile the same way the sidebar gates its items
// (lvl < osPathMinLevel(href) ⇒ hidden): showing a tile the viewer cannot open
// was a silent-denial loop waiting to happen — RBAC shown==reachable parity.
func osWorkspaceGrid(onion bool, blogPosts, pages, pendingComments, unread, media, accessLevel int) string {
	gate := func(item, href string) string {
		if accessLevel < osPathMinLevel(href) {
			return ""
		}
		return item
	}
	var b strings.Builder
	b.WriteString(`<div class="section-head"><span class="section-head__title">Workspace</span><span class="section-head__hint">Everything you manage, in one place</span></div>`)
	b.WriteString(`<div class="work-grid">`)
	b.WriteString(gate(osWorkCard("/os/editor", "New Post", "Start writing a new story", iconNewPost, 0, "", true), "/os/editor"))
	b.WriteString(gate(osWorkCard("/os/posts", "Posts", "Manage & edit your posts", iconPosts, blogPosts, "", false), "/os/posts"))
	b.WriteString(gate(osWorkCard("/os/pages", "Pages", "Standalone pages", iconPages, pages, "", false), "/os/pages"))
	cBadge := ""
	if pendingComments > 0 {
		cBadge = osBadgeCount(pendingComments)
	}
	b.WriteString(gate(osWorkCard("/os/comments", "Comments", "Moderate reader comments", iconComments, 0, cBadge, false), "/os/comments"))
	mBadge := ""
	if unread > 0 {
		mBadge = osBadgeCount(unread)
	}
	b.WriteString(gate(osWorkCard("/os/messages", "Messages", "Contact-form inbox", iconMessages, 0, mBadge, false), "/os/messages"))
	b.WriteString(gate(osWorkCard("/os/media", "Media", "Images & uploads", iconMedia, media, "", false), "/os/media"))
	if !onion {
		b.WriteString(gate(osWorkCard("/os/website", "Website", "Site identity & layout", iconPages, 0, "", false), "/os/website"))
	}
	b.WriteString(`</div>`)
	return b.String()
}

// osWorldCard surfaces the Anonymous Tor world's live status + .onion on the
// dashboard (moved off the sidebar toggle). On the clearnet console a running
// Space shows its address with a copy button + an "Enter Tor world" link, and a
// booting Space shows a "starting" state. In the Tor world itself (onion) it shows
// "you're in the Tor world" with this install's own .onion. Returns "" when there
// is nothing to show (clearnet with the Space off).
func osWorldCard(onion, torOn, running bool, addr string) string {
	if onion {
		if addr == "" {
			return ""
		}
		esc := html.EscapeString(addr)
		return `<div class="world-card">
  <span class="world-card__dot"></span>
  <span class="world-card__text">
    <span class="world-card__title">You're in the Anonymous Tor world</span>
    <span class="world-card__addr">` + esc + `</span>
  </span>
  <span class="world-card__actions">
    <button type="button" class="btn btn--ghost btn--sm" data-copy="http://` + esc + `">Copy .onion</button>
    <a class="btn btn--ghost btn--sm" href="/os/world?target=clearnet">Back to Clearnet →</a>
  </span>
</div>`
	}
	if !torOn {
		return ""
	}
	if running && addr != "" {
		esc := html.EscapeString(addr)
		return `<div class="world-card">
  <span class="world-card__dot"></span>
  <span class="world-card__text">
    <span class="world-card__title">Anonymous Tor world is live</span>
    <span class="world-card__addr">` + esc + `</span>
  </span>
  <span class="world-card__actions">
    <button type="button" class="btn btn--ghost btn--sm" data-copy="http://` + esc + `">Copy .onion</button>
    <a class="btn btn--ghost btn--sm" href="/os/world?target=tor">Enter Tor world →</a>
  </span>
</div>`
	}
	return `<div class="world-card">
  <span class="world-card__dot world-card__dot--warn"></span>
  <span class="world-card__text">
    <span class="world-card__title">Starting your anonymous world…</span>
    <span class="world-card__addr">Publishing its .onion — this can take a minute.</span>
  </span>
</div>`
}

// notifCap clamps a badge count to a compact "99+" so a large backlog never
// blows out the bell badge or a row's count chip.
func notifCap(n int) string {
	if n > 99 {
		return "99+"
	}
	return strconv.Itoa(n)
}

// notifIcon maps a notification kind to its glyph. The kind is a fixed literal
// from osNotifications (never user input), so it also doubles as the accent
// modifier class on the icon chip.
func notifIcon(kind string) string {
	switch kind {
	case "mail":
		return iconMail
	case "comment":
		return iconComments
	case "message":
		return iconMessages
	case "domain":
		return iconDomains
	case "update":
		return iconUpdate
	default:
		return iconBell
	}
}

// osNotifItem renders one notification as a clickable row that navigates straight
// to the page which clears it (a plain <a>, so no JS is needed for the jump).
func osNotifItem(n osNotification) string {
	// Most items read "<count> <detail>" (e.g. "3 unread in your inbox"); the
	// update notice is a single event, so it shows its detail verbatim.
	detail := n.Detail
	if n.Kind != "update" {
		detail = notifCap(n.Count) + " " + n.Detail
	}
	return `<a class="notif-item" href="` + n.Href + `">
  <span class="notif-item__icon notif-item__icon--` + n.Kind + `">` + notifIcon(n.Kind) + `</span>
  <span class="notif-item__body">
    <span class="notif-item__title">` + html.EscapeString(n.Title) + `</span>
    <span class="notif-item__detail">` + html.EscapeString(detail) + `</span>
  </span>
  <span class="notif-item__count">` + notifCap(n.Count) + `</span>
</a>`
}

// osNotifBell renders the topbar notification centre (the bell that replaced the
// New Post shortcut): a button with a live count badge and an expandable panel
// listing every actionable item, each a direct link to the page that clears it.
// The panel is present on every admin page; the toggle is wired CSP-safely in
// admin-os.js (initNotifications). Rendered identically in both worlds.
func osNotifBell(s *osSettings) string {
	var notifs []osNotification
	if s != nil {
		notifs = s.Notifications
	}
	total := 0
	hasDanger := false
	for _, n := range notifs {
		total += n.Count
		if n.Severity == "danger" {
			hasDanger = true
		}
	}
	badge, headCount, activeCls := "", "", ""
	if total > 0 {
		// The badge wears its worst severity (Wave 2.2): ten failed jobs must
		// read as an alarm, not as three pending comments.
		badgeCls := ""
		if hasDanger {
			badgeCls = " topbar-notif__badge--danger"
		}
		badge = `<span class="topbar-notif__badge` + badgeCls + `">` + notifCap(total) + `</span>`
		headCount = `<span class="topbar-notif__count">` + notifCap(total) + ` new</span>`
		activeCls = " topbar-notif__btn--active"
	}
	var list strings.Builder
	if len(notifs) == 0 {
		list.WriteString(`<div class="topbar-notif__empty">✨ You're all caught up</div>`)
	} else {
		for _, n := range notifs {
			list.WriteString(osNotifItem(n))
		}
	}
	return `<div class="topbar-notif" data-notif>
  <button type="button" class="btn--icon topbar-notif__btn` + activeCls + `" data-notif-toggle aria-haspopup="true" aria-expanded="false" aria-label="Notifications">
    ` + iconBell + badge + `
  </button>
  <div class="topbar-notif__panel" data-notif-panel hidden>
    <div class="topbar-notif__head"><span>Notifications</span>` + headCount + `</div>
    <div class="topbar-notif__list">` + list.String() + `</div>
  </div>
</div>`
}

// torWorldNav is the sidebar for the Tor world (OnionMode): a Tor-only console
// showing just the blog, the anonymous services (VayuMail·Tor, VayuTalk·Tor) and
// its onion Domains — no clearnet sections. Access-gated like the main nav.
func torWorldNav(active string, lvl int, s *osSettings) string {
	var b strings.Builder
	// Static "Tor world" indicator + copyable .onion at the top (spaceSwitch
	// renders the non-switchable indicator in OnionMode).
	b.WriteString(spaceSwitch(lvl, s))
	gate := func(item, href string) string {
		if lvl < osPathMinLevel(href) {
			return ""
		}
		return item
	}
	section := func(label string, items ...string) {
		shown := make([]string, 0, len(items))
		for _, it := range items {
			if it != "" {
				shown = append(shown, it)
			}
		}
		if len(shown) == 0 {
			return
		}
		b.WriteString(`<div class="sidebar-section-label">` + label + `</div>`)
		for _, it := range shown {
			b.WriteString(it)
		}
	}
	// Blog content (Posts, New Post, Pages, Comments, Media) lives INSIDE the
	// Dashboard workspace grid now — the same premium hub the clearnet console uses
	// — so the Tor sidebar stays a short, focused list. Theme (a design tool, not
	// content) stays pinned here.
	b.WriteString(gate(navItem("/os", "Dashboard", "dashboard", active, iconDashboard), "/os"))
	section("Design",
		gate(navItem("/os/theme", "Theme", "theme", active, iconTheme), "/os/theme"),
	)
	// Tor analytics: the visit count and which pages were visited — privacy-
	// preserving (aggregate counts only, no per-visitor data), served entirely from
	// the Tor world's own database. The /os/analytics handler already works in
	// OnionMode; it was only missing from this sidebar.
	section("Insights",
		gate(navItem("/os/analytics", "Analytics", "analytics", active, iconAnalytics), "/os/analytics"),
	)
	section("Anonymous services",
		navItem("/os/vayumail", "VayuMail", "vayuos", active, iconSecurity),
		navItem("/os/talk", "VayuTalk", "talk", active, iconTalk),
		gate(navItem("/os/domains", "Domains", "domains", active, iconDomains), "/os/domains"),
	)
	// System (Storage & System, Settings, My Profile) is consolidated into ONE
	// pinned hub tab too — the same card-hub treatment the clearnet console uses —
	// so both worlds share the identical minimal pattern (design parity, ADR-0141).
	b.WriteString(gate(navItem("/os/system", "System", "system", active, iconSettings), "/os/system"))
	return b.String()
}

// osSidebarNav builds the role-scoped sidebar. A mail-only session (mailbox /
// reviewer role) sees only its Mailbox and Profile; console sessions see only
// the sections their access level permits. The visibility rule is exactly the
// route guard (osPathMinLevel) so what is shown is precisely what is reachable —
// hidden items are also blocked server-side.
func osSidebarNav(active string, s *osSettings) string {
	lvl := accessAdmin
	mailOnly := false
	if s != nil {
		lvl = s.AccessLevel
		mailOnly = s.MailOnly
	}
	// An agency client (ADR-0152) is a console session, not a mail-only one, so
	// it fell through to the operator sidebar below — where every gate() closed
	// against its floor access level and the two ungated product links pointed at
	// pages the confinement refuses. The result was a customer with no link to
	// their own site at all: /os/mysite was reachable only by typing it.
	if s != nil && s.UserRole == roleClientName {
		return `<div class="sidebar-section-label">Your account</div>` +
			navItem("/os/mysite", "My site", "mysite", active, iconDomains) +
			navItem("/os/mysite/traffic", "Visitors", "mysite-traffic", active, iconAnalytics) +
			navItem("/os/vayumail/inbox", "Mailbox", "vayuos", active, iconSecurity) +
			navItem("/os/profile", "My Profile", "profile", active, iconMembers)
	}
	if mailOnly {
		return `<div class="sidebar-section-label">Mail</div>` +
			navItem("/os/vayumail/inbox", "Mailbox", "vayuos", active, iconSecurity) +
			navItem("/os/profile", "My Profile", "profile", active, iconMembers)
	}

	// The Tor world (OnionMode) is its OWN system — a separate database and
	// identity — so its console shows ONLY what belongs in the anonymous world:
	// the blog, VayuMail·Tor, VayuTalk·Tor and its onion Domains. Every
	// clearnet-only section (monetization, ads, newsletter, members, SEO/IndexNow,
	// VayuMCP, analytics, the ops panels…) is hidden, so it reads as a clean,
	// standalone Tor system (ADR-0141). The clearnet console is unchanged.
	if config.Cfg.OnionMode {
		return torWorldNav(active, lvl, s)
	}

	var b strings.Builder
	// One-click world switch pinned to the TOP of the sidebar (ADR-0141): flip the
	// install between the public Clearnet world and the Anonymous Tor Space in a
	// single click, from anywhere, with the live status + .onion shown inline (no
	// separate page). Admin-only (matches the /os/spaces guard).
	b.WriteString(spaceSwitch(lvl, s))
	// gate returns the item only when this access level can reach its href. The
	// clearnet sidebar is now a flat, label-less list of hub tabs + a few pinned
	// items (no "Products"/"System" section headings) — every grouping lives inside
	// a hub page (Dashboard, Growth, Optimize, Operations).
	gate := func(item, href string) string {
		if lvl < osPathMinLevel(href) {
			return ""
		}
		return item
	}

	// Content management (Posts, Pages, Comments, Messages, Media, New Post,
	// Website) now lives INSIDE the Dashboard as a premium workspace grid with live
	// counts + notification badges, so the sidebar stays focused on the broader
	// system areas. Only the Dashboard hub is pinned here.
	b.WriteString(gate(navItem("/os", "Dashboard", "dashboard", active, iconDashboard), "/os"))
	// Audience (Members, Newsletter, Profile) and Monetization (Monetization,
	// Advertising) are consolidated into ONE pinned Growth hub — a card grid with
	// live counts, mirroring the Dashboard pattern — so the sidebar stays minimal.
	// (My Profile also remains reachable from the sidebar footer avatar.)
	b.WriteString(gate(navItem("/os/growth", "Growth", "growth", active, iconGrowth), "/os/growth"))
	// Optimize hub. SEO, Analytics, VayuShield, Theme Studio, Theme Store AND the
	// everyday config surfaces (Tools & Plugins, Domains, Settings, VayuAPI, VayuMCP)
	// all live inside this one card page now.
	b.WriteString(gate(navItem("/os/optimize", "Optimize", "optimize", active, iconOptimize), "/os/optimize"))
	// Operations hub (ops/diagnostics + health/governance).
	b.WriteString(gate(navItem("/os/operations", "Operations", "operations", active, iconOperations), "/os/operations"))
	// Pinned, label-less: the products (opened often) and Update & Backup (the one
	// system surface kept a click away). Everything else folded into the hubs.
	b.WriteString(navItem("/os/vayumail", "VayuMail", "vayuos", active, iconSecurity))
	b.WriteString(navItem("/os/talk", "VayuTalk", "talk", active, iconTalk))
	b.WriteString(gate(navItem("/os/tor", "VayuTor", "tor", active, iconTor), "/os/tor"))
	b.WriteString(gate(navItem("/os/update", "Update & Backup", "update", active, iconUpdate), "/os/update"))
	return b.String()
}

// svgIcon returns a minimal inline SVG for the sidebar.
// Using path data keeps us CDN-free and avoids an extra HTTP round-trip.
func svgIcon(path string) string {
	return `<svg viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="` + path + `" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`
}

// World-switch glyphs shown inside the sidebar Clearnet⟷Tor switch: a globe for
// the public Clearnet world and a layered onion (the Tor mark) for the anonymous
// world, so each segment is recognisable at a glance. currentColor lets the
// stylesheet tint each in its own world accent.
const iconWorldClearnet = `<svg class="space-switch__ico" viewBox="0 0 16 16" width="14" height="14" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="6.1" stroke="currentColor" stroke-width="1.2"/><path d="M1.9 8h12.2M8 1.9v12.2M8 1.9c-2.3 1.7-2.3 10.5 0 12.2M8 1.9c2.3 1.7 2.3 10.5 0 12.2" stroke="currentColor" stroke-width="1.1"/></svg>`
const iconWorldTor = `<svg class="space-switch__ico" viewBox="0 0 16 16" width="14" height="14" fill="none" aria-hidden="true"><path d="M8 1.7c-.8.9-.8 1.8 0 2.7" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/><path d="M8 4c-2.9 0-4.9 2.5-4.9 5.3 0 2.6 2.2 4.9 4.9 4.9s4.9-2.3 4.9-4.9C12.9 6.5 10.9 4 8 4z" stroke="currentColor" stroke-width="1.2"/><path d="M8 4.3c-1.3 1.4-2 3.2-2 5s.7 3.4 2 4.8M8 4.3c1.3 1.4 2 3.2 2 5s-.7 3.4-2 4.8" stroke="currentColor" stroke-width="1"/></svg>`

var (
	iconDashboard  = svgIcon("M3 10.5L10 3l7 7.5M5 8.5V17h3.5v-4h3v4H15V8.5")
	iconPosts      = svgIcon("M4 4h12v2H4V4zm0 4h12v2H4V8zm0 4h8v2H4v-2z")
	iconComments   = svgIcon("M3 4h14v9H7l-4 3V4zm3 3h8M6 10h5")
	iconPages      = svgIcon("M5 2h7l3 3v13H5V2zm7 0v3h3M7 9h6M7 12h6M7 15h4")
	iconMessages   = svgIcon("M2 4h16v10H6l-4 3V4zm3 4h10M5 11h7")
	iconTalk       = svgIcon("M4 3h9a3 3 0 013 3v4a3 3 0 01-3 3H8l-4 3v-3a3 3 0 01-3-3V6a3 3 0 013-3zm2 4h7M6 9.5h4")
	iconDNS        = svgIcon("M10 2.5a7.5 7.5 0 100 15 7.5 7.5 0 000-15zM2.5 10h15M10 2.5c2 2.4 3 4.9 3 7.5s-1 5.1-3 7.5c-2-2.4-3-4.9-3-7.5s1-5.1 3-7.5z")
	iconTor        = svgIcon("M10 2.5a7.5 7.5 0 100 15 7.5 7.5 0 000-15zM10 6.5a3.5 3.5 0 100 7 3.5 3.5 0 000-7zM10 9.2a.8.8 0 100 1.6.8.8 0 000-1.6z")
	iconNewPost    = svgIcon("M10 4v12m-6-6h12")
	iconMedia      = svgIcon("M3 5a2 2 0 012-2h10a2 2 0 012 2v10a2 2 0 01-2 2H5a2 2 0 01-2-2V5zm0 8l4-4 3 3 2-2 4 4")
	iconMembers    = svgIcon("M13 6a3 3 0 11-6 0 3 3 0 016 0zm-9 10a6 6 0 1112 0H4z")
	iconNewsletter = svgIcon("M3 8l7-4 7 4v8a1 1 0 01-1 1H4a1 1 0 01-1-1V8zm7-1v9m-4-6h8")
	iconSEO        = svgIcon("M8 15A7 7 0 108 1a7 7 0 000 14zm5-1l4 4")
	iconAnalytics  = svgIcon("M3 17l4-8 4 4 4-6 4 4")
	iconGrowth     = svgIcon("M3 15l4-4 3 2 6-7m0 0h-3m3 0v3")
	iconOperations = svgIcon("M6 4v4M6 12v4M14 4v2M14 10v6M6 8a2 2 0 100 4 2 2 0 000-4zM14 6a2 2 0 100 4 2 2 0 000-4z")
	iconOptimize   = svgIcon("M10 3l1.8 4.2L16 9l-4.2 1.8L10 15l-1.8-4.2L4 9l4.2-1.8L10 3z")
	iconSettings   = svgIcon("M10 13a3 3 0 100-6 3 3 0 000 6zm0 0v1m0-8V5M4.2 4.2l.7.7m10-.7l-.7.7M3 10H2m16 0h-1M4.9 15.8l.7-.7m9.5.7l-.7-.7")
	iconSecurity   = svgIcon("M10 2l6 3v5c0 3.5-2.5 6.8-6 8-3.5-1.2-6-4.5-6-8V5l6-3z")
	iconTools      = svgIcon("M12.5 3.5a3 3 0 00-3.9 3.9l-5.1 5.1 2 2 5.1-5.1a3 3 0 003.9-3.9l-2 2-2-2 2-2z")
	iconUpdate     = svgIcon("M3 10a7 7 0 0112-4.9L17 7m0 0V3m0 4h-4M17 10a7 7 0 01-12 4.9L3 13m0 0v4m0-4h4")
	iconStorage    = svgIcon("M3 5a2 2 0 012-2h10a2 2 0 012 2v2H3V5zm0 4h14v6a2 2 0 01-2 2H5a2 2 0 01-2-2V9zm3 3h2")
	iconDomains    = svgIcon("M10 2a8 8 0 100 16 8 8 0 000-16zM2 10h16M10 2c2.2 2 3.3 4.9 3.3 8s-1.1 6-3.3 8c-2.2-2-3.3-4.9-3.3-8s1.1-6 3.3-8z")
	iconMonitoring = svgIcon("M2 10h3l2-5 3 11 3-8 2 2h3")
	iconGovernance = svgIcon("M10 2l7 3v5c0 3.5-2.8 6.8-7 8-4.2-1.2-7-4.5-7-8V5l7-3zm0 5v6m-3-3h6")
	iconTheme      = svgIcon("M10 2a8 8 0 100 16c1 0 1.5-.7 1.5-1.5 0-.4-.2-.8-.4-1-.3-.3-.4-.6-.4-1 0-.8.7-1.5 1.5-1.5H14a4 4 0 004-4c0-3.6-3.6-6.5-8-6.5zM5.5 10a1 1 0 110-2 1 1 0 010 2zm3-3a1 1 0 110-2 1 1 0 010 2zm5 0a1 1 0 110-2 1 1 0 010 2z")
	iconThemeStore = svgIcon("M3 7l1.5-3h11L17 7M3 7h14M3 7v9a1 1 0 001 1h12a1 1 0 001-1V7M8 7v3a2 2 0 004 0V7")
	iconModes      = svgIcon("M10 2l7 4v8l-7 4-7-4V6l7-4zm0 2.3L5 7v6l5 2.7L15 13V7l-5-2.7z")
	iconPolicy     = svgIcon("M10 2l6 3v5c0 3.5-2.5 6.8-6 8-3.5-1.2-6-4.5-6-8V5l6-3zm-1 9l4-4-1.4-1.4L9 8.2 7.4 6.6 6 8l3 3z")
	iconTopology   = svgIcon("M10 3a2 2 0 100 4 2 2 0 000-4zM4 13a2 2 0 100 4 2 2 0 000-4zm12 0a2 2 0 100 4 2 2 0 000-4zM10 7v3m0 0l-4 3m4-3l4 3")
	iconReplay     = svgIcon("M4 10a6 6 0 116 6m-6-6l-2-2m2 2l2-2m-2 8v-2")
	iconFaults     = svgIcon("M10 2l8 14H2L10 2zm0 5v4m0 3h.01")
	iconADR        = svgIcon("M5 3h7l3 3v11H5V3zm7 0v3h3M7 9h6m-6 3h6m-6 3h4")
	iconMoney      = svgIcon("M10 2v16M6.5 6.5h5a2 2 0 010 4h-3a2 2 0 000 4h5")
	iconAds        = svgIcon("M3 5h14v8H3V5zm2 11h6M6 8h6m-6 2.5h4")
	iconBell       = svgIcon("M10 3a4 4 0 00-4 4c0 4-2 5-2 5h12s-2-1-2-5a4 4 0 00-4-4zm-1.5 13a1.5 1.5 0 003 0")
	iconMail       = svgIcon("M3 5h14v10H3V5zm0 1l7 5 7-5")
	// iconApps is the mobile bottom-nav "Menu" affordance — a 2x2 grid that
	// reads as "all sections", opening the full role-scoped drawer.
	iconApps = svgIcon("M3 3h6v6H3V3zm8 0h6v6h-6V3zM3 11h6v6H3v-6zm8 0h6v6h-6v-6z")
)

// renderTrustedHTML emits a pre-constructed, server-side HTML fragment verbatim.
// The page body is assembled from fixed templates with every interpolated user
// value escaped via html.EscapeString at construction, so it is already safe.
//
// It is intentionally a plain string conversion — NOT an html/template
// execution. Passing a template.HTML value into html/template's Execute is what
// CodeQL flags as an "escaping bypass" (go/html-template-escaping-bypass), and
// since the passthrough emits the bytes unchanged either way, the direct
// conversion is equivalent and keeps the data off the html/template sink.
func renderTrustedHTML(h htmpl.HTML) string {
	return string(h)
}

// adminOSLayout renders the shared chrome for VayuOS.
// The nonce is injected into the single inline bootstrap <script> block.
// All CSS/JS are external same-origin files. No inline styles.
//
// It is composed from adminOSShellHead + the body + adminOSShellFoot so that
// streaming operator pages (System Modes, Policy, Topology, Replay, Faults,
// ADRs) can share the exact same VayuOS chrome without buffering their whole
// body — they call the head/foot helpers directly.
func adminOSLayout(nonce, title, active string, settings *osSettings, bodyHTML htmpl.HTML) string {
	return adminOSShellHead(nonce, title, active, settings) +
		renderTrustedHTML(bodyHTML) +
		adminOSShellFoot(nonce, "", pageUsesAlpine(string(bodyHTML)), pageUsesPurify(string(bodyHTML)))
}

// pageUsesAlpine reports whether a rendered admin page body hosts an Alpine
// island (an x-data component), so adminOSShellFoot loads the Alpine runtime
// only where it is actually used (ADR-0136). Any page that gains an island is
// covered automatically — no per-page bookkeeping to drift out of sync.
func pageUsesAlpine(body string) bool { return strings.Contains(body, "x-data") }

// pageUsesPurify reports whether a rendered admin page body is a block-editor
// page (the canvas marker only the editor renders), so adminOSShellFoot loads
// DOMPurify — which only the editor's client code uses — on exactly those pages.
func pageUsesPurify(body string) bool { return strings.Contains(body, "data-editor-canvas") }

// adminOSShellHead emits the VayuOS document head, sidebar, topbar and the
// opening <main class="content"> tag. The caller appends body content and then
// adminOSShellFoot.
// vpConfirm is the shared CSP-safe confirmation dialog (Wave 3.11): a real
// focus-aware modal built with createElement and textContent only — the
// browser-native confirm() is an unstyled chrome blob that cannot say what will
// happen and blocks the whole tab. Defined in the foot's bootstrap script so
// the per-page operator scripts (which run before admin-os.js) can use it too.
// message/labels must be plain text; they are set via textContent.
const vpConfirmScript = `window.vpConfirm=function(opts,onYes){
  var lastFocus=document.activeElement;
  var backdrop=document.createElement('div');backdrop.className='vp-confirm-backdrop';
  var box=document.createElement('div');box.className='vp-confirm';box.setAttribute('role','alertdialog');box.setAttribute('aria-modal','true');
  var t=document.createElement('div');t.className='vp-confirm__title';t.textContent=opts.title||'Are you sure?';
  var m=document.createElement('div');m.className='vp-confirm__msg';if(opts.message)m.textContent=opts.message;
  var row=document.createElement('div');row.className='vp-confirm__row';
  var cancel=document.createElement('button');cancel.type='button';cancel.className='btn btn--ghost btn--sm';cancel.textContent=opts.cancel||'Cancel';
  var ok=document.createElement('button');ok.type='button';ok.className='btn btn--danger btn--sm';ok.textContent=opts.confirm||'Confirm';
  row.appendChild(cancel);row.appendChild(ok);
  box.appendChild(t);if(opts.message)box.appendChild(m);box.appendChild(row);backdrop.appendChild(box);
  function close(){if(backdrop.parentNode)backdrop.parentNode.removeChild(backdrop);document.removeEventListener('keydown',onKey);if(lastFocus&&lastFocus.focus)lastFocus.focus();}
  function onKey(e){if(e.key==='Escape'){e.preventDefault();close();}else if(e.key==='Tab'){var f=[ok,cancel];var i=f.indexOf(document.activeElement);e.preventDefault();f[(i+1)%2].focus();}}
  cancel.addEventListener('click',close);
  backdrop.addEventListener('click',function(e){if(e.target===backdrop)close();});
  ok.addEventListener('click',function(){close();if(onYes)onYes();});
  document.addEventListener('keydown',onKey);
  document.body.appendChild(backdrop);
  ok.focus();
};`

// osThemeColorMetas renders the browser-chrome theme-colour meta for the
// console's resolved theme (Wave 2.8 login polish). A fixed dark value lied to
// light-theme and auto operators: the mobile browser chrome stayed near-black
// over a near-white console. A "light"/"dark" theme renders its one honest
// value; "auto" (the default) genuinely follows the OS, so it renders BOTH
// media-scoped values and lets the browser pick per system preference.
func osThemeColorMetas(theme string) string {
	dark, light := "#080e1a", "#f8fafc"
	switch theme {
	case "light":
		return `<meta name="theme-color" content="` + light + `">`
	case "dark":
		return `<meta name="theme-color" content="` + dark + `">`
	default: // "auto" — the OS decides, so both are declared
		return `<meta name="theme-color" media="(prefers-color-scheme: dark)" content="` + dark + `">` +
			`<meta name="theme-color" media="(prefers-color-scheme: light)" content="` + light + `">`
	}
}

func adminOSShellHead(nonce, title, active string, settings *osSettings) string {
	et := html.EscapeString(title)
	theme := "auto" // follow the operating system by default (clean/light on light OS)
	if settings != nil && settings.AdminTheme != "" {
		theme = settings.AdminTheme
	}
	siteName := "VayuPress"
	if settings != nil && settings.SiteName != "" {
		siteName = html.EscapeString(settings.SiteName)
	}
	// data-space="tor" repaints the shell in the Tor (purple) palette ONLY when the
	// console being shown IS the Tor world (OnionMode) — i.e. when you are VIEWING
	// Tor. The clearnet console keeps its own colour even while the Tor world is
	// enabled/running in the background; entering the Tor world proxies to that
	// instance, which renders purple itself. Tying the colour to "Tor is enabled"
	// (rather than "viewing Tor") wrongly painted the clearnet console purple
	// (ADR-0141).
	spaceAttr := ""
	if config.Cfg.OnionMode {
		spaceAttr = ` data-space="tor"`
	}

	cmdHint := `<button class="topbar-cmd" aria-label="Command palette" title="Open command palette">
      <svg viewBox="0 0 20 20" fill="none" width="14" height="14" aria-hidden="true"><path d="M8 15A7 7 0 108 1a7 7 0 000 14zm5-1l4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
      <span class="topbar-cmd-text">Search or jump…</span>
      <kbd>⌘K</kbd>
    </button>`

	// The topbar's primary affordance is now the notification centre (bell +
	// expandable panel), not a New Post button: every actionable signal in the
	// system surfaces here, each a direct link to the page that clears it. New Post
	// still lives on the dashboard workspace and the command palette.
	notifBell := osNotifBell(settings)

	// Feedback affordance: a topbar button that opens the VayuMail composer in
	// feedback mode (recipient pre-filled, structured template, PGP pre-enabled).
	// On hover/focus a small premium popover explains what it's for. Rendered in
	// the shared shell, so it appears identically in the clearnet and Tor consoles.
	feedbackBtn := `<div class="topbar-feedback" data-feedback>
      <a class="btn--icon topbar-feedback__btn" href="/os/vayumail/compose?feedback=1" aria-label="Report a bug or suggest an improvement" title="Report a bug · request a feature">
        <svg viewBox="0 0 20 20" width="18" height="18" fill="none" aria-hidden="true"><path d="M10 2.4a5.2 5.2 0 00-3.1 9.36c.44.33.7.86.72 1.42l.02.62h4.72l.02-.62c.02-.56.28-1.09.72-1.42A5.2 5.2 0 0010 2.4z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M8 16.4h4M8.6 18h2.8" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>
      </a>
      <div class="topbar-feedback__pop" role="tooltip">
        <div class="topbar-feedback__title">💡 Help improve VayuPress</div>
        <p class="topbar-feedback__desc">Found a bug, want an improvement, or have a feature idea? Tell us — it opens a PGP-encrypted email (attachments included) where you can add screenshots or files.</p>
        <span class="topbar-feedback__cta">Report a bug · request a feature →</span>
      </div>
    </div>`

	// Space-mode indicator (ADR-0141): every admin page carries an unmistakable
	// badge for the world this whole install controls — a CLEARNET Space (public
	// HTTPS domain) or a TOR Space (anonymous .onion, clearnet callbacks off) — so
	// the two are never confused. The mode is fixed per install by VAYUOS_MODE, so
	// this is a read-only status label, not a toggle.
	spaceBadge := `<span class="space-badge space-badge--clearnet" title="Clearnet Space — served over HTTPS on your public domain">Clearnet</span>`
	if config.Cfg.OnionMode {
		spaceBadge = `<span class="space-badge space-badge--tor" title="Tor Space — anonymous .onion world; clearnet callbacks disabled">Tor</span>`
	}

	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + et + ` — ` + siteName + ` · VayuOS</title>
<meta name="robots" content="noindex, nofollow">
<!-- HTMX runtime config: skip the injected indicator <style> so we never need
     style-src 'unsafe-inline' — the strict admin CSP (style-src 'self') stays intact. -->
<meta name="htmx-config" content='{"includeIndicatorStyles":false,"globalViewTransitions":true}'>
<link rel="stylesheet" href="/os/static/css/admin-os.css?v=` + assetVer("css/admin-os.css") + `">
    <!-- Wave 1: preload the Body and Mono fonts so the console typeset
         with its designed typefaces from the first paint instead of
         falling back to system-ui while the @font-face fetches resolve. -->
    <link rel="preload" href="/static/fonts/inter-latin-400.woff2" as="font" type="font/woff2" crossorigin>
    <link rel="preload" href="/static/fonts/inter-latin-500.woff2" as="font" type="font/woff2" crossorigin>
    <link rel="preload" href="/static/fonts/jetbrains-mono-latin-400.woff2" as="font" type="font/woff2" crossorigin>
<link rel="icon" type="image/png" href="/static/favicon-light.png">
<!-- Installable app (PWA): manifest + icons so the browser offers "Install VayuOS"
     on desktop and mobile, and the installed app opens straight into the console. -->
<link rel="manifest" href="/os/manifest.webmanifest">
` + osThemeColorMetas(theme) + `
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="VayuOS">
<link rel="apple-touch-icon" href="/os/static/icons/vayuos-apple-180.png">
</head>
<body class="vp-os" data-theme="` + html.EscapeString(theme) + `" data-admin-theme="` + html.EscapeString(theme) + `"` + spaceAttr + `>
<a href="#main-content" class="skip-link">Skip to main content</a>

<!-- Sidebar overlay for mobile tap-to-close -->
<div class="sidebar-overlay" aria-hidden="true"></div>

<div class="shell">
<!-- ── Sidebar ──────────────────────────────────────────────── -->
<aside id="vp-sidebar" class="sidebar" aria-label="Admin navigation">
  <div class="sidebar-brand">
    <img src="/static/favicon-light.png" alt="" width="28" height="28">
    <span class="sidebar-brand-name">` + siteName + `</span>
    <span class="sidebar-brand-os">VayuOS</span>
  </div>
  <nav class="sidebar-nav" aria-label="Primary">
    ` + osSidebarNav(active, settings) + `
    <div class="sidebar-spacer"></div>
  </nav>
  <div class="sidebar-footer">
    ` + osSidebarUser(settings) + `
  </div>
</aside>

<!-- ── Main ─────────────────────────────────────────────────── -->
<div class="main">
  <header class="topbar" role="banner">
    <button type="button" class="menu-toggle btn--icon" data-action="toggle-sidebar" aria-label="Toggle navigation menu" aria-controls="vp-sidebar" aria-expanded="false">
      <svg viewBox="0 0 20 20" fill="none" width="20" height="20" aria-hidden="true"><path d="M3 5h14M3 10h14M3 15h14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
    </button>
    <span class="topbar-title">` + et + `</span>
    ` + spaceBadge + `
    <span class="topbar-spacer"></span>
    ` + cmdHint + `
    ` + feedbackBtn + `
    ` + notifBell + `
    <button type="button" class="btn--icon topbar-install-btn" data-pwa-install hidden aria-label="Install VayuOS as an app" title="Install VayuOS app">
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" aria-hidden="true"><path d="M10 3v9m0 0l-3.2-3.2M10 12l3.2-3.2" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 15.5h12" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>
    </button>
    <button type="button" class="btn--icon topbar-theme-btn" aria-label="Toggle colour theme (light / dark / auto)" title="Colour theme">
      <svg class="theme-ico theme-ico--light" viewBox="0 0 20 20" width="18" height="18" fill="none" aria-hidden="true"><circle cx="10" cy="10" r="3.6" stroke="currentColor" stroke-width="1.6"/><path d="M10 1.6v2.2M10 16.2v2.2M1.6 10h2.2M16.2 10h2.2M4.1 4.1l1.5 1.5M14.4 14.4l1.5 1.5M15.9 4.1l-1.5 1.5M5.6 14.4l-1.5 1.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>
      <svg class="theme-ico theme-ico--dark" viewBox="0 0 20 20" width="18" height="18" fill="none" aria-hidden="true"><path d="M16.2 11.8A6.6 6.6 0 118.2 3.8a5.2 5.2 0 008 8z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>
      <svg class="theme-ico theme-ico--auto" viewBox="0 0 20 20" width="18" height="18" fill="none" aria-hidden="true"><circle cx="10" cy="10" r="8" stroke="currentColor" stroke-width="1.5"/><path d="M10 2a8 8 0 010 16z" fill="currentColor"/></svg>
    </button>
    <form method="POST" action="/os/logout">
      <button type="submit" class="btn btn--ghost btn--sm">Sign out</button>
    </form>
  </header>

  <main id="main-content" class="content">
`
}

// adminOSShellFoot closes the content/main/shell, renders the mobile bottom nav,
// command palette and toast container, then the nonce-gated bootstrap script.
// When pageScript is non-empty it is emitted as an additional nonce-gated inline
// script alongside the shared operator-control helpers (csrf/vpPost/show) and a
// live status region, so streaming operator pages keep their POST controls.
//
// needsPurify (variadic, adminOSLayout only) scopes DOMPurify (Wave 3.3): the
// 21 KB library is used exclusively by the block editor (admin-os-editor.js),
// so every non-editor console page was shipping it for nothing. Editor pages
// are detected from the body markup via pageUsesPurify.
func adminOSShellFoot(nonce, pageScript string, needsAlpine bool, needsPurify ...bool) string {
	// Alpine (ADR-0136) is loaded ONLY on pages that actually host an island
	// (an x-data component). Emitting the 61 KB CSP build + its document-wide
	// MutationObserver on every admin page would tax parse time and every HTMX
	// swap for zero benefit — Alpine is the exception, not the rule. Island-free
	// pages (the overwhelming majority) stay fully Alpine-free.
	alpine := ""
	if needsAlpine {
		alpine = `<!-- Alpine.js islands (ADR-0136): the eval-free CSP build + the VayuOS island
     registry. Self-hosted, deferred, same-origin so they satisfy script-src
     'self' with no dynamic code evaluation. The registry loads FIRST so its
     alpine:init listener is armed before Alpine starts; components are
     referenced by name in x-data, never as inline expressions. HTMX stays the
     backbone — Alpine only powers isolated client-reactive islands, and every
     island degrades to plain HTML. Loaded only when this page hosts one. -->
<script src="/os/static/js/vayu-islands.js?v=` + assetVer("js/vayu-islands.js") + `" defer></script>
<script src="/os/static/js/alpine-csp.min.js?v=` + assetVer("js/alpine-csp.min.js") + `" defer></script>
`
	}
	// DOMPurify (Wave 3.3): only the block editor sanitises client-side, so only
	// the editor ships the library. Non-editor pages stop paying the download
	// and parse cost entirely.
	purifyTag := ""
	if len(needsPurify) > 0 && needsPurify[0] {
		purifyTag = `<script src="/os/static/js/purify.min.js"></script>`
	}
	ops := ""
	if pageScript != "" {
		ops = `<div id="action-msg" role="status" aria-live="polite" class="action-msg"></div>
<script nonce="` + nonce + `">
(function(){'use strict';
var msg=document.getElementById('action-msg');
function csrf(){var m=document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);return m?m[1]:'';}
function show(text,isErr){if(!msg)return;msg.textContent=text;msg.classList.toggle('is-error',!!isErr);msg.classList.add('visible');}
window.vpPost=function(url,onok){fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()}}).then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});}).then(function(res){show(res.ok?(onok?onok(res.d):'ok'):(res.d.detail||res.d.title||'error'),!res.ok);if(res.ok)setTimeout(function(){location.reload();},650);}).catch(function(e){show('Error: '+e,true);});};
` + pageScript + `
})();
</script>`
	}
	return `  </main>
</div><!-- .main -->
</div><!-- .shell -->
` + ops + `
<!-- Bottom nav for mobile — quick links + a Menu button that opens the full,
     role-scoped drawer so every section is reachable like a native app. -->
<nav class="bottom-nav" aria-label="Mobile navigation">
  <a class="bottom-nav-item" href="/os" data-nav="/os">
    ` + iconDashboard + `<span>Home</span>
  </a>
  <a class="bottom-nav-item" href="/os/posts" data-nav="/os/posts">
    ` + iconPosts + `<span>Posts</span>
  </a>
  <a class="bottom-nav-item bottom-nav-item--accent" href="/os/editor" data-nav="/os/editor">
    ` + iconNewPost + `<span>Write</span>
  </a>
  <a class="bottom-nav-item" href="/os/messages" data-nav="/os/messages">
    ` + iconMessages + `<span>Inbox</span>
  </a>
  <button type="button" class="bottom-nav-item" data-action="toggle-sidebar" aria-controls="vp-sidebar" aria-expanded="false" aria-label="Open menu">
    ` + iconApps + `<span>Menu</span>
  </button>
</nav>

<!-- Command palette -->
<div id="cmd-backdrop" class="cmd-backdrop" hidden role="dialog" aria-modal="true" aria-label="Command palette">
  <div class="cmd-panel">
    <div class="cmd-input-wrap">
      <svg class="cmd-search-icon" viewBox="0 0 20 20" fill="none" width="18" height="18" aria-hidden="true">
        <path d="M8 15A7 7 0 108 1a7 7 0 000 14zm5-1l4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      </svg>
      <input id="cmd-input" class="cmd-input" type="text" placeholder="Search posts, members, settings…" autocomplete="off" aria-label="Search">
    </div>
    <div id="cmd-results" class="cmd-results" role="listbox"></div>
    <div class="cmd-footer">
      <span class="cmd-footer-hint"><kbd>↑↓</kbd> navigate</span>
      <span class="cmd-footer-hint"><kbd>↵</kbd> select</span>
      <span class="cmd-footer-hint"><kbd>Esc</kbd> close</span>
    </div>
  </div>
</div>

<!-- Toast container -->
<div class="toast-container" aria-live="polite" aria-atomic="true"></div>

<!-- Screen-reader announce region for HTMX outcomes (WCAG 2.2 AA). Visually
     hidden; the nonce-gated glue script updates it after each hx-* request. -->
<div id="vp-live" class="vp-sr-only" role="status" aria-live="polite" aria-atomic="true"></div>

<!-- Self-hosted HTMX (static/js/htmx.min.js) — embedded in the binary, served
     same-origin so it satisfies script-src 'self' with no nonce and no external
     host. Deferred so hx-* attributes are wired after the document parses. -->
<script src="/static/js/htmx.min.js?v=` + assetVer("js/htmx.min.js") + `" defer></script>
<!-- HTMX glue (nonce-gated → CSP-safe):
     1. CSRF — mirror the double-submit vp_csrf cookie into the X-CSRF-Token
        header on every hx-* mutating request, so admin HTMX POST/DELETE pass the
        same CSRFTokenMiddleware the fetch() controls already use.
     2. Failure feedback — surface any HTTP or network error from an hx-* request
        as a toast, so a failed publish/pin/moderate never fails silently. -->
<script nonce="` + nonce + `">
(function(){var b=document.body;if(!b)return;
b.addEventListener('htmx:configRequest',function(e){var m=document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);if(m)e.detail.headers['X-CSRF-Token']=m[1];});
function vpHtmxFail(){if(window.vpToast)window.vpToast('Action failed — please try again.','error');}
b.addEventListener('htmx:responseError',vpHtmxFail);
b.addEventListener('htmx:sendError',vpHtmxFail);
b.addEventListener('htmx:afterRequest',function(e){var d=e.detail;if(!d||!d.successful)return;var l=document.getElementById('vp-live');if(!l)return;var v=(d.requestConfig&&(d.requestConfig.verb||'')).toLowerCase();l.textContent='';l.textContent=(v==='get'?'Content refreshed.':'Change saved.');});
// One-click world switch (ADR-0141): the switch lives on every admin page but the
// vp_csrf cookie is only issued by CSRF-wrapped GETs, so prime it with a GET of
// the (admin-only, side-effect-free) Spaces page, then POST the toggle with the
// fresh token. Reloads on success to pick up the new world + its colour.
function vpSpaceStatus(txt){var st=document.querySelector('[data-space-status]');if(st){st.hidden=false;st.textContent=txt;}}
Array.prototype.forEach.call(document.querySelectorAll('[data-space-switch]'),function(seg){
  seg.addEventListener('click',function(){
    if(seg.classList.contains('is-active')||seg.disabled)return;
    var on=seg.getAttribute('data-space-switch')==='on';
    var sw=seg.parentNode;if(sw)sw.classList.add('is-busy');
    vpSpaceStatus(on?'Starting your anonymous world…':'Switching to Clearnet…'); // instant feedback
    if(!on){location.href='/os/world?target=clearnet';return;} // leave: just drop the view
    // Enter Tor: make sure the anonymous world is on, then step INTO it.
    fetch('/os/spaces',{credentials:'same-origin'}).then(function(){
      var m=document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);
      return fetch('/os/spaces/toggle?enable=1',{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':m?m[1]:''}});
    }).then(function(r){
      if(r.ok){location.href='/os/world?target=tor';return;} // enter the Tor world console
      if(sw)sw.classList.remove('is-busy');
      // Surface the SERVER's actual reason (admin required, settings unavailable,
      // write failed…) instead of always blaming permissions — so a real failure
      // is diagnosable on mobile where there is no console to inspect.
      r.json().then(function(d){
        var msg=(d&&(d.detail||d.title))||'Could not start the anonymous world.';
        vpSpaceStatus(msg);if(window.vpToast)window.vpToast(msg,'error');
      }).catch(function(){
        var m='Could not start the anonymous world (HTTP '+r.status+'). Please try again.';
        vpSpaceStatus(m);if(window.vpToast)window.vpToast(m,'error');
      });
    }).catch(function(){if(sw)sw.classList.remove('is-busy');vpSpaceStatus('Could not switch — please try again.');if(window.vpToast)window.vpToast('Could not switch world — please try again.','error');});
  });
});
// Copy buttons for the Tor .onion address — in the sidebar and on the dashboard
// world card. Scoped so it never double-binds with the VayuTor page's own island.
Array.prototype.forEach.call(document.querySelectorAll('.sidebar [data-copy], .world-card [data-copy]'),function(btn){
  btn.addEventListener('click',function(){
    var v=btn.getAttribute('data-copy')||'',p=btn.textContent;
    var done=function(){btn.textContent='copied';setTimeout(function(){btn.textContent=p;},1400);};
    if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(v).then(done,done);}else{done();}
  });
});
})();
` + vpConfirmScript + `
</script>
` + alpine + `<!-- Bootstrap (nonce-gated, reads data-admin-theme from body) -->
` + purifyTag + `
<script nonce="` + nonce + `" src="/os/static/js/admin-os.js?v=` + assetVer("js/admin-os.js") + `"></script>
</body></html>`
}

// osSettings holds the subset of site settings needed to render every page.
type osSettings struct {
	SiteName   string
	AdminTheme string
	// Signed-in user, surfaced in the sidebar footer card.
	UserID     string
	UserName   string
	UserRole   string
	UserAvatar string
	// MailOnly / AccessLevel drive role-scoped sidebar visibility and match the
	// route guard in requireSessionOrAPIKey (hidden == unreachable).
	MailOnly    bool
	AccessLevel int
	// UnreadMessages drives the sidebar badge on the Messages item.
	UnreadMessages int
	// TorSpaceOn: the Anonymous Tor Space is enabled — the shell wears the Tor
	// (purple) palette so the operator always knows the anonymous world is live.
	TorSpaceOn bool
	// TorSpaceRunning / TorSpaceOnion back the inline status shown under the sidebar
	// world switch, so the operator sees whether the anonymous world is live and its
	// .onion address without opening a separate page.
	TorSpaceRunning bool
	TorSpaceOnion   string
	// Notifications backs the topbar notification centre (the bell that replaced the
	// New Post shortcut): every actionable signal in the system — new contact mail,
	// comments to moderate, mail devices awaiting approval, domains waiting to sync —
	// each linking straight to the page that clears it. Gated per-item to the
	// viewer's access level, so an item never points at a page they cannot open.
	Notifications []osNotification
}

// osNotification is one actionable item in the topbar notification centre: a
// short title, a human detail, the count driving its badge, a target page, and a
// kind slug that selects both its icon and its accent colour (a fixed literal, so
// it is safe to interpolate straight into the class name).
type osNotification struct {
	Title  string
	Detail string
	Href   string
	Count  int
	Kind   string // "mail" | "comment" | "message" | "domain" | "update" | "jobs" | "storage" | "mode"
	// Severity (Wave 2.2): "" / "info" is a todo, "warn" needs attention soon,
	// "danger" is something failing NOW. Drives the badge colour on the bell and
	// the dashboard attention strip, so "3 pending comments" never screams the
	// way "10 failed jobs" must.
	Severity string
}

// getOSSettings loads settings needed for layout rendering.
func (a *App) getOSSettings(ctx context.Context) *osSettings {
	s := &osSettings{}
	if a.siteSettings != nil {
		s.SiteName = a.siteSettings.Get(ctx, settings.ForPrimary(), settings.KeySiteName)
		s.AdminTheme = a.siteSettings.Get(ctx, settings.ForPrimary(), "admin.theme")
		// Anonymous Tor Space on ⇒ shift the whole VayuOS chrome to the Tor palette.
		s.TorSpaceOn = a.siteSettings.Get(ctx, settings.ForPrimary(), settings.KeyTorSpaceEnabled) == "on"
	}
	// Live Tor-Space status for the inline panel under the sidebar switch (nil-safe;
	// zero values in a Tor-Space child, which has no supervisor).
	if s.TorSpaceOn {
		st := a.torSpaceStatusNow()
		s.TorSpaceRunning = st.Running
		s.TorSpaceOnion = st.Onion
	}
	// Unread contact messages drive the sidebar badge. Best-effort: any error
	// (nil DB / missing table on a pre-046 schema) just leaves the badge off.
	if dbpkg.DB != nil {
		_ = dbpkg.Reader().QueryRowContext(ctx, `SELECT COUNT(1) FROM contact_messages WHERE is_read=0`).Scan(&s.UnreadMessages)
	}
	// Surface the authenticated user (if any) so the shell can show their
	// avatar/name/role. The user is attached to the context by
	// requireSessionOrAPIKey and already carries the profile fields.
	s.AccessLevel = accessAdmin // legacy API-key / no-session callers are admin-equivalent
	if v := ctx.Value(ctxUserKey); v != nil {
		if u, ok := v.(*users.User); ok && u != nil {
			s.UserID = u.ID
			s.UserName = u.Name
			if s.UserName == "" {
				s.UserName = authorFallbackName(u.Email)
			}
			s.UserRole = u.Role
			s.UserAvatar = u.AvatarURL
			if mo, ok := ctx.Value(ctxMailOnlyKey).(bool); ok && mo {
				s.MailOnly = true
			}
			s.AccessLevel = accessLevelFor(u.Role, s.MailOnly)
		}
	}
	// Notification centre (topbar bell): computed last, once the access level is
	// known, so each item can be gated to what the viewer can actually open.
	s.Notifications = a.osNotifications(ctx, s)
	return s
}

// osNotifications aggregates the actionable signals shown in the topbar bell.
// Every source is a cheap, best-effort read (a nil DB, a missing table on an
// older schema, or a query error simply drops that item — the console never
// fails to render because a count could not be taken). Each item is gated to the
// viewer's access level via osPathMinLevel(href), so it never advertises a page
// the viewer cannot open.
func (a *App) osNotifications(ctx context.Context, s *osSettings) []osNotification {
	var out []osNotification
	add := func(href, title, detail, kind string, count int, severity ...string) {
		if count <= 0 || s.AccessLevel < osPathMinLevel(href) {
			return
		}
		sev := ""
		if len(severity) > 0 {
			sev = severity[0]
		}
		out = append(out, osNotification{Title: title, Detail: detail, Href: href, Count: count, Kind: kind, Severity: sev})
	}
	if dbpkg.DB == nil {
		return out
	}
	rdb := dbpkg.Reader()
	// Unread contact-form mail (already counted for the sidebar badge).
	add("/os/messages", "New messages", "unread in your inbox", "message", s.UnreadMessages)
	// Comments awaiting moderation.
	pendingComments := 0
	_ = rdb.QueryRowContext(ctx, `SELECT COUNT(1) FROM comments WHERE status='pending'`).Scan(&pendingComments)
	add("/os/comments", "Comments to review", "awaiting moderation", "comment", pendingComments)
	// New mail waiting in the viewer's mailboxes — the count that also raises the
	// live desktop notification (admin-os.js). Cheap readdir-only counts.
	if unseen, href := a.mailUnseenForViewer(ctx, s); unseen > 0 {
		noun := "unread in your mailbox"
		if href == "/os/vayumail/inbox" {
			noun = "unread across your mailboxes"
		}
		add(href, "New mail", noun, "mail", unseen)
	}
	// Mail devices waiting for approval to sync a mailbox (VayuMail direct-connect).
	if a.vayuMail != nil {
		pendingDevices := 0
		_ = rdb.QueryRowContext(ctx, `SELECT COUNT(1) FROM vayumail_app_passwords WHERE device_id IS NOT NULL AND device_id <> '' AND status='pending'`).Scan(&pendingDevices)
		add("/os/vayumail", "Mail devices", "waiting for approval", "mail", pendingDevices)
	}
	// Secondary domains registered but still on manual hold (not yet approved to
	// provision). Pending Tor sites (placeholder host, minting their .onion) are
	// excluded — there is nothing to approve until their address lands.
	if a.domains != nil {
		if list, err := a.domains.List(ctx); err == nil {
			held := 0
			for _, d := range list {
				if !d.IsPrimary && !d.IsSyncApproved() && !isPendingTorSite(d.Host) {
					held++
				}
			}
			add("/os/domains", "Domains to sync", "waiting for approval", "domain", held)
		}
	}
	// A newer signed VayuPress release is ready to install (read from the cached
	// update-check history, refreshed by the background watcher). Admin-only via
	// the /os/update gate in add(); silent in a Tor Space.
	if v, ok := a.latestUpdateNotice(ctx); ok {
		add("/os/update", "VayuOS update ready", "Install "+v+" in one click", "update", 1)
	}
	// Wave 2.2 — the operational signals the bell used to ignore. All three come
	// from the metrics snapshot (an atomic load; collectAdminMetrics is already
	// running on a 30s ticker), so the bell costs nothing extra.
	if snap := a.getAdminSnapshot(); snap != nil {
		// Failed render/write jobs: the public site is silently going stale.
		// One failure is "look soon"; a pile is "failing now".
		if snap.FailedJobs > 0 {
			sev := "warn"
			if snap.FailedJobs >= 10 {
				sev = "danger"
			}
			add("/os/monitoring", "Failed jobs", "render/write jobs failed — the site may be serving stale content", "jobs", snap.FailedJobs, sev)
		}
		// Disk pressure: quota consumption from the same snapshot. At 90% the
		// next upload or backup can start failing — that is danger, not todo.
		if snap.StoragePct >= 75 {
			sev := "warn"
			if snap.StoragePct >= 90 {
				sev = "danger"
			}
			add("/os/storage", "Storage filling up", "of your storage quota is in use", "storage", int(snap.StoragePct), sev)
		}
		// Maintenance mode on: deliberate, but visible — an install parked in
		// maintenance "for a moment" three days ago deserves a bell entry.
		if config.Cfg.MaintenanceMode {
			add("/os/modes", "Maintenance mode on", "the public site is offline behind a maintenance page", "mode", 1, "info")
		}
	}
	return out
}

// osAttentionStrip renders the dashboard's attention strip (Wave 2.2): the
// bell's actionable signals surfaced inline where the operator actually looks,
// sorted danger → warn → info. Empty when there is nothing needing eyes — an
// all-clear strip that always renders is wallpaper, not signal.
func osAttentionStrip(notifs []osNotification) string {
	weight := func(sev string) int {
		switch sev {
		case "danger":
			return 0
		case "warn":
			return 1
		default:
			return 2
		}
	}
	sorted := append([]osNotification(nil), notifs...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && weight(sorted[j].Severity) < weight(sorted[j-1].Severity); j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	var b strings.Builder
	b.WriteString(`<div class="attention-strip" data-attention-strip role="region" aria-label="Needs attention">`)
	for _, n := range sorted {
		sev := n.Severity
		if sev == "" {
			sev = "info"
		}
		detail := n.Detail
		if n.Kind != "update" && n.Kind != "storage" && n.Count > 0 {
			detail = notifCap(n.Count) + " " + n.Detail
		}
		if n.Kind == "storage" {
			detail = notifCap(n.Count) + "% " + n.Detail
		}
		b.WriteString(`<a class="attention-chip attention-chip--` + sev + `" href="` + n.Href + `">` +
			`<span class="attention-chip__dot" aria-hidden="true"></span>` +
			`<span class="attention-chip__title">` + html.EscapeString(n.Title) + `</span>` +
			`<span class="attention-chip__detail">` + html.EscapeString(detail) + `</span></a>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// roleDisplay returns a human label for a role slug.
func roleDisplay(role string) string {
	switch role {
	case users.RoleAdmin:
		return "Administrator"
	case users.RoleEditor:
		return "Editor"
	case users.RoleAuthor:
		return "Author"
	case "":
		return "Administrator"
	default:
		return strings.ToUpper(role[:1]) + role[1:]
	}
}

// osSidebarUser renders the signed-in user card (avatar + name + role) shown at
// the foot of the sidebar. It links to the self-service profile editor.
func osSidebarUser(s *osSettings) string {
	name, role, avatarURL := "Admin", "Administrator", ""
	if s != nil {
		if s.UserName != "" {
			name = s.UserName
		}
		role = roleDisplay(s.UserRole)
		avatarURL = s.UserAvatar
	}
	avatar := `<div class="avatar avatar--sm avatar--brand">` + html.EscapeString(initials(name, "")) + `</div>`
	if avatarURL != "" {
		avatar = `<img class="avatar avatar--sm" src="` + html.EscapeString(avatarURL) + `" alt="" width="28" height="28">`
	}
	return `<a class="sidebar-user" href="/os/profile" title="Edit your profile">
      ` + avatar + `
      <div class="sidebar-user-info">
        <div class="sidebar-user-name">` + html.EscapeString(name) + `</div>
        <div class="sidebar-user-role">` + html.EscapeString(role) + `</div>
      </div>
    </a>`
}

// writeOSHTML writes HTML with the standard os response headers and CSRF cookie.
func writeOSHTML(w http.ResponseWriter, r *http.Request, body string) {
	// Reuse the browser's existing token rather than rotating on every render —
	// rotating is what made a second console tab's form 403 on submit.
	csrfTokenFor(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex")
	// Admin pages must never be cached by the browser or any proxy/CDN —
	// otherwise a stale panel (e.g. an old Analytics page) keeps showing after a
	// deploy. These pages are dynamic and cheap to render, so always serve fresh.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

// ── Login page ───────────────────────────────────────────────────────────────

// setAuthPageNoCache marks an auth page (login, change-password) uncacheable by
// the browser AND every proxy/CDN.
//
// This is load-bearing, not defensive boilerplate: the login page is written
// directly (it bypasses writeOSHTML, which is where the dashboard gets its
// no-store). Without an explicit Cache-Control the browser is free to
// heuristically cache the rendered 200 form and serve it on a LATER visit
// WITHOUT hitting the server — so the "already signed in → redirect to /os"
// check below never runs, and a logged-in operator keeps seeing the login page
// while /os (always no-store) correctly shows the dashboard. That exact
// asymmetry is the reported bug. no-store forbids all caching/reuse, so the
// session-aware redirect runs on every /os/login navigation.
func setAuthPageNoCache(w http.ResponseWriter) {
	// "private" and Vary: Cookie are what stop a SHARED cache (a CDN or reverse
	// proxy in front of the origin) from storing this response and later handing it
	// to somebody else. Without them a proxy can serve a stored sign-in form to a
	// visitor who already holds a valid session — which looks exactly like being
	// logged out, right up until you edit the URL and land inside, still signed in.
	// no-store alone is not reliably honoured by every edge, so state it three ways:
	// the standard directives, the explicit private/Vary contract, and the
	// CDN-specific override that takes precedence at the edge.
	w.Header().Set("Cache-Control", "private, no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("CDN-Cache-Control", "no-store")
	w.Header().Set("Vary", "Cookie")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func (a *App) handleOSLogin(w http.ResponseWriter, r *http.Request) {
	// no-store BEFORE the branch so both the redirect and the form response are
	// uncacheable — otherwise a cached form silently defeats the redirect.
	setAuthPageNoCache(w)
	// Already signed in? Opening /os/login with a live session must land on the
	// dashboard, not re-prompt for credentials — the seamless posture the operator
	// expects whether they typed /os or /os/login.
	next := r.URL.Query().Get("next")
	if !isLocalURL(next) {
		next = ""
	}
	if a.hasValidConsoleSession(r) {
		// Redirect the guarded value directly inside `if isLocalURL(next)` so the
		// static analyser sees `next` neutralised on this branch (barrier guard).
		if isLocalURL(next) {
			http.Redirect(w, r, next, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/os", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(osLoginPage("", "", next)))
}

// isLocalURL reports whether s is a safe SAME-ORIGIN path. It must parse as a
// purely relative reference — no scheme, no host/authority, no userinfo, no
// opaque part — that is site-rooted ("/…"), and must not be protocol-relative
// ("//host"), a backslash trick ("/\host"), or carry control characters or an
// embedded scheme. Anything else is rejected, so a post-login "next" bounce can
// never leave this site.
//
// The name deliberately matches CodeQL's redirect-check barrier-guard heuristic
// (isLocalUrl / isValidRedirect / …): used as `if isLocalURL(v) { redirect(v) }`
// the analyser treats v as a neutralised, safe-to-redirect value on the true
// branch. A prior version returned a normalised string, which the analyser never
// recognised as a sanitizer — a boolean guard is what the query actually models.
func isLocalURL(s string) bool {
	if s == "" || len(s) > 512 || strings.Contains(s, "://") {
		return false
	}
	// Some browsers treat "\" as "/", so a "/\evil.com" could become
	// protocol-relative; reject backslashes and control characters outright.
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return false
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	if u.IsAbs() || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return false
	}
	return strings.HasPrefix(u.Path, "/") && !strings.HasPrefix(u.Path, "//")
}

func (a *App) handleOSLoginSubmit(w http.ResponseWriter, r *http.Request) {
	setAuthPageNoCache(w)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	next := r.FormValue("next")
	if !isLocalURL(next) {
		next = ""
	}
	loginDest := "/os"
	if isLocalURL(next) {
		loginDest = next
	}
	email := strings.TrimSpace(r.FormValue("email"))
	pass := r.FormValue("password")
	if email == "" || pass == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(osLoginPage(email, "Email and password are required.", next)))
		return
	}
	if a.userStore == nil || a.sessions == nil {
		http.Error(w, "accounts not initialised", http.StatusServiceUnavailable)
		return
	}
	// "Remember me": checked (default) keeps a persistent cookie across browser
	// restarts; unchecked issues a browser-session cookie that is dropped on close,
	// so the operator is signed out and must log in again on the next visit.
	remember := r.FormValue("remember") != ""
	// Brute-force guard — shared lockout state with the v2 surface and the
	// API-key path so attempts cannot be split across surfaces.
	ip := loginClientIP(r)
	if locked, until := auth.CheckAuthLockout(ip); locked {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(osLoginPage(email, loginLockoutMessage(until), next)))
		return
	}
	u, err := a.userStore.Authenticate(r.Context(), email, pass)
	if err != nil {
		// Fall back to a VayuMail account login (mailbox / author / editor / etc.),
		// so those email accounts can sign in from the same website login button.
		if addr, mok, totpMissing := a.authMailAccount(r.Context(), email, pass, r.FormValue("totp")); mok {
			token, terr := a.sessions.Create(r.Context(), "vmail:"+addr)
			if terr != nil {
				http.Error(w, "could not start session", http.StatusInternalServerError)
				return
			}
			auth.RecordAuthSuccess(ip)
			auth.SetSessionCookieRemember(w, token, remember)
			http.Redirect(w, r, loginDest, http.StatusSeeOther)
			return
		} else if totpMissing {
			auth.RecordAuthFailure(ip)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(osLoginPage(email, "Enter the 6-digit code from your authenticator app, then re-enter your password.", next)))
			return
		}
		auth.RecordAuthFailure(ip)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(osLoginPage(email, "Invalid email or password.", next)))
		return
	}
	// Second factor: if the account has 2FA enabled, a valid TOTP code is required.
	// On failure the password must be re-entered (it is never echoed back).
	if ok, required := a.verifyTOTPForLogin(r.Context(), email, r.FormValue("totp")); required && !ok {
		auth.RecordAuthFailure(ip)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(osLoginPage(email, "Enter the 6-digit code from your authenticator app, then re-enter your password.", next)))
		return
	}
	token, err := a.sessions.Create(r.Context(), u.ID)
	if err != nil {
		http.Error(w, "could not start session", http.StatusInternalServerError)
		return
	}
	auth.RecordAuthSuccess(ip)
	a.userStore.TouchLastLogin(r.Context(), u.ID)
	auth.SetSessionCookieRemember(w, token, remember)
	http.Redirect(w, r, loginDest, http.StatusSeeOther)
}

// handleOSChangePassword renders the forced first-login password-change page for
// a bootstrapped default admin. Reached via the serveWithAccess gate.
func (a *App) handleOSChangePassword(w http.ResponseWriter, r *http.Request) {
	setAuthPageNoCache(w)
	u := currentUser(r)
	em := ""
	if u != nil {
		em = u.Email
	}
	// Reuse a valid token when the browser already holds one (see csrfTokenFor):
	// minting on every render invalidated a form left open in another tab. The
	// cookie is host-only (no Domain), so a same-site subdomain foothold cannot
	// read it to forge the token.
	token := csrfTokenFor(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(osChangePasswordPage(em, "", token)))
}

// handleOSChangePasswordSubmit sets a new password for the signed-in user and
// clears the must-change flag, then sends them to the console. New password must
// be ≥8 chars and match the confirmation.
func (a *App) handleOSChangePasswordSubmit(w http.ResponseWriter, r *http.Request) {
	setAuthPageNoCache(w)
	u := currentUser(r)
	if u == nil || a.userStore == nil {
		http.Redirect(w, r, "/os/login", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	pass := r.FormValue("password")
	confirm := r.FormValue("confirm")
	// Re-embed the still-valid CSRF token from the cookie so a validation-error
	// re-render can be resubmitted without a fresh page load.
	csrf := ""
	if c, cerr := r.Cookie("vp_csrf"); cerr == nil {
		csrf = c.Value
	}
	render := func(msg string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(osChangePasswordPage(u.Email, msg, csrf)))
	}
	if len(pass) < 8 {
		render("Password must be at least 8 characters.")
		return
	}
	if pass != confirm {
		render("The two passwords do not match.")
		return
	}
	if err := a.userStore.SetPassword(r.Context(), u.Email, pass); err != nil {
		render("Could not update the password: " + err.Error())
		return
	}
	dbpkg.AuditLog("user.password_change", u.Email, "", "forced first-login change")
	http.Redirect(w, r, "/os", http.StatusSeeOther)
}

// osChangePasswordPage renders the forced password-change form. Self-contained
// (reuses the login page chrome); the only inline script is the nonce'd one in
// the shared shell, so no CSP exception is needed.
func osChangePasswordPage(email, msg, csrf string) string {
	banner := ""
	if msg != "" {
		banner = `<div class="login-error" role="alert">` + html.EscapeString(msg) + `</div>`
	}
	return authPageShell("Set a new password — VayuOS", `
  <div class="login-brandline">
    <img src="/static/favicon-light.png" alt="" width="30" height="30">
    <span>VayuPress</span>
  </div>
  <div class="login-card">
    <h1 class="login-title">Set a new password</h1>
    <p class="login-sub">You're signing in with the default administrator password. Choose a new one to continue.</p>
    `+banner+`
    <form class="login-form" method="POST" action="/os/change-password" novalidate>
      <input type="hidden" name="csrf_token" value="`+html.EscapeString(csrf)+`">
      <div class="field">
        <label class="field-label" for="cp-email">Account</label>
        <input id="cp-email" class="input" type="email" value="`+html.EscapeString(email)+`" readonly>
      </div>
      <div class="field">
        <label class="field-label" for="cp-pass">New password</label>
        <input id="cp-pass" class="input" type="password" name="password" required minlength="8" autocomplete="new-password" placeholder="At least 8 characters">
      </div>
      <div class="field">
        <label class="field-label" for="cp-confirm">Confirm new password</label>
        <input id="cp-confirm" class="input" type="password" name="confirm" required minlength="8" autocomplete="new-password" placeholder="Re-enter the password">
      </div>
      <button class="btn btn--primary login-submit" type="submit">Save &amp; continue</button>
    </form>
  </div>`)
}

func (a *App) handleOSLogout(w http.ResponseWriter, r *http.Request) {
	if a.sessions != nil {
		if token := auth.SessionTokenFromRequest(r); token != "" {
			_ = a.sessions.Destroy(r.Context(), token)
		}
	}
	auth.ClearSessionCookie(w)
	// Also end any membership session, so a reader who reached VayuMail via the
	// portal (VayuMail mailbox login) is signed out completely from one action.
	if a.members != nil {
		if c, err := r.Cookie(memberCookie); err == nil && c.Value != "" {
			_ = a.members.DestroySession(r.Context(), c.Value)
		}
	}
	writeSecureCookie(w, &http.Cookie{
		Name: memberCookie, Value: "", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	http.Redirect(w, r, "/os/login", http.StatusSeeOther)
}

// osLoginPage builds the sign-in page: a single, calm, centered card on a clean
// background (light by default, following the OS) with an unobtrusive
// light/dark/auto theme switch. No gradients, no animation — minimalist premium.
func osLoginPage(prefillEmail, errMsg, next string) string {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="login-error" role="alert">` + html.EscapeString(errMsg) + `</div>`
	}
	// next carries the post-login destination (e.g. an /oauth/authorize URL the
	// operator was bounced from). It is a safe same-origin path (isLocalURL),
	// so it can never redirect off-site; it is round-tripped as a hidden field.
	nextHTML := ""
	if next != "" {
		nextHTML = `<input type="hidden" name="next" value="` + html.EscapeString(next) + `">`
	}
	return authPageShell("Sign in — VayuPress", `
  <div class="login-brandline">
    <img src="/static/favicon-light.png" alt="" width="30" height="30">
    <span>VayuPress</span>
  </div>
  <div class="login-card">
    <h1 class="login-title">Welcome back</h1>
    <p class="login-sub">Sign in to your dashboard</p>
    `+errHTML+`
    <form class="login-form" method="POST" action="/os/login" novalidate>`+nextHTML+`
      <div class="field">
        <label class="field-label" for="login-email">Email</label>
        <input id="login-email" class="input" type="email" name="email"
          value="`+html.EscapeString(prefillEmail)+`"
          placeholder="you@example.com" autocomplete="username" required autofocus>
      </div>
      <div class="field">
        <label class="field-label" for="login-password">Password</label>
        <input id="login-password" class="input" type="password" name="password"
          placeholder="Your password" autocomplete="current-password" required>
      </div>
      <details class="login-totp"` + loginTOTPOpen(errHTML) + `>
        <summary class="login-totp__summary">Sign in with a 2FA code</summary>
        <div class="field">
          <label class="field-label" for="login-totp">Two-factor code</label>
          <input id="login-totp" class="input" type="text" name="totp"
            inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="000000">
        </div>
      </details>
      <label class="login-remember" for="login-remember">
        <input id="login-remember" type="checkbox" name="remember" value="1" checked>
        <span>Remember me on this device</span>
      </label>
      <button type="submit" class="btn btn--primary login-submit">Sign in</button>
    </form>
    <p class="login-recover"><a href="/mail/recover">Forgot your mailbox password?</a></p>
  </div>
  <div class="login-footer">Sovereign · zero-telemetry · yours completely</div>`)
}

// authPageShell wraps the calm auth-page layout (theme toggle + centered column)
// shared by the sign-in and change-password pages. The .vp-os class and the
// data-theme attribute both sit on <html> so the token overrides apply; the
// theme defaults to "auto" (follows the OS) and is switchable via os-theme.js.
// loginTOTPOpen reports whether the collapsed 2FA disclosure must start open:
// only when the sign-in error was about the code itself, so a failed attempt
// reopens the field instead of hiding the reason it failed.
func loginTOTPOpen(errHTML string) string {
	if strings.Contains(errHTML, "two-factor") || strings.Contains(errHTML, "2FA") ||
		strings.Contains(errHTML, "code") || strings.Contains(errHTML, "TOTP") {
		return " open"
	}
	return ""
}

func authPageShell(title, inner string) string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + html.EscapeString(title) + `</title>
<meta name="robots" content="noindex, nofollow">
<link rel="stylesheet" href="/os/static/css/admin-os.css?v=` + assetVer("css/admin-os.css") + `">
<link rel="icon" type="image/png" href="/static/favicon-light.png">
<!-- Installable app (PWA): manifest + icons so the browser offers "Install VayuOS"
     on desktop and mobile, and the installed app opens straight into the console. -->
<link rel="manifest" href="/os/manifest.webmanifest">
` + osThemeColorMetas("auto") + `
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="VayuOS">
<link rel="apple-touch-icon" href="/os/static/icons/vayuos-apple-180.png">
</head>
<body class="vp-os auth-page" data-theme="auto">
  <div class="theme-switch" role="group" aria-label="Colour theme">
    <button type="button" class="theme-opt" data-set-theme="light" aria-label="Light" title="Light">☀</button>
    <button type="button" class="theme-opt" data-set-theme="dark" aria-label="Dark" title="Dark">☾</button>
    <button type="button" class="theme-opt" data-set-theme="auto" aria-label="Auto (match system)" title="Auto">◐</button>
  </div>
  <main class="auth-col">` + inner + `
  </main>
<script src="/os/static/js/os-theme.js?v=` + assetVer("js/os-theme.js") + `"></script>
</body></html>`
}

// ── Dashboard ────────────────────────────────────────────────────────────────

// osSparkline renders a compact inline SVG line chart from a series of values.
// It emits no inline styles (CSP-safe); all colour comes from CSS via
// currentColor on the .sparkline class. width/height are SVG viewBox units.
func osSparkline(vals []int) string {
	const w, h = 240, 48
	if len(vals) == 0 {
		return ""
	}
	maxV := 1
	for _, v := range vals {
		if v > maxV {
			maxV = v
		}
	}
	n := len(vals)
	stepX := float64(w) / float64(n-1)
	if n == 1 {
		stepX = 0
	}
	pts := make([]string, 0, n)
	for i, v := range vals {
		x := float64(i) * stepX
		// Leave 4px top/bottom padding so the stroke isn't clipped.
		y := float64(h-4) - (float64(v)/float64(maxV))*float64(h-8)
		pts = append(pts, strconv.FormatFloat(x, 'f', 1, 64)+","+strconv.FormatFloat(y, 'f', 1, 64))
	}
	poly := strings.Join(pts, " ")
	// Area fill path (down to baseline) + the line on top.
	area := "0," + strconv.Itoa(h) + " " + poly + " " + strconv.Itoa(w) + "," + strconv.Itoa(h)
	return `<svg class="sparkline" viewBox="0 0 ` + strconv.Itoa(w) + ` ` + strconv.Itoa(h) +
		`" preserveAspectRatio="none" role="img" aria-label="Publishing activity, last ` + strconv.Itoa(n) + ` days">` +
		`<polyline class="sparkline__area" points="` + area + `"/>` +
		`<polyline class="sparkline__line" points="` + poly + `"/>` +
		`</svg>`
}

// ── Dashboard: first-run checklist (Wave 2.5) ────────────────────────────────

// osChecklistItem is one row of the dashboard's first-run checklist. Review
// items are actions the operator must eyeball elsewhere (DNS/HTTPS state lives
// on its own page) — they render as a neutral "Review" step, never as a ✓/✗ the
// server cannot honestly know.
type osChecklistItem struct {
	Label  string
	Detail string
	Href   string
	Done   bool
	Review bool
}

// osFirstRunChecklist assembles the dashboard's dismissable first-run card from
// cheap, server-known facts only — DB counts, settings presence, the configured
// domain. It deliberately performs NO network probes (DNS lookups, certificate
// fetches): the dashboard render path must stay fast, and a probe that times
// out would hang sign-in-to-dashboard. Nil when the viewer cannot reach the
// pages the items link to, or when everything is already done.
func (a *App) osFirstRunChecklist(ctx context.Context, accessLevel int) []osChecklistItem {
	// Every item links into an admin-gated page; an author who cannot open
	// /os/settings must not be handed a card of dead links.
	if accessLevel < osPathMinLevel("/os/settings") {
		return nil
	}
	var items []osChecklistItem
	add := func(it osChecklistItem) { items = append(items, it) }

	published := 0
	if dbpkg.DB != nil {
		_ = dbpkg.Reader().QueryRowContext(ctx, `SELECT COUNT(1) FROM articles WHERE status='published'`).Scan(&published)
	}
	add(osChecklistItem{
		Label:  "Publish your first post",
		Detail: "Drafts stay private until you flip them live from the editor",
		Href:   "/os/posts",
		Done:   published > 0,
	})

	// Site name + theme: value-diff against the compiled-in defaults. GetAll
	// merges the defaults into its result, so presence proves nothing — an
	// unset key resolves to "VayuPress" — but a value that DIFFERS from the
	// default can only come from the operator.
	if a.siteSettings != nil {
		if kv, err := a.siteSettings.GetAll(ctx, settings.ForPrimary()); err == nil {
			differsFromDefault := func(key string) bool {
				v, ok := kv[key]
				def, hasDefault := settings.Defaults[key]
				if !hasDefault {
					return ok && v != "" // no default ⇒ any stored value is a choice
				}
				return ok && v != def
			}
			add(osChecklistItem{
				Label:  "Name your site",
				Detail: "The name your readers see in the header and their inbox",
				Href:   "/os/settings",
				Done:   differsFromDefault(settings.KeySiteName),
			})
			themed := false
			for k := range kv {
				if strings.HasPrefix(k, "theme.") && differsFromDefault(k) {
					themed = true
					break
				}
			}
			add(osChecklistItem{
				Label:  "Make it yours",
				Detail: "Pick colours and typography in Theme",
				Href:   "/os/theme",
				Done:   themed,
			})
		}
	}

	// A bare single-binary install serves "localhost" — the machine name no
	// reader can type. Anything else counts as pointed.
	domain := strings.TrimSpace(config.Cfg.Domain)
	add(osChecklistItem{
		Label:  "Point a real domain",
		Detail: "A bare install only answers on localhost",
		Href:   "/os/domains",
		Done:   domain != "" && domain != "localhost",
	})
	add(osChecklistItem{
		Label:  "Review DNS & HTTPS",
		Detail: "Records resolve and the certificate is live — once a domain points here",
		Href:   "/os/dns",
		Review: true,
	})

	// All done ⇒ no card. A checklist that nags completed work is the same
	// dishonesty the plan set out to remove.
	for _, it := range items {
		if !it.Done {
			return items
		}
	}
	return nil
}

// osFirstRunCard renders the dismissable checklist card. Dismissal lives in
// localStorage (vayuOS.firstRun.dismissed): a per-browser "seen it" is exactly
// right for an orientation card, and it needs no schema, no write endpoint and
// no per-user column.
func osFirstRunCard(items []osChecklistItem, nonce string) string {
	var rows string
	for _, it := range items {
		state := `<a class="frc__action btn btn--ghost btn--sm" href="` + it.Href + `">Open<span aria-hidden="true"> →</span></a>`
		mark := `<span class="frc__mark frc__mark--todo" aria-hidden="true">○</span>`
		if it.Done {
			state = `<span class="frc__done-label">Done</span>`
			mark = `<span class="frc__mark frc__mark--done" aria-hidden="true">✓</span>`
		} else if it.Review {
			state = `<a class="frc__action btn btn--ghost btn--sm" href="` + it.Href + `">Review<span aria-hidden="true"> →</span></a>`
		}
		rows += `<li class="frc__item` + map[bool]string{true: " frc__item--done", false: ""}[it.Done] + `">` +
			mark +
			`<span class="frc__text"><span class="frc__label">` + it.Label + `</span>` +
			`<span class="frc__detail">` + it.Detail + `</span></span>` +
			state + `</li>`
	}
	return `<section class="card first-run" data-first-run role="region" aria-label="First-run checklist">
  <div class="frc__head">
    <span class="frc__title">Get set up</span>
    <span class="frc__hint">The short path from install to a live site</span>
    <button type="button" class="btn btn--ghost btn--sm" data-first-run-dismiss aria-label="Dismiss the first-run checklist">Dismiss</button>
  </div>
  <ul class="frc__list">` + rows + `</ul>
</section>
<script nonce="` + nonce + `">
(function(){'use strict';
var KEY='vayuOS.firstRun.dismissed';
var card=document.querySelector('[data-first-run]');
if(!card)return;
function seen(){try{return window.localStorage.getItem(KEY)==='1';}catch(e){return false;}}
function hide(){card.hidden=true;}
if(seen())hide();
var btn=card.querySelector('[data-first-run-dismiss]');
if(btn)btn.addEventListener('click',function(){try{window.localStorage.setItem(KEY,'1');}catch(e){}hide();});
})();
</script>`
}

func (a *App) handleOSDashboard(w http.ResponseWriter, r *http.Request) {
	nonce := render.CSPNonce(r)
	cfg := a.getOSSettings(r.Context())
	snap := a.getAdminSnapshot()

	// Content workspace (dashboard redesign): the content areas that used to live in
	// the sidebar (Posts, Pages, Comments, Messages, Media, New Post, Website) are
	// surfaced here as premium tiles with live counts and notification badges. Counts
	// are cheap on-demand reads, so the 30s metrics collector is left untouched.
	onionMode := config.Cfg.OnionMode
	blogPosts := snap.TotalArticles - snap.TotalPages
	if blogPosts < 0 {
		blogPosts = 0
	}
	pendingComments := 0
	if dbpkg.DB != nil {
		_ = dbpkg.Reader().QueryRowContext(r.Context(), `SELECT COUNT(1) FROM comments WHERE status='pending'`).Scan(&pendingComments)
	}
	mediaCount := countMediaItems()
	// The Tor world's .onion is shown ONLY inside the Tor console itself — the
	// clearnet dashboard must never surface the anonymous address (ADR-0141
	// anti-correlation: the onion never appears alongside the clearnet identity).
	// Entering the Tor world is done from the sidebar world switch.
	worldCardHTML := ""
	if onionMode {
		worldCardHTML = osWorldCard(true, cfg.TorSpaceOn, cfg.TorSpaceRunning, config.Cfg.Domain)
	}
	workspaceHTML := osWorkspaceGrid(onionMode, blogPosts, snap.TotalPages, pendingComments, snap.UnreadMessages, mediaCount, cfg.AccessLevel)
	// First-run checklist (Wave 2.5): the short path from install to a live
	// site, assembled from cheap server-known facts and dismissed per browser.
	// Nil for operators who are past it — and never rendered for roles that
	// could not open the pages it links to.
	firstRunHTML := ""
	if items := a.osFirstRunChecklist(r.Context(), cfg.AccessLevel); len(items) > 0 {
		firstRunHTML = osFirstRunCard(items, nonce)
	}

	// Attention strip (Wave 2.2): the bell's warn/danger signals surfaced on the
	// dashboard itself, before the checklist and the world card.
	attentionHTML := osAttentionStrip(cfg.Notifications)

	body := `<!-- Quick compose -->
<div class="quick-compose" role="search">
  <span class="quick-compose-icon" aria-hidden="true">✍</span>
  <input id="quick-compose-input" class="quick-compose-input"
    type="text" placeholder="Start a new post… (press Enter)" autocomplete="off"
    aria-label="Quick compose: type a title and press Enter">
</div>
` + attentionHTML + firstRunHTML + worldCardHTML + workspaceHTML + `
<!-- System health -->
<div class="section-head"><span class="section-head__title">System health</span><span class="section-head__hint">Background jobs &amp; queue</span></div>
<div class="stat-grid">
  <div class="stat-card">
    <div class="stat-card__top">
      <div class="stat-card__label">Pending jobs</div>
      <div class="stat-card__icon stat-card__icon--accent">
        <svg viewBox="0 0 16 16" fill="none" width="16" height="16" aria-hidden="true"><path d="M8 3v5l3 3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.2"/></svg>
      </div>
    </div>
    <div class="stat-card__value">` + strconv.Itoa(snap.PendingJobs) + `</div>
    <div class="stat-card__bottom">
      <span class="muted text-xs">In queue</span>
    </div>
  </div>
  <div class="stat-card">
    <div class="stat-card__top">
      <div class="stat-card__label">Failed jobs</div>
      <div class="stat-card__icon stat-card__icon--warn">
        <svg viewBox="0 0 16 16" fill="none" width="16" height="16" aria-hidden="true"><path d="M8 5v4m0 2.5v.5M3 13h10L8 3 3 13z" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </div>
    </div>
    <div class="stat-card__value">` + strconv.Itoa(snap.FailedJobs) + `</div>
    <div class="stat-card__bottom">
      <span class="muted text-xs">Needs attention</span>
    </div>
  </div>
  <div class="stat-card">
    <div class="stat-card__top">
      <div class="stat-card__label">Completed</div>
      <div class="stat-card__icon stat-card__icon--ok">
        <svg viewBox="0 0 16 16" fill="none" width="16" height="16" aria-hidden="true"><path d="M4 8l3 3 5-5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.2"/></svg>
      </div>
    </div>
    <div class="stat-card__value">` + strconv.Itoa(snap.CompletedJobs) + `</div>
    <div class="stat-card__bottom">
      <span class="muted text-xs">All time</span>
    </div>
  </div>
</div>

<!-- Activity feed (full-width) -->
<div class="card">
  <div class="card-title">Recent activity</div>
  <div id="activity-feed" class="activity-list">
    <!-- Populated by admin-os.js via GET /os/api/activity -->
    <div class="skeleton skeleton--text mb-3"></div>
    <div class="skeleton skeleton--text mb-3 w-80"></div>
    <div class="skeleton skeleton--text w-65"></div>
  </div>
</div>`

	writeOSHTML(w, r, adminOSLayout(nonce, "Dashboard", "dashboard", cfg, htmpl.HTML(body)))
}

// ── Posts ────────────────────────────────────────────────────────────────────

// osPostsPageSize is how many posts the manager shows per page. The newest
// page (page 1) lists the latest osPostsPageSize posts; older posts live on
// subsequent pages reachable via the pager. This replaces the old hard
// `LIMIT 500` cap so every post is reachable regardless of archive size.
const osPostsPageSize = 100

// osPostStatusPill renders the status badge shown in the Posts manager for a
// post's current status ("draft" → Draft, anything else → Published).
func osPostStatusPill(status string) string {
	if status == "draft" {
		return `<span class="status-pill status-pill--draft">● Draft</span>`
	}
	return `<span class="status-pill status-pill--live">● Published</span>`
}

// osPostStatusButton renders the HTMX publish/unpublish toggle for a post in its
// CURRENT status. Clicking it POSTs the opposite status to the fragment endpoint
// (handleOSPostToggleFragment), which returns the flipped button plus an
// out-of-band swap of the status pill — so the row updates in place with no
// full-page reload. slugEsc must already be HTML-escaped by the caller.
// The button carries a stable per-slug id and data-src="body" so the fragment
// endpoint and the bulk updater can always tell the row-face copy from this
// accordion copy (Wave 3.5: the publish action lives on the row face too).
func osPostStatusButton(slugEsc, status string) string {
	label, to := "Unpublish", "draft"
	if status == "draft" {
		label, to = "Publish", "published"
	}
	return `<button type="button" id="post-pub-` + slugEsc + `" data-src="body" class="btn btn--ghost btn--sm"` +
		` hx-post="/os/api/posts/` + slugEsc + `/status-fragment"` +
		` hx-vals='{"status":"` + to + `"}'` +
		` hx-target="this" hx-swap="outerHTML" hx-disabled-elt="this">` + label + `</button>`
}

// osPostStatusFaceButton is the Wave 3.5 row-face copy of the publish toggle: a
// compact icon button rendered in the summary row itself, so the most common
// action (publish a draft) never requires opening the card. Same endpoint and
// id scheme as the accordion copy — data-src="face" tells the fragment endpoint
// which copy to return in place so BOTH copies flip on a single click.
func osPostStatusFaceButton(slugEsc, status string) string {
	glyph, label, to := "↥", "Publish", "published"
	if status != "draft" {
		glyph, label, to = "↧", "Unpublish", "draft"
	}
	return `<button type="button" id="post-pubface-` + slugEsc + `" data-src="face" class="btn btn--ghost btn--sm post-acc__face-btn"` +
		` title="` + label + ` (opens nothing — toggles right here)" aria-label="` + label + ` post"` +
		` hx-post="/os/api/posts/` + slugEsc + `/status-fragment"` +
		` hx-vals='{"status":"` + to + `","src":"face"}'` +
		` hx-target="this" hx-swap="outerHTML" hx-disabled-elt="this"><span aria-hidden="true">` + glyph + `</span></button>`
}

// osPostStatusButtonOOB renders the accordion publish toggle as an out-of-band
// swap target, so a click on the row-face copy also flips the hidden copy.
func osPostStatusButtonOOB(slugEsc, status string) string {
	return strings.Replace(osPostStatusButton(slugEsc, status),
		`data-src="body"`, `data-src="body" hx-swap-oob="true"`, 1)
}

// osPostStatusFaceButtonOOB renders the row-face publish toggle as an
// out-of-band swap target, so a click on the accordion copy also flips the face.
func osPostStatusFaceButtonOOB(slugEsc, status string) string {
	return strings.Replace(osPostStatusFaceButton(slugEsc, status),
		`data-src="face"`, `data-src="face" hx-swap-oob="true"`, 1)
}

// osPostStatusOOB renders the out-of-band status-pill update the fragment
// endpoint returns alongside the flipped button, keyed by the row's stable
// per-slug id so HTMX swaps only that cell.
func osPostStatusOOB(slugEsc, status string) string {
	return `<span id="post-status-` + slugEsc + `" hx-swap-oob="true">` + osPostStatusPill(status) + `</span>`
}

// osPostPinButton renders the HTMX pin/unpin toggle for a post in its CURRENT
// featured state. Clicking it POSTs the opposite state to the pin-fragment
// endpoint, which returns the flipped button plus an out-of-band swap of the
// row's "📌 Pinned" badge. slugEsc must already be HTML-escaped.
func osPostPinButton(slugEsc string, featured bool) string {
	label, to := "Pin", "1"
	if featured {
		label, to = "Unpin", "0"
	}
	return `<button type="button" id="post-pin-` + slugEsc + `" data-src="body" class="btn btn--ghost btn--sm"` +
		` hx-post="/os/api/posts/` + slugEsc + `/pin-fragment"` +
		` hx-vals='{"pinned":"` + to + `"}'` +
		` hx-target="this" hx-swap="outerHTML" hx-disabled-elt="this">` + label + `</button>`
}

// osPostPinFaceButton is the Wave 3.5 row-face copy of the pin toggle: one click
// pins or unpins from the summary row, without opening the card.
func osPostPinFaceButton(slugEsc string, featured bool) string {
	label, glyph, to := "Pin", "📌", "1"
	if featured {
		label, glyph, to = "Unpin", "📍", "0"
	}
	return `<button type="button" id="post-pinface-` + slugEsc + `" data-src="face" class="btn btn--ghost btn--sm post-acc__face-btn"` +
		` title="` + label + ` (toggles right here)" aria-label="` + label + ` post"` +
		` hx-post="/os/api/posts/` + slugEsc + `/pin-fragment"` +
		` hx-vals='{"pinned":"` + to + `","src":"face"}'` +
		` hx-target="this" hx-swap="outerHTML" hx-disabled-elt="this"><span aria-hidden="true">` + glyph + `</span></button>`
}

// osPostPinButtonOOB renders the accordion pin toggle as an out-of-band swap
// target, so a click on the row-face copy also flips the hidden copy.
func osPostPinButtonOOB(slugEsc string, featured bool) string {
	return strings.Replace(osPostPinButton(slugEsc, featured),
		`data-src="body"`, `data-src="body" hx-swap-oob="true"`, 1)
}

// osPostPinFaceButtonOOB renders the row-face pin toggle as an out-of-band swap
// target, so a click on the accordion copy also flips the face.
func osPostPinFaceButtonOOB(slugEsc string, featured bool) string {
	return strings.Replace(osPostPinFaceButton(slugEsc, featured),
		`data-src="face"`, `data-src="face" hx-swap-oob="true"`, 1)
}

// osPostPinBadge renders the pinned indicator next to a post's title, keyed by a
// stable per-slug id so the pin toggle can update it out-of-band. It is always
// emitted (empty when unpinned) so the OOB target exists for a later pin.
func osPostPinBadge(slugEsc string, featured, oob bool) string {
	inner := ""
	if featured {
		inner = ` <span class="chip" title="Pinned to the homepage and trending widget">📌 Pinned</span>`
	}
	oobAttr := ""
	if oob {
		oobAttr = ` hx-swap-oob="true"`
	}
	return `<span id="ppin-` + slugEsc + `"` + oobAttr + `>` + inner + `</span>`
}

// osIndexNowBadge renders a post's IndexNow (search-engine instant-index)
// submission state as a small chip, keyed by a stable per-slug id so the manual
// re-ping can swap it out-of-band. slugEsc must already be HTML-escaped. Drafts
// are not public, so they show a neutral "—" instead of a submission state.
func osIndexNowBadge(slugEsc string, st dbpkg.IndexNowStatus, ok, isDraft bool) string {
	var inner string
	switch {
	case isDraft:
		inner = `<span class="chip" title="Drafts are not public, so nothing is submitted to IndexNow until you publish.">IndexNow: —</span>`
	case ok && st.State == dbpkg.IndexNowSubmitted:
		when := st.SubmittedAt.Format("2 Jan 2006 15:04 UTC")
		inner = `<span class="chip chip--brand" title="Submitted to IndexNow on ` + html.EscapeString(when) + `">✓ IndexNow</span>`
	case ok && st.State == dbpkg.IndexNowPending:
		// HTTP 202 — received, but the engine has not yet validated the key file.
		// Shown distinctly on purpose: if that validation fails the URL is dropped
		// silently, so a tick here would be a claim the install cannot support.
		when := st.SubmittedAt.Format("2 Jan 2006 15:04 UTC")
		title := st.Detail
		if title == "" {
			title = "The engine received this URL but has not finished validating your key file."
		}
		inner = `<span class="chip" style="color:#f59e0b" title="` + html.EscapeString(title+" Sent "+when) + `">◌ IndexNow pending</span>`
	case ok && st.State == dbpkg.IndexNowFailed:
		inner = `<span class="chip" style="color:#f59e0b" title="` + html.EscapeString(st.Detail) + `">⚠ IndexNow failed</span>`
	default:
		inner = `<span class="chip" title="Not yet submitted to IndexNow. Use “Ping IndexNow” to submit it now.">IndexNow: not sent</span>`
	}
	return `<span id="post-indexnow-` + slugEsc + `">` + inner + `</span>`
}

// osIndexNowBadgeOOB is the out-of-band variant returned by the manual re-ping
// endpoint so HTMX updates just that post's badge in place.
func osIndexNowBadgeOOB(slugEsc string, st dbpkg.IndexNowStatus, ok, isDraft bool) string {
	base := osIndexNowBadge(slugEsc, st, ok, isDraft)
	return strings.Replace(base, `<span id="post-indexnow-`+slugEsc+`">`, `<span id="post-indexnow-`+slugEsc+`" hx-swap-oob="true">`, 1)
}

// osIndexNowButton renders the manual "Ping IndexNow" control. It is only
// meaningful for a published post (a draft has no public URL to announce), so it
// returns empty for drafts. The label reads "Re-ping" once a post was already
// submitted. Clicking POSTs to the fragment endpoint, which returns the flipped
// button plus an out-of-band badge update.
func osIndexNowButton(slugEsc string, st dbpkg.IndexNowStatus, ok, isDraft bool) string {
	if isDraft {
		return ""
	}
	label := "Ping IndexNow"
	if ok && (st.State == dbpkg.IndexNowSubmitted || st.State == dbpkg.IndexNowPending) {
		label = "Re-ping"
	}
	return `<button type="button" class="btn btn--ghost btn--sm"` +
		` hx-post="/os/api/posts/` + slugEsc + `/indexnow-fragment"` +
		` hx-target="this" hx-swap="outerHTML" hx-disabled-elt="this">` + label + `</button>`
}

func (a *App) handleOSPosts(w http.ResponseWriter, r *http.Request) {
	nonce := render.CSPNonce(r)
	cfg := a.getOSSettings(r.Context())

	// A CSRF token cookie so the inline publish/unpublish control can POST.
	csrfTokenFor(w, r)

	// ── Parse filters from the query string ──────────────────────────────────
	qv := r.URL.Query()
	q := strings.TrimSpace(qv.Get("q"))
	if len(q) > 120 {
		q = q[:120]
	}
	status := qv.Get("status")
	if status != "published" && status != "draft" {
		status = "all"
	}
	period := qv.Get("period")
	from := normalizeDateParam(qv.Get("from"))
	to := normalizeDateParam(qv.Get("to"))
	// A period preset is a shortcut for a created-at window. An explicit custom
	// from/to range always wins; the preset only applies when no range is set.
	if from == "" && to == "" {
		if since := periodSince(period); since != "" {
			from = since
		} else {
			period = "all"
		}
	} else {
		period = "" // a custom range overrides the preset selector
	}

	// ── Shared filter predicate (search + date range), independent of the
	// status tab so the tab counts reflect the active search/date filter. ──
	// Pages (is_page=1) are managed on /os/pages, not in the blog feed, so the
	// Posts manager only ever lists real posts.
	where := []string{"is_page=0"}
	args := []any{}
	if q != "" {
		where = append(where, "(title LIKE ? OR COALESCE(tags,'') LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like)
	}
	if from != "" {
		where = append(where, "date(created_at) >= ?")
		args = append(args, from)
	}
	if to != "" {
		where = append(where, "date(created_at) <= ?")
		args = append(args, to)
	}
	filterClause := ""
	if len(where) > 0 {
		filterClause = " WHERE " + strings.Join(where, " AND ")
	}

	// ── Status counts within the active filter ───────────────────────────────
	// A bounded context so a slow or contended query can never hang the request
	// until the upstream proxy gives up — the cause of the intermittent 502 on
	// large catalogs. On deadline the queries return an error and the handler
	// degrades to a friendly, retryable page (HTTP 200) instead of a gateway
	// error.
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	loadErr := false

	allCount, published, drafts := 0, 0, 0
	if dbpkg.DB != nil {
		// status is NOT NULL DEFAULT 'published' (migration 030), so we group by
		// the bare column — `COALESCE(status,'published')` would defeat
		// idx_articles_status and force a full-table scan (a 502-class stall on a
		// large catalog). With no search/date filter this is an index-only count.
		if rows, err := dbpkg.Reader().QueryContext(ctx,
			`SELECT status s, COUNT(1) c FROM articles`+filterClause+` GROUP BY status`, args...); err == nil {
			for rows.Next() {
				var s string
				var c int
				if rows.Scan(&s, &c) == nil {
					allCount += c
					if s == "draft" {
						drafts += c
					} else {
						published += c
					}
				}
			}
			_ = rows.Err() // best-effort admin status counts
			rows.Close()
		} else {
			loadErr = true
		}
	}
	total := allCount
	switch status {
	case "published":
		total = published
	case "draft":
		total = drafts
	}

	// ── Pagination maths (100 per page; page clamped to a valid range) ────────
	totalPages := (total + osPostsPageSize - 1) / osPostsPageSize
	if totalPages < 1 {
		totalPages = 1
	}
	page := 1
	if p, err := strconv.Atoi(qv.Get("page")); err == nil && p > 1 {
		page = p
	}
	if page > totalPages {
		page = totalPages
	}
	offset := (page - 1) * osPostsPageSize

	// ── Fetch the current page of posts (drafts included; the public site never
	// surfaces drafts but the manager must). ──────────────────────────────────
	type postRow struct {
		Title, Slug, Status string
		Tags                []string
		Updated             time.Time
		Featured            bool
	}
	var posts []postRow
	listWhere := append([]string{}, where...)
	listArgs := append([]any{}, args...)
	switch status {
	case "published":
		listWhere = append(listWhere, "status='published'")
	case "draft":
		listWhere = append(listWhere, "status='draft'")
	}
	listClause := ""
	if len(listWhere) > 0 {
		listClause = " WHERE " + strings.Join(listWhere, " AND ")
	}
	listArgs = append(listArgs, osPostsPageSize, offset)
	if dbpkg.DB != nil {
		if rows, err := dbpkg.Reader().QueryContext(ctx,
			`SELECT title,slug,COALESCE(tags,''),updated_at,COALESCE(status,'published'),COALESCE(featured,0) FROM articles`+listClause+` ORDER BY created_at DESC LIMIT ? OFFSET ?`, listArgs...); err == nil {
			defer rows.Close()
			for rows.Next() {
				var p postRow
				var tagsCSV string
				var featured int
				if rows.Scan(&p.Title, &p.Slug, &tagsCSV, &p.Updated, &p.Status, &featured) == nil {
					p.Tags = splitCSVTags(tagsCSV)
					p.Featured = featured != 0
					posts = append(posts, p)
				}
			}
			_ = rows.Err() // best-effort admin post list
		} else {
			loadErr = true
		}
	}

	filtersActive := q != "" || from != "" || to != "" || status != "all"

	// When a query times out or errors we never want to mislead the operator
	// with the "No posts yet" empty state; instead we render the manager shell
	// with a non-blocking retry notice so the page always loads.
	notice := ""
	if loadErr {
		notice = `<div class="card load-notice"><strong>Couldn't load everything just now</strong> — the database was busy. <a href="/os/posts">Retry</a>.</div>`
	}

	var body string
	if allCount == 0 && !filtersActive && !loadErr {
		body = `<div class="page-header"><h1>Posts</h1></div>
<div class="card empty-state">
  <div class="empty-icon">✍️</div>
  <div class="empty-title">No posts yet</div>
  <div class="empty-sub">Your articles will appear here. Write your first one — it only takes a minute.</div>
  <a class="btn btn--primary mt-4" href="/os/editor">Write your first post</a>
</div>`
	} else {
		// Batch-load each shown post's IndexNow submission status in one query
		// (avoids an N+1) so every row can show whether it was announced to
		// search engines and offer a manual re-ping.
		slugList := make([]string, 0, len(posts))
		for _, p := range posts {
			slugList = append(slugList, p.Slug)
		}
		inStatus := dbpkg.IndexNowStatuses(slugList)
		cards := ""
		for _, p := range posts {
			tags := ""
			for _, t := range p.Tags {
				tags += `<span class="chip chip--brand">#` + html.EscapeString(t) + `</span> `
			}
			esc := html.EscapeString(p.Slug)
			isDraft := p.Status == "draft"
			inSt, inOK := inStatus[p.Slug]
			viewBtn := `<a class="btn btn--ghost btn--sm" href="/` + esc + `" target="_blank" rel="noopener">View ↗</a>`
			if isDraft {
				// A draft is hidden from the public site (previewed in the editor).
				viewBtn = ""
			}
			tagsBlock := ""
			if tags != "" {
				tagsBlock = `
      <div class="post-acc__tags">` + tags + `</div>`
			}
			// Each post is a premium collapsible card (Monetization-console style).
			// The bulk-select checkbox sits OUTSIDE the <summary> (column 1 of the
			// row grid) so ticking it never toggles the card; tapping the card body
			// reveals ONLY that post's actions. Pin/status/IndexNow keep their stable
			// per-slug ids so the HTMX out-of-band swaps still land in place.
			cards += `<div class="post-row" data-post-row>
  <input type="checkbox" class="post-acc__check" data-post-select value="` + esc + `" aria-label="Select ` + html.EscapeString(p.Title) + `">
  <details class="mon-acc post-acc">
    <summary class="mon-acc__sum">
      <span class="mon-acc__head">
        <span class="mon-acc__title">` + html.EscapeString(p.Title) + osPostPinBadge(esc, p.Featured, false) + `</span>
        <span class="mon-acc__sub">/` + esc + ` · Updated ` + config.FormatSite(p.Updated, "2 Jan 2006") + `</span>
      </span>
      <span id="post-status-` + esc + `" class="post-acc__status">` + osPostStatusPill(p.Status) + `</span>
      <span class="post-acc__face">` + osPostStatusFaceButton(esc, p.Status) + osPostPinFaceButton(esc, p.Featured) + `</span>
      <svg class="mon-acc__chev" viewBox="0 0 20 20" width="16" height="16" fill="none" aria-hidden="true"><path d="M6 8l4 4 4-4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </summary>
    <div class="mon-acc__body post-acc__body">` + tagsBlock + `
      <div class="post-acc__meta-row">` + osIndexNowBadge(esc, inSt, inOK, isDraft) + `</div>
      <div class="post-acc__actions">
        <a class="btn btn--primary btn--sm" href="/os/editor/` + esc + `">Edit</a>
        ` + viewBtn + `
        ` + osPostPinButton(esc, p.Featured) + `
        ` + osPostStatusButton(esc, p.Status) + `
        ` + osIndexNowButton(esc, inSt, inOK, isDraft) + `
        <button type="button" class="btn btn--ghost btn--sm" data-post-delete data-slug="` + esc + `" data-title="` + html.EscapeString(p.Title) + `">Delete</button>
      </div>
    </div>
  </details>
</div>`
		}

		listBlock := `<div class="post-list-head">
    <label class="post-selectall"><input type="checkbox" data-post-select-all aria-label="Select all posts on this page"> Select all on this page</label>
    <span class="muted text-xs">Tap a post to see its actions</span>
  </div>
  <div class="mon-stack post-stack">` + cards + `</div>`
		if len(posts) == 0 {
			listBlock = `<div class="table-empty">No posts match your filter. <a href="/os/posts">Clear filters</a>.</div>`
		}

		shownFrom, shownTo := 0, 0
		if len(posts) > 0 {
			shownFrom = offset + 1
			shownTo = offset + len(posts)
		}

		body = notice + `<div class="page-header">
  <h1>Posts <span class="count-pill">` + strconv.Itoa(allCount) + `</span></h1>
  <div class="page-actions">
    <a class="btn btn--primary" href="/os/editor">New Post</a>
  </div>
</div>
<p class="page-sub">Every article in one place — search, filter by status or date, publish or unpublish inline, and see at a glance what's announced to search engines.</p>
<div class="stat-grid mb-6">
  <div class="stat-card"><div class="stat-card__label">Total posts</div><div class="stat-card__value">` + strconv.Itoa(allCount) + `</div><div class="stat-card__bottom"><span class="muted text-xs">across your whole catalogue</span></div></div>
  <div class="stat-card"><div class="stat-card__label">Published</div><div class="stat-card__value">` + strconv.Itoa(published) + `</div><div class="stat-card__bottom"><span class="muted text-xs">live on your site</span></div></div>
  <div class="stat-card"><div class="stat-card__label">Drafts</div><div class="stat-card__value">` + strconv.Itoa(drafts) + `</div><div class="stat-card__bottom"><span class="muted text-xs">not yet published</span></div></div>
</div>
<div class="card">
  <div class="toolbar-row">
    <form class="posts-filter" method="GET" action="/os/posts" role="search">
      <input type="hidden" name="status" value="` + html.EscapeString(status) + `">
      <input class="input search-input" type="search" name="q" value="` + html.EscapeString(q) + `" placeholder="Search by title or tag…" aria-label="Search posts">
      ` + osPostsPeriodSelect(period) + `
      <label class="posts-filter-date">From <input class="input input--sm" type="date" name="from" value="` + html.EscapeString(from) + `" aria-label="From date"></label>
      <label class="posts-filter-date">To <input class="input input--sm" type="date" name="to" value="` + html.EscapeString(to) + `" aria-label="To date"></label>
      <button class="btn btn--ghost btn--sm" type="submit">Filter</button>
      <a class="btn btn--ghost btn--sm" href="/os/posts">Clear</a>
    </form>
    <div class="seg-filter" role="tablist" aria-label="Filter by status">
      <a class="seg-btn` + osActiveCls(status == "all") + `" href="` + osPostsHref("all", q, from, to, period, 1) + `">All <span class="muted">` + strconv.Itoa(allCount) + `</span></a>
      <a class="seg-btn` + osActiveCls(status == "published") + `" href="` + osPostsHref("published", q, from, to, period, 1) + `">Published <span class="muted">` + strconv.Itoa(published) + `</span></a>
      <a class="seg-btn` + osActiveCls(status == "draft") + `" href="` + osPostsHref("draft", q, from, to, period, 1) + `">Drafts <span class="muted">` + strconv.Itoa(drafts) + `</span></a>
    </div>
  </div>
  <div class="bulk-bar" data-post-bulkbar hidden>
    <span class="text-sm"><span data-post-bulk-count>0</span> selected</span>
    <button type="button" class="btn btn--ghost btn--sm" data-post-bulk="published">Publish</button>
    <button type="button" class="btn btn--ghost btn--sm" data-post-bulk="draft">Unpublish</button>
    <button type="button" class="btn btn--ghost btn--sm" data-post-bulk="delete">Delete</button>
  </div>
  ` + listBlock + `
  ` + osPostsPager(status, q, from, to, period, page, totalPages, total, shownFrom, shownTo) + `
</div>
<div id="action-msg" role="status" aria-live="polite" class="action-msg"></div>
<script nonce="` + nonce + `">
(function(){'use strict';
function csrf(){var m=document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);return m?m[1]:'';}
var msg=document.getElementById('action-msg');
function show(t,e){if(!msg)return;msg.textContent=t;msg.classList.toggle('is-error',!!e);msg.classList.add('visible');}
// Pin/unpin is HTMX-driven (hx-post → out-of-band button + badge update); see
// osPostPinButton and handleOSPostPinFragment. No JS handler needed here.
// Publish/unpublish is HTMX-driven (hx-post → out-of-band row update); see
// osPostStatusButton and handleOSPostToggleFragment. No JS handler needed here.
document.querySelectorAll('[data-post-delete]').forEach(function(b){
  b.addEventListener('click',function(){
    var t=b.getAttribute('data-title')||'this post';
    vpConfirm({title:'Delete post',message:'Delete "'+t+'"? This permanently removes the post and its comments and cannot be undone.',confirm:'Delete'},function(){
      b.disabled=true;
      fetch('/os/api/posts/'+encodeURIComponent(b.getAttribute('data-slug')),{method:'DELETE',headers:{'X-CSRF-Token':csrf()}})
        .then(function(r){return r.json().then(function(d){return{ok:r.ok,d:d};});})
        .then(function(res){if(res.ok){show('Deleted',false);var row=b.closest('[data-post-row]');if(row)row.remove();}else{b.disabled=false;show(res.d.detail||res.d.title||'Error',true);}})
        .catch(function(e){b.disabled=false;show('Error: '+e,true);});
    });
  });
});
// ── Bulk selection + actions ──────────────────────────────────────────────────
var bulkBar=document.querySelector('[data-post-bulkbar]');
var bulkCount=document.querySelector('[data-post-bulk-count]');
var selectAll=document.querySelector('[data-post-select-all]');
function selectedSlugs(){return Array.prototype.slice.call(document.querySelectorAll('[data-post-select]:checked')).map(function(c){return c.value;});}
function refreshBulk(){var n=selectedSlugs().length;if(bulkCount)bulkCount.textContent=String(n);if(bulkBar)bulkBar.hidden=n===0;}
document.querySelectorAll('[data-post-select]').forEach(function(c){c.addEventListener('change',refreshBulk);});
if(selectAll)selectAll.addEventListener('change',function(){document.querySelectorAll('[data-post-select]').forEach(function(c){c.checked=selectAll.checked;});refreshBulk();});
document.querySelectorAll('[data-post-bulk]').forEach(function(b){
  b.addEventListener('click',function(){
    var slugs=selectedSlugs();if(!slugs.length)return;
    var act=b.getAttribute('data-post-bulk');
    if(act==='delete'){vpConfirm({title:'Delete posts',message:'Delete '+slugs.length+' post'+(slugs.length>1?'s':'')+'? This cannot be undone.',confirm:'Delete'},function(){runBulk(b,act,slugs);});return;}
    runBulk(b,act,slugs);
  });
});
function runBulk(b,act,slugs){
    b.disabled=true;show(act==='delete'?'Deleting…':'Updating…',false);
    fetch('/os/api/posts/bulk',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:JSON.stringify({action:act,slugs:slugs})})
      .then(function(r){return r.json().then(function(d){return{ok:r.ok,d:d};});})
      .then(function(res){
        if(!res.ok){b.disabled=false;show((res.d&&res.d.detail)||'Bulk request failed',true);return;}
        var d=res.d,fail=[];
        (d.results||[]).forEach(function(r0){
          var row=null;
          document.querySelectorAll('[data-post-select]').forEach(function(c){if(c.value===r0.slug)row=c.closest('[data-post-row]');});
          if(r0.ok){
            if(act==='delete'){if(row)row.remove();}
            else{
              var pill=document.getElementById('post-status-'+r0.slug);if(pill&&r0.pill)pill.innerHTML=r0.pill;
              if(row&&r0.button){var btn=row.querySelector('button[hx-post$="/status-fragment"][data-src="body"]');if(btn)btn.outerHTML=r0.button;}
              if(row){var chk=row.querySelector('[data-post-select]');if(chk)chk.checked=false;}
            }
          }else{fail.push(r0.slug+(r0.error?': '+r0.error:''));}
        });
        if(d.counts){var seg=document.querySelectorAll('.seg-btn .muted');if(seg.length>=3){seg[0].textContent=String(d.counts.all||0);seg[1].textContent=String(d.counts.published||0);seg[2].textContent=String(d.counts.draft||0);}}
        refreshBulk();
        if(fail.length){b.disabled=false;show('Failed: '+fail.join('; '),true);}
        else{show('Done — '+d.ok+(act==='delete'?' deleted':' updated'),false);setTimeout(function(){b.disabled=false;},800);}
      })
      .catch(function(e){b.disabled=false;show('Error: '+e,true);});
}
})();
</script>`
	}
	writeOSHTML(w, r, adminOSLayout(nonce, "Posts", "posts", cfg, htmpl.HTML(body)))
}

// ── Comments moderation ──────────────────────────────────────────────────────

// commentIDRe is the strict allowlist for a comment id. Comment ids are
// generated as 24 lowercase hex chars (comments.newID), so a value outside this
// set is invalid input — validating against it before the id is ever reflected
// into the moderation fragment removes any HTML/URL/CSS-injection vector
// (reflected XSS, CodeQL go/reflected-xss).
var commentIDRe = regexp.MustCompile(`^[0-9a-f]{1,64}$`)

// canonicalCommentStatus maps a requested moderation status to a fixed,
// compile-time constant (or "" if unrecognised). Returning a literal — rather
// than the request string — means the value later reflected into the moderation
// fragment is provably not request-tainted, which removes the reflected-XSS
// flow at the source (defence in depth alongside output escaping).
func canonicalCommentStatus(s string) string {
	switch strings.TrimSpace(s) {
	case "approved":
		return "approved"
	case "rejected":
		return "rejected"
	case "spam":
		return "spam"
	default:
		return ""
	}
}

// osCommentPill renders a comment's status badge. It carries a stable per-id id
// and a data-status attribute so the client-side status filter can read the live
// status after an HTMX moderation swap. When oob is true it is emitted as an
// out-of-band swap so the fragment endpoint can update the pill in place. idEsc
// and status must already be safe (escaped id; status from the validated enum).
func osCommentPill(idEsc, status string, oob bool) string {
	cls := "status-pill"
	switch status {
	case "approved":
		cls = "status-pill status-pill--live"
	case "pending":
		cls = "status-pill status-pill--draft"
	}
	oobAttr := ""
	if oob {
		oobAttr = ` hx-swap-oob="true"`
	}
	// status is escaped in BOTH the attribute and the text: it reaches here from
	// request input on the moderation-fragment path, and an unescaped reflection
	// (even of a validated value) is a reflected-XSS sink (CodeQL go/reflected-xss).
	esc := html.EscapeString(status)
	return `<span class="` + cls + `" id="cpill-` + idEsc + `" data-status="` + esc + `"` + oobAttr + `>● ` + esc + `</span>`
}

// osCommentActions renders the moderation buttons for a comment in its CURRENT
// status (the action matching the current status is omitted). Each button is
// HTMX-driven: it POSTs the new status to the fragment endpoint and swaps the
// row's action cell in place, so moderation needs no full-page reload. The
// buttons depend only on (id, status), so the fragment endpoint can re-render
// them without re-fetching the comment. idEsc must already be HTML-escaped.
func osCommentActions(idEsc, status string) string {
	btn := func(to, label, cls string) string {
		if status == to {
			return ""
		}
		return `<button type="button" class="btn ` + cls + ` btn--sm"` +
			` hx-post="/os/api/comments/` + idEsc + `/status-fragment"` +
			` hx-vals='{"status":"` + to + `"}'` +
			` hx-target="#cact-` + idEsc + `" hx-swap="innerHTML" hx-disabled-elt="this">` + label + `</button> `
	}
	return btn("approved", "Approve", "btn--primary") + btn("rejected", "Reject", "btn--ghost") + btn("spam", "Spam", "btn--ghost")
}

func (a *App) handleOSComments(w http.ResponseWriter, r *http.Request) {
	nonce := render.CSPNonce(r)
	cfg := a.getOSSettings(r.Context())

	// CSRF token cookie so the inline approve/reject controls can POST.
	csrfTokenFor(w, r)

	var body string
	if a.commentStore == nil {
		body = `<div class="page-header"><h1>Comments</h1></div>
<div class="card empty-state"><div class="empty-icon">💬</div>
<div class="empty-title">Comments unavailable</div>
<div class="empty-sub">The comment store is not initialised.</div></div>`
		writeOSHTML(w, r, adminOSLayout(nonce, "Comments", "comments", cfg, htmpl.HTML(body)))
		return
	}

	// Resolve slugs only for the articles referenced by the comments shown
	// (≤500), via the read pool. At scale the catalog can hold hundreds of
	// thousands of posts, so loading the entire id→slug map per page view — and
	// on the single writer connection — does not scale.
	all, _ := a.commentStore.ListAll(r.Context(), "all", 500)
	slugByID := map[string]string{}
	seenID := map[string]bool{}
	ids := make([]any, 0, len(all))
	for _, c := range all {
		if c.ArticleID != "" && !seenID[c.ArticleID] {
			seenID[c.ArticleID] = true
			ids = append(ids, c.ArticleID)
		}
	}
	if len(ids) > 0 {
		ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
		if rows, err := dbpkg.Reader().QueryContext(r.Context(), `SELECT id, slug FROM articles WHERE id IN (`+ph+`)`, ids...); err == nil {
			defer rows.Close() //nolint:errcheck
			for rows.Next() {
				var id, slug string
				if rows.Scan(&id, &slug) == nil {
					slugByID[id] = slug
				}
			}
			_ = rows.Err() // best-effort id→slug map for comment links
		}
	}

	var pending, approved int
	rowsHTML := ""
	for _, c := range all {
		switch c.Status {
		case "pending":
			pending++
		case "approved":
			approved++
		}
		idEsc := html.EscapeString(c.ID)
		slug := slugByID[c.ArticleID]
		postCell := html.EscapeString(slug)
		if slug != "" {
			postCell = `<a href="/` + html.EscapeString(slug) + `" target="_blank" rel="noopener">/` + html.EscapeString(slug) + `</a>`
		}
		// The status filter reads data-status off the pill (updated in place by the
		// HTMX moderation swap), not off the <tr>, so a moderated row re-filters
		// correctly without a full-page reload.
		rowsHTML += `<tr data-comment-row>
  <td class="row-title"><strong>` + html.EscapeString(c.Author) + `</strong>
    <div class="row-meta">` + html.EscapeString(c.Email) + `</div></td>
  <td>` + html.EscapeString(c.Body) + `</td>
  <td>` + postCell + `</td>
  <td class="text-sm">` + geoDisplayHTML(c.Country, c.City) + `</td>
  <td>` + osCommentPill(idEsc, c.Status, false) + `</td>
  <td class="muted text-sm">` + config.FormatSite(c.CreatedAt, "2 Jan 2006 15:04") + `</td>
  <td class="row-actions" id="cact-` + idEsc + `">` + osCommentActions(idEsc, c.Status) + `</td>
</tr>`
	}

	if len(all) == 0 {
		body = `<div class="page-header"><h1>Comments</h1></div>
<div class="card empty-state"><div class="empty-icon">💬</div>
<div class="empty-title">No comments yet</div>
<div class="empty-sub">When readers comment on your articles, they appear here for moderation before going public.</div></div>`
	} else {
		body = `<div class="page-header">
  <h1>Comments <span class="count-pill">` + strconv.Itoa(len(all)) + `</span></h1>
  <div class="page-actions"><span class="text-sm muted"><span id="cc-sum-pending">` + strconv.Itoa(pending) + `</span> pending · <span id="cc-sum-approved">` + strconv.Itoa(approved) + `</span> approved</span></div>
</div>
<p class="page-sub">Moderate the conversation on your posts — approve, reply to or remove comments before they go public.</p>
<div class="card">
  <div class="toolbar-row">
    <div class="seg-filter" role="tablist" aria-label="Filter by status">
      <button type="button" class="seg-btn is-active" data-comment-filter="all">All <span class="muted">` + strconv.Itoa(len(all)) + `</span></button>
      <button type="button" class="seg-btn" data-comment-filter="pending">Pending <span class="muted" id="cc-pending">` + strconv.Itoa(pending) + `</span></button>
      <button type="button" class="seg-btn" data-comment-filter="approved">Approved <span class="muted" id="cc-approved">` + strconv.Itoa(approved) + `</span></button>
    </div>
  </div>
  <div class="table-wrap">
    <table class="table">
      <thead><tr><th>Author</th><th>Comment</th><th>Post</th><th>Location</th><th>Status</th><th>When</th><th></th></tr></thead>
      <tbody>` + rowsHTML + `</tbody>
    </table>
  </div>
  <div class="table-empty" data-filter-empty hidden>No comments match this filter.</div>
</div>
<div id="action-msg" role="status" aria-live="polite" class="action-msg"></div>
<script nonce="` + nonce + `">
(function(){'use strict';
// Moderation is HTMX-driven (hx-post → swap the row's action cell + out-of-band
// pill and counts); see osCommentActions and handleOSCommentModerateFragment.
// The filter reads each row's live status from its pill's data-status (updated
// by the swap) and re-applies after every HTMX swap so a moderated row moves to
// the right tab without a page reload.
var activeFilter='all';
function applyFilter(){
  document.querySelectorAll('[data-comment-row]').forEach(function(row){
    var pill=row.querySelector('[data-status]');
    var st=pill?pill.getAttribute('data-status'):'';
    row.hidden=(activeFilter!=='all'&&st!==activeFilter);
  });
}
document.querySelectorAll('[data-comment-filter]').forEach(function(s){
  s.addEventListener('click',function(){
    document.querySelectorAll('[data-comment-filter]').forEach(function(x){x.classList.remove('is-active');});
    s.classList.add('is-active');
    activeFilter=s.getAttribute('data-comment-filter');
    applyFilter();
  });
});
document.body.addEventListener('htmx:afterSwap',applyFilter);
})();
</script>`
	}
	writeOSHTML(w, r, adminOSLayout(nonce, "Comments", "comments", cfg, htmpl.HTML(body)))
}

// handleOSCommentModerateFragment is the HTMX counterpart to handleCommentModerate:
// it moderates a comment and returns an HTML fragment — the row's new action
// buttons (main swap) plus out-of-band updates of its status pill and the
// pending/approved counts — so the Comments manager updates in place with no
// full-page reload. CSRF is enforced by the route's CSRFTokenMiddleware (the
// admin layout mirrors the vp_csrf cookie into the X-CSRF-Token header for every
// hx-* request). The JSON PUT endpoint remains for API clients.
func (a *App) handleOSCommentModerateFragment(w http.ResponseWriter, r *http.Request) {
	if a.commentStore == nil {
		http.Error(w, "comments not initialised", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	// Map the requested status to a compile-time constant rather than passing the
	// request string through: the value later reflected into the response fragment
	// is then provably untainted (not request-derived), closing the reflected-XSS
	// vector at the source. Likewise the id is constrained to a well-formed comment
	// id (hex) before it is used or echoed.
	status := canonicalCommentStatus(r.FormValue("status"))
	if !commentIDRe.MatchString(id) || status == "" {
		http.Error(w, "a valid comment id and status (approved|rejected|spam) are required", http.StatusBadRequest)
		return
	}
	if err := a.commentStore.Moderate(r.Context(), id, status); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Mirror the JSON path's side effects: notify on approval.
	if status == "approved" {
		go a.notifyCommentApproved(context.WithoutCancel(r.Context()), id)
		go a.notifyCommentReply(context.WithoutCancel(r.Context()), id)
	}
	// Recompute pending/approved for the out-of-band count badges via the store's
	// GROUP BY count (accurate on any size catalog and cheaper than re-listing).
	// Only these two change on a status move; the All total is unaffected.
	pending, approved := 0, 0
	if counts, err := a.commentStore.Count(r.Context()); err == nil {
		pending = int(counts["pending"])
		approved = int(counts["approved"])
	}
	idEsc := html.EscapeString(id)
	p, ap := strconv.Itoa(pending), strconv.Itoa(approved)
	frag := osCommentActions(idEsc, status) +
		osCommentPill(idEsc, status, true) +
		`<span id="cc-pending" class="muted" hx-swap-oob="true">` + p + `</span>` +
		`<span id="cc-approved" class="muted" hx-swap-oob="true">` + ap + `</span>` +
		`<span id="cc-sum-pending" hx-swap-oob="true">` + p + `</span>` +
		`<span id="cc-sum-approved" hx-swap-oob="true">` + ap + `</span>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(frag))
}

// osActiveCls returns the " is-active" class suffix when active is true.
func osActiveCls(active bool) string {
	if active {
		return " is-active"
	}
	return ""
}

// normalizeDateParam validates a YYYY-MM-DD date string, returning "" if it is
// empty or malformed so an invalid value never reaches the SQL query.
func normalizeDateParam(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return ""
	}
	return s
}

// periodSince maps a preset time-window key to an inclusive lower-bound date
// (YYYY-MM-DD, UTC). An empty return means "all time" / unrecognised key.
func periodSince(period string) string {
	var days int
	switch period {
	case "7d":
		days = 7
	case "30d":
		days = 30
	case "90d":
		days = 90
	case "365d":
		days = 365
	default:
		return ""
	}
	return time.Now().UTC().AddDate(0, 0, -(days - 1)).Format("2006-01-02")
}

// osPostsPeriodSelect renders the time-range preset dropdown with the active
// option preselected.
func osPostsPeriodSelect(period string) string {
	opts := []struct{ Val, Label string }{
		{"all", "Any time"},
		{"7d", "Last 7 days"},
		{"30d", "Last 30 days"},
		{"90d", "Last 90 days"},
		{"365d", "Last 12 months"},
	}
	cur := period
	if cur == "" {
		cur = "all"
	}
	out := `<select class="select select--inline" name="period" aria-label="Time range">`
	for _, o := range opts {
		sel := ""
		if o.Val == cur {
			sel = " selected"
		}
		out += `<option value="` + o.Val + `"` + sel + `>` + o.Label + `</option>`
	}
	out += `</select>`
	return out
}

// osPostsHref builds a /os/posts URL that preserves the active filters while
// overriding the status tab and target page. Default values are omitted so the
// query string stays clean and shareable.
func osPostsHref(status, q, from, to, period string, page int) string {
	v := url.Values{}
	if status != "" && status != "all" {
		v.Set("status", status)
	}
	if q != "" {
		v.Set("q", q)
	}
	if from != "" {
		v.Set("from", from)
	}
	if to != "" {
		v.Set("to", to)
	}
	if period != "" && period != "all" {
		v.Set("period", period)
	}
	if page > 1 {
		v.Set("page", strconv.Itoa(page))
	}
	if enc := v.Encode(); enc != "" {
		return "/os/posts?" + enc
	}
	return "/os/posts"
}

// osPostsPager renders the premium pagination control: a "showing X–Y of Z"
// summary, first/last + prev/next + ±10-page jump buttons, a windowed run of
// page numbers, and a "go to page" form. All navigation is plain GET links so
// it works without JavaScript and respects the strict CSP.
func osPostsPager(status, q, from, to, period string, page, totalPages, total, shownFrom, shownTo int) string {
	info := `<div class="pager-info">Showing <strong>` + strconv.Itoa(shownFrom) + `–` + strconv.Itoa(shownTo) +
		`</strong> of <strong>` + strconv.Itoa(total) + `</strong> posts</div>`
	if totalPages <= 1 {
		return `<nav class="pager" aria-label="Posts pagination">` + info + `</nav>`
	}

	btn := func(label string, target int, disabled bool, extraCls string) string {
		cls := "pager-btn"
		if extraCls != "" {
			cls += " " + extraCls
		}
		if disabled {
			return `<span class="` + cls + ` is-disabled" aria-disabled="true">` + label + `</span>`
		}
		return `<a class="` + cls + `" href="` + osPostsHref(status, q, from, to, period, target) + `">` + label + `</a>`
	}
	num := func(i int) string {
		if i == page {
			return `<span class="pager-btn is-current" aria-current="page">` + strconv.Itoa(i) + `</span>`
		}
		return `<a class="pager-btn" href="` + osPostsHref(status, q, from, to, period, i) + `">` + strconv.Itoa(i) + `</a>`
	}

	prev10 := page - 10
	if prev10 < 1 {
		prev10 = 1
	}
	next10 := page + 10
	if next10 > totalPages {
		next10 = totalPages
	}

	controls := btn("« First", 1, page == 1, "")
	if totalPages > 10 {
		controls += btn("‹‹ 10", prev10, page == 1, "")
	}
	controls += btn("‹ Prev", page-1, page == 1, "")

	start := page - 2
	if start < 1 {
		start = 1
	}
	end := page + 2
	if end > totalPages {
		end = totalPages
	}
	if start > 1 {
		controls += num(1)
		if start > 2 {
			controls += `<span class="pager-gap">…</span>`
		}
	}
	for i := start; i <= end; i++ {
		controls += num(i)
	}
	if end < totalPages {
		if end < totalPages-1 {
			controls += `<span class="pager-gap">…</span>`
		}
		controls += num(totalPages)
	}

	controls += btn("Next ›", page+1, page == totalPages, "")
	if totalPages > 10 {
		controls += btn("10 ››", next10, page == totalPages, "")
	}
	controls += btn("Last »", totalPages, page == totalPages, "")

	jump := `<form class="pager-jump" method="GET" action="/os/posts">`
	if status != "all" {
		jump += `<input type="hidden" name="status" value="` + html.EscapeString(status) + `">`
	}
	if q != "" {
		jump += `<input type="hidden" name="q" value="` + html.EscapeString(q) + `">`
	}
	if from != "" {
		jump += `<input type="hidden" name="from" value="` + html.EscapeString(from) + `">`
	}
	if to != "" {
		jump += `<input type="hidden" name="to" value="` + html.EscapeString(to) + `">`
	}
	if period != "" && period != "all" {
		jump += `<input type="hidden" name="period" value="` + html.EscapeString(period) + `">`
	}
	jump += `<label class="pager-jump-label">Go to page
      <input class="input input--sm pager-jump-input" type="number" name="page" min="1" max="` + strconv.Itoa(totalPages) + `" value="` + strconv.Itoa(page) + `" aria-label="Page number">
    </label>
    <span class="pager-jump-total">of ` + strconv.Itoa(totalPages) + `</span>
    <button class="btn btn--ghost btn--sm" type="submit">Go</button>
  </form>`

	return `<nav class="pager" aria-label="Posts pagination">
  ` + info + `
  <div class="pager-controls">` + controls + `</div>
  ` + jump + `
</nav>`
}

// ── Editor ───────────────────────────────────────────────────────────────────

// handleOSEditor serves the post editor. To avoid any data loss during the
// gradual migration it picks the editor by article state:
//   - existing article with a block document      → native os block editor
//   - existing empty draft (no content, no blocks) → native os block editor
//   - existing article with legacy HTML/Markdown   → v2 editor (lossless)
//   - brand-new post (no slug)                     → v2 editor (handles create)
func (a *App) handleOSEditor(w http.ResponseWriter, r *http.Request) {
	nonce := render.CSPNonce(r)
	cfg := a.getOSSettings(r.Context())
	slug := chi.URLParam(r, "slug")

	if slug != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		art, err := a.articles.Get(ctx, slug)
		if err == nil {
			meta := loadPostMeta(r.Context(), slug)
			metaScript := osEditorMetaScript(slug, art.Status, art.CreatedAt, art.Tags, meta)
			blocksJSON := loadBlocksJSON(r.Context(), slug)
			hasBlocks := strings.TrimSpace(blocksJSON) != "" && strings.TrimSpace(blocksJSON) != "[]"
			emptyDraft := strings.TrimSpace(art.Content) == ""
			authorSel := meta.AuthorID
			if authorSel == "" {
				authorSel = currentUserIDOf(r)
			}
			authorOpts := a.authorSelectOptions(r.Context(), authorSel)
			if hasBlocks || emptyDraft {
				body := osEditorBody(slug, art.Title, blocksJSON, authorOpts) + metaScript
				body += `
<script nonce="` + nonce + `" src="/os/static/js/admin-os-editor.js?v=` + assetVer("js/admin-os-editor.js") + `"></script>`
				writeOSHTML(w, r, adminOSLayout(nonce, "Edit Post", "editor", cfg, htmpl.HTML(body)))
				return
			}
			// Legacy (non-block) content: open it in the native block editor,
			// pre-seeded with an in-memory import of the article HTML. The block
			// side-car is NOT persisted and articles.content is left untouched, so
			// this is non-destructive — navigating away leaves the post exactly as
			// it was. The first Save commits the imported blocks (HTML→blocks via
			// the conservative importer + bluemonday on render).
			blocks := blockrender.ImportHTML(art.Content)
			raw, err := json.Marshal(blocks)
			if err != nil {
				raw = []byte("[]")
			}
			body := osEditorBody(slug, art.Title, string(raw), authorOpts) + metaScript
			body += `
<script nonce="` + nonce + `" src="/os/static/js/admin-os-editor.js?v=` + assetVer("js/admin-os-editor.js") + `"></script>`
			writeOSHTML(w, r, adminOSLayout(nonce, "Edit Post", "editor", cfg, htmpl.HTML(body)))
			return
		}
	}

	// Brand-new post: the native block editor owns the create path (v1.6.0).
	// It hydrates with an empty document and an empty slug; the first Save POSTs
	// to /os/api/editor/save, which creates the article and returns its slug.
	body := osEditorBody("", "", "[]", a.authorSelectOptions(r.Context(), currentUserIDOf(r))) + osEditorMetaScript("", "", time.Time{}, nil, PostMeta{})
	body += `
<script nonce="` + nonce + `" src="/os/static/js/admin-os-editor.js?v=` + assetVer("js/admin-os-editor.js") + `"></script>`
	writeOSHTML(w, r, adminOSLayout(nonce, "New Post", "editor", cfg, htmpl.HTML(body)))
}

// ── SEO ──────────────────────────────────────────────────────────────────────
// The native SEO dashboard now lives in admin_os_intel.go (handleOSSEONative).

// ── Settings ─────────────────────────────────────────────────────────────────

func (a *App) handleOSSettings(w http.ResponseWriter, r *http.Request) {
	nonce := render.CSPNonce(r)
	cfg := a.getOSSettings(r.Context())
	group := chi.URLParam(r, "group")
	if group == "" {
		group = "general"
	}

	tabs := []struct{ Key, Label, Href string }{
		{"general", "General", "/os/settings/general"},
		{"navigation", "Navigation", "/os/settings/navigation"},
		{"footer", "Footer", "/os/settings/footer"},
		{"design", "Design", "/os/settings/design"},
		{"members", "Members", "/os/settings/members"},
		{"email", "Email", "/os/settings/email"},
		{"security", "Security", "/os/settings/security"},
		{"advanced", "Advanced", "/os/settings/advanced"},
	}

	tabHTML := ""
	for _, t := range tabs {
		cls := "tab"
		if t.Key == group {
			cls += " tab--active"
		}
		tabHTML += `<a class="` + cls + `" href="` + t.Href + `">` + html.EscapeString(t.Label) + `</a>`
	}

	var groupBody string
	ss := a.siteSettings
	switch group {
	case "navigation":
		groupBody = osSettingsNavigation(r.Context(), ss)
	case "footer":
		groupBody = osSettingsFooter(r.Context(), ss)
	case "design":
		groupBody = osSettingsDesign(r.Context(), ss)
	case "members":
		groupBody = osSettingsMembers(r.Context(), ss)
	case "email":
		groupBody = osSettingsEmail(r.Context(), ss)
	case "security":
		groupBody = osSettingsSecurity(r.Context(), ss)
	case "advanced":
		groupBody = osSettingsAdvanced(r.Context(), ss)
	default:
		groupBody = osSettingsGeneral(r.Context(), ss)
	}

	body := `<div class="page-header">
  <h1>Settings</h1>
  <div class="page-actions">
    <span id="settings-status" role="status" aria-live="polite" class="text-xs muted"></span>
    <button type="button" class="btn btn--primary btn--sm" id="settings-save-btn">Save changes</button>
  </div>
</div>
<nav class="tab-list" aria-label="Settings sections">` + tabHTML + `</nav>
<div class="card">
  ` + groupBody + `
  <div class="settings-save-bar">
    <span id="settings-status-bar" role="status" aria-live="polite" class="text-xs muted"></span>
    <button type="button" class="btn btn--primary btn--sm" id="settings-save-bar-btn">Save changes</button>
  </div>
</div>`

	saveScript := `var saveBtn=document.getElementById('settings-save-btn');
var saveBtnBar=document.getElementById('settings-save-bar-btn');
var statusEl=document.getElementById('settings-status');
var statusBar=document.getElementById('settings-status-bar');
function setStatus(t,isErr){
  var c=isErr?'var(--color-danger,#ef4444)':'var(--color-success,#22c55e)';
  if(statusEl){statusEl.textContent=t;statusEl.style.color=c;}
  if(statusBar){statusBar.textContent=t;statusBar.style.color=c;}
}
function doSave(){
  var fields=document.querySelectorAll('[data-setting-key]');
  var pairs=[];
  fields.forEach(function(el){
    var key=el.dataset.settingKey;
    var val=el.type==='checkbox'?(el.checked?'true':'false'):el.value;
    pairs.push({key:key,value:val});
  });
  if(!pairs.length){setStatus('Nothing to save',false);return;}
  if(saveBtn)saveBtn.disabled=true;
  if(saveBtnBar)saveBtnBar.disabled=true;
  setStatus('Saving…',false);
  var c=csrf();
  // Send sequentially to avoid SQLite write contention (WAL allows one writer).
  pairs.reduce(function(chain,p){
    return chain.then(function(){
      return fetch('/os/api/settings',{
        method:'POST',
        headers:{'Content-Type':'application/json','X-CSRF-Token':c},
        body:JSON.stringify(p)
      }).then(function(r){
        if(r.ok)return;
        return r.json().then(function(e){
          throw new Error(p.key+': '+(e.detail||e.message||e.error||r.status));
        }).catch(function(){
          throw new Error(p.key+': HTTP '+r.status);
        });
      });
    });
  },Promise.resolve()).then(function(){
    setStatus('Saved',false);
    if(saveBtn)saveBtn.disabled=false;
    if(saveBtnBar)saveBtnBar.disabled=false;
    if(window.vpToast)window.vpToast('Settings saved','ok');
  }).catch(function(e){
    setStatus('Failed — '+e.message,true);
    if(saveBtn)saveBtn.disabled=false;
    if(saveBtnBar)saveBtnBar.disabled=false;
  });
}
if(saveBtn)saveBtn.addEventListener('click',doSave);
if(saveBtnBar)saveBtnBar.addEventListener('click',doSave);
// Reorder a row among its same-type siblings (dir<0 = up, dir>0 = down), then
// resync the hidden JSON so the new order persists on Save. Shared by the nav
// and footer link editors. CSP-safe: pure DOM, no inline handlers.
function moveRow(row,dir,sync){
  if(dir<0){var p=row.previousElementSibling;if(p)row.parentNode.insertBefore(row,p);}
  else{var n=row.nextElementSibling;if(n)row.parentNode.insertBefore(n,row);}
  if(sync)sync();
}
function reorderBtns(row,sync){
  var up=document.createElement('button');up.type='button';up.className='btn btn--sm';up.textContent='↑';up.title='Move up';up.setAttribute('aria-label','Move up');
  up.addEventListener('click',function(){moveRow(row,-1,sync);});
  var dn=document.createElement('button');dn.type='button';dn.className='btn btn--sm';dn.textContent='↓';dn.title='Move down';dn.setAttribute('aria-label','Move down');
  dn.addEventListener('click',function(){moveRow(row,1,sync);});
  return[up,dn];
}
// Navigation menu editor (Navigation tab). Builds rows from nav.items JSON and
// keeps a hidden input in sync so the generic Save picks it up.
var navEditor=document.getElementById('nav-editor');
var navHidden=document.getElementById('nav-json-input');
var navAdd=document.getElementById('nav-add-btn');
if(navEditor&&navHidden){
  function navSync(){
    var rows=navEditor.querySelectorAll('[data-nav-row]');var out=[];
    rows.forEach(function(row){
      var l=row.querySelector('[data-nav-label]').value.trim();
      var h=row.querySelector('[data-nav-href]').value.trim();
      if(l&&h)out.push({label:l,href:h});
    });
    navHidden.value=JSON.stringify(out);
  }
  function navRow(label,href){
    var row=document.createElement('div');row.setAttribute('data-nav-row','');
    row.style.cssText='display:flex;gap:.5rem;align-items:center;margin-bottom:.5rem';
    var li=document.createElement('input');li.className='input';li.type='text';li.placeholder='Label';li.value=label||'';li.setAttribute('data-nav-label','');li.style.flex='1';
    var hi=document.createElement('input');hi.className='input';hi.type='text';hi.placeholder='/path or https://…';hi.value=href||'';hi.setAttribute('data-nav-href','');hi.style.flex='2';
    var rm=document.createElement('button');rm.type='button';rm.className='btn btn--sm';rm.textContent='✕';
    rm.addEventListener('click',function(){row.remove();navSync();});
    li.addEventListener('input',navSync);hi.addEventListener('input',navSync);
    row.appendChild(li);row.appendChild(hi);
    var nb=reorderBtns(row,navSync);row.appendChild(nb[0]);row.appendChild(nb[1]);
    row.appendChild(rm);
    return row;
  }
  (function(){
    var seed=[];try{seed=JSON.parse(navEditor.getAttribute('data-nav-json')||'[]');}catch(e){seed=[];}
    seed.forEach(function(it){navEditor.appendChild(navRow(it.label,it.href));});
  })();
  if(navAdd)navAdd.addEventListener('click',function(){navEditor.appendChild(navRow('',''));});
}
// Branding: favicon/logo upload (Design tab). Elements only exist there.
var favFile=document.getElementById('brand-favicon-file');
var favUp=document.getElementById('brand-favicon-upload');
var favRm=document.getElementById('brand-favicon-remove');
var favStatus=document.getElementById('brand-favicon-status');
var favImg=document.getElementById('brand-favicon-img');
var favState=document.getElementById('brand-favicon-state');
function favSet(t,isErr){if(favStatus){favStatus.textContent=t;favStatus.style.color=isErr?'var(--color-danger,#ef4444)':'var(--color-success,#22c55e)';}}
// The endpoint and the preview both follow the page's scope, taken from the
// image the server already rendered. Hard-coding /os/api/branding/favicon here
// is what made a hosted domain's Theme Studio save the install-wide mark while
// looking like it saved that domain's.
var favBase=(favImg&&favImg.getAttribute('src')||'/favicon.ico').split('?')[0];
var favPost=favBase==='/favicon.ico'?'/os/api/branding/favicon':favBase.replace('/branding/mark','/api/branding/favicon');
function favBust(){if(favImg)favImg.src=favBase+'?t='+Date.now();}
if(favUp)favUp.addEventListener('click',function(){
  var f=favFile&&favFile.files&&favFile.files[0];
  if(!f){favSet('Choose a PNG or ICO first',true);return;}
  favUp.disabled=true;favSet('Uploading…',false);
  var fd=new FormData();fd.append('favicon',f);
  fetch(favPost,{method:'POST',headers:{'X-CSRF-Token':csrf()},body:fd})
    .then(function(r){return r.json().then(function(d){return{ok:r.ok,d:d};});})
    .then(function(res){favUp.disabled=false;if(res.ok){favSet('Favicon updated',false);favBust();if(favState)favState.textContent='Custom favicon active — stored in the database.';}else{favSet(res.d.error||'Upload failed',true);}})
    .catch(function(e){favUp.disabled=false;favSet('Error: '+e,true);});
});
if(favRm)favRm.addEventListener('click',function(){
  favRm.disabled=true;favSet('Removing…',false);
  var fd=new FormData();fd.append('remove','1');
  fetch(favPost,{method:'POST',headers:{'X-CSRF-Token':csrf()},body:fd})
    .then(function(r){return r.json().then(function(d){return{ok:r.ok,d:d};});})
    .then(function(res){favRm.disabled=false;if(res.ok){favSet('Default restored',false);favBust();if(favState)favState.textContent='Using the default mark.';}else{favSet(res.d.error||'Remove failed',true);}})
    .catch(function(e){favRm.disabled=false;favSet('Error: '+e,true);});
});
// Footer editor (Footer tab). Builds tagline/copyright/columns/social/legal and
// keeps a hidden JSON input (footer.config) in sync for the generic Save.
var footerInput=document.getElementById('footer-json-input');
if(footerInput){
  var fTagline=document.getElementById('footer-tagline');
  var fCopyright=document.getElementById('footer-copyright');
  var fCols=document.getElementById('footer-cols');
  var fSocial=document.getElementById('footer-social');
  var fLegal=document.getElementById('footer-legal');
  function fLinkRow(label,href){
    var row=document.createElement('div');row.setAttribute('data-f-link','');
    row.style.cssText='display:flex;gap:.5rem;align-items:center;margin-bottom:.4rem';
    var li=document.createElement('input');li.className='input';li.type='text';li.placeholder='Label';li.value=label||'';li.setAttribute('data-f-label','');li.style.flex='1';
    var hi=document.createElement('input');hi.className='input';hi.type='text';hi.placeholder='/path, mailto: or https://…';hi.value=href||'';hi.setAttribute('data-f-href','');hi.style.flex='2';
    var rm=document.createElement('button');rm.type='button';rm.className='btn btn--sm';rm.textContent='✕';
    rm.addEventListener('click',function(){row.remove();footerSync();});
    li.addEventListener('input',footerSync);hi.addEventListener('input',footerSync);
    row.appendChild(li);row.appendChild(hi);
    var fb=reorderBtns(row,footerSync);row.appendChild(fb[0]);row.appendChild(fb[1]);
    row.appendChild(rm);
    return row;
  }
  function fColCard(title,links){
    var card=document.createElement('div');card.setAttribute('data-f-col','');
    card.style.cssText='border:1px solid var(--border,#2a2a2a);border-radius:8px;padding:.75rem;margin-bottom:.75rem';
    var head=document.createElement('div');head.style.cssText='display:flex;gap:.5rem;align-items:center;margin-bottom:.5rem';
    var ti=document.createElement('input');ti.className='input';ti.type='text';ti.placeholder='Column title (e.g. Company)';ti.value=title||'';ti.setAttribute('data-f-col-title','');ti.style.flex='1';
    ti.addEventListener('input',footerSync);
    var rmc=document.createElement('button');rmc.type='button';rmc.className='btn btn--sm';rmc.textContent='Remove column';
    rmc.addEventListener('click',function(){card.remove();footerSync();});
    head.appendChild(ti);
    var cb=reorderBtns(card,footerSync);head.appendChild(cb[0]);head.appendChild(cb[1]);
    head.appendChild(rmc);
    var linksWrap=document.createElement('div');linksWrap.setAttribute('data-f-col-links','');
    (links||[]).forEach(function(l){linksWrap.appendChild(fLinkRow(l.label,l.href));});
    var addL=document.createElement('button');addL.type='button';addL.className='btn btn--sm';addL.textContent='+ Add link';
    addL.addEventListener('click',function(){linksWrap.appendChild(fLinkRow('',''));footerSync();});
    card.appendChild(head);card.appendChild(linksWrap);card.appendChild(addL);
    return card;
  }
  function fCollect(wrap){
    var out=[];if(!wrap)return out;
    wrap.querySelectorAll('[data-f-link]').forEach(function(row){
      var l=row.querySelector('[data-f-label]').value.trim();
      var h=row.querySelector('[data-f-href]').value.trim();
      if(l&&h)out.push({label:l,href:h});
    });
    return out;
  }
  function footerSync(){
    var cols=[];
    if(fCols)fCols.querySelectorAll('[data-f-col]').forEach(function(card){
      var t=card.querySelector('[data-f-col-title]').value.trim();
      var links=fCollect(card.querySelector('[data-f-col-links]'));
      if(t||links.length)cols.push({title:t,links:links});
    });
    footerInput.value=JSON.stringify({
      tagline:fTagline?fTagline.value.trim():'',
      copyright:fCopyright?fCopyright.value.trim():'',
      columns:cols,
      social:fCollect(fSocial),
      legal:fCollect(fLegal)
    });
  }
  (function(){
    var seed={};try{seed=JSON.parse(footerInput.getAttribute('data-footer-seed')||'{}');}catch(e){seed={};}
    if(fTagline)fTagline.value=seed.tagline||'';
    if(fCopyright)fCopyright.value=seed.copyright||'';
    if(fCols)(seed.columns||[]).forEach(function(c){fCols.appendChild(fColCard(c.title,c.links));});
    if(fSocial)(seed.social||[]).forEach(function(l){fSocial.appendChild(fLinkRow(l.label,l.href));});
    if(fLegal)(seed.legal||[]).forEach(function(l){fLegal.appendChild(fLinkRow(l.label,l.href));});
    if(fTagline)fTagline.addEventListener('input',footerSync);
    if(fCopyright)fCopyright.addEventListener('input',footerSync);
    footerSync();
  })();
  var addCol=document.getElementById('footer-add-col');
  if(addCol)addCol.addEventListener('click',function(){fCols.appendChild(fColCard('',[]));footerSync();});
  var addSocial=document.getElementById('footer-add-social');
  if(addSocial)addSocial.addEventListener('click',function(){fSocial.appendChild(fLinkRow('',''));footerSync();});
  var addLegal=document.getElementById('footer-add-legal');
  if(addLegal)addLegal.addEventListener('click',function(){fLegal.appendChild(fLinkRow('',''));footerSync();});
}`

	fullHTML := adminOSShellHead(nonce, "Settings", "settings", cfg) +
		renderTrustedHTML(htmpl.HTML(body)) +
		adminOSShellFoot(nonce, saveScript, pageUsesAlpine(body))
	writeOSHTML(w, r, fullHTML)
}

func osSettingsGeneral(ctx context.Context, ss *settings.Store) string {
	var siteName, tagline, desc, author, tz string
	if ss != nil {
		siteName = ss.Get(ctx, settings.ForPrimary(), settings.KeySiteName)
		tagline = ss.Get(ctx, settings.ForPrimary(), settings.KeySiteTagline)
		desc = ss.Get(ctx, settings.ForPrimary(), settings.KeySiteDescription)
		author = ss.Get(ctx, settings.ForPrimary(), settings.KeySiteAuthor)
		tz = ss.Get(ctx, settings.ForPrimary(), settings.KeySiteTimezone)
	}

	// Date & time. Timestamps are always STORED in UTC (unambiguous, survives a
	// server move, never shifts under daylight saving); this setting only decides
	// what is displayed — post dates on the public site and every timestamp in the
	// admin. Without it both read as UTC, so an operator in IST saw every time 5½
	// hours behind their clock and a post published after 05:30 local showed the
	// previous day's date to readers.
	nowLine := "Currently showing: " + currentSiteTimeLine()
	tzBlock := `<div class="settings-section">
  <div class="settings-block-title">Date &amp; time</div>
  <div class="field"><label class="field-label" for="s-timezone">Display timezone</label>
    <select id="s-timezone" class="input" data-setting-key="` + settings.KeySiteTimezone + `">` +
		timezoneOptionsHTML(tz) + `</select>
    <span class="field-hint">Post dates and every admin timestamp are shown in this zone. Times are always stored in UTC, so changing this never alters your data — only how it reads. ` +
		html.EscapeString(nowLine) + `</span></div>
</div>`

	return tzBlock + `<div class="settings-section">
  <div class="settings-block-title">Site identity</div>
  <div class="field"><label class="field-label" for="s-name">Site name</label>
    <input id="s-name" class="input" type="text"
      data-setting-key="` + settings.KeySiteName + `"
      value="` + html.EscapeString(siteName) + `" placeholder="My Publication"></div>
  <div class="field"><label class="field-label" for="s-tagline">Tagline</label>
    <input id="s-tagline" class="input" type="text"
      data-setting-key="` + settings.KeySiteTagline + `"
      value="` + html.EscapeString(tagline) + `" placeholder="A short description"></div>
  <div class="field"><label class="field-label" for="s-desc">Description</label>
    <textarea id="s-desc" class="textarea"
      data-setting-key="` + settings.KeySiteDescription + `"
      placeholder="Used in RSS, sitemaps, and SEO meta">` + html.EscapeString(desc) + `</textarea></div>
  <div class="field"><label class="field-label" for="s-author">Author name</label>
    <input id="s-author" class="input" type="text"
      data-setting-key="` + settings.KeySiteAuthor + `"
      value="` + html.EscapeString(author) + `" placeholder="Your name"></div>
</div>`
}

func osSettingsNavigation(ctx context.Context, ss *settings.Store) string {
	navJSON := ""
	if ss != nil {
		navJSON = ss.Get(ctx, settings.ForPrimary(), settings.KeyNavItems)
	}
	if strings.TrimSpace(navJSON) == "" {
		// Seed the editor with the built-in defaults so operators start from the
		// current visible menu rather than a blank slate.
		navJSON = `[{"label":"Home","href":"/"},{"label":"Feed","href":"/feed.xml"},{"label":"Console","href":"/admin"}]`
	}
	return `<div class="settings-section">
  <div class="settings-block-title">Public navigation menu</div>
  <p class="text-sm muted mb-4">These links appear in the top navigation bar on every public page. Point them at internal pages (e.g. <code>/about</code>), feeds, or external/redirect URLs (e.g. <code>https://example.com</code>). Drag-free, add or remove as many as you like.</p>
  <div id="nav-editor" data-nav-json="` + html.EscapeString(navJSON) + `"></div>
  <button type="button" class="btn btn--sm mt-2" id="nav-add-btn">+ Add link</button>
  <input type="hidden" id="nav-json-input" data-setting-key="` + settings.KeyNavItems + `" value="` + html.EscapeString(navJSON) + `">
  <p class="field-hint mt-2">Leave the list empty and Save to restore the default Home / Feed / Console menu.</p>
</div>`
}

// defaultFooterSeed pre-populates the footer editor for operators who have not
// configured a footer yet, so they start from a premium layout (a link column,
// Privacy/Terms legal links, copyright line) rather than a blank slate.
const defaultFooterSeed = `{"tagline":"","copyright":"© {year} {site}. All rights reserved.","columns":[{"title":"Explore","links":[{"label":"Home","href":"/"},{"label":"Feed","href":"/feed.xml"}]}],"social":[],"legal":[{"label":"Privacy","href":"/privacy"},{"label":"Terms","href":"/terms"}]}`

func osSettingsFooter(ctx context.Context, ss *settings.Store) string {
	footerJSON := ""
	if ss != nil {
		footerJSON = ss.Get(ctx, settings.ForPrimary(), settings.KeyFooterConfig)
	}
	if strings.TrimSpace(footerJSON) == "" {
		footerJSON = defaultFooterSeed
	}
	esc := html.EscapeString(footerJSON)
	return `<div class="settings-section">
  <div class="settings-block-title">Premium footer</div>
  <p class="text-sm muted mb-4">Build a rich footer for every public page: a brand tagline, multiple link columns, social links, a legal-links bar (Privacy, Terms…) and a copyright line. Hrefs accept internal paths (e.g. <code>/privacy</code>), feeds, <code>mailto:</code> or external URLs. Leave everything empty to fall back to a clean default copyright bar.</p>

  <div class="field"><label class="field-label" for="footer-tagline">Footer tagline</label>
    <input id="footer-tagline" class="input" type="text" placeholder="A short line shown under your brand"></div>

  <div class="field"><label class="field-label" for="footer-copyright">Copyright line</label>
    <input id="footer-copyright" class="input" type="text" placeholder="© {year} {site}. All rights reserved.">
    <span class="field-hint">Use <code>{year}</code> for the current year and <code>{site}</code> for your site name.</span></div>

  <div class="settings-block-title mt-4">Link columns</div>
  <p class="text-sm muted mb-2">Grouped link lists (e.g. Explore, Company, Resources).</p>
  <div id="footer-cols"></div>
  <button type="button" class="btn btn--sm mt-2" id="footer-add-col">+ Add column</button>

  <div class="settings-block-title mt-4">Social links</div>
  <div id="footer-social"></div>
  <button type="button" class="btn btn--sm mt-2" id="footer-add-social">+ Add social link</button>

  <div class="settings-block-title mt-4">Legal links (bottom bar)</div>
  <p class="text-sm muted mb-2">Shown in the footer's bottom bar next to the copyright — e.g. Privacy, Terms, Cookies.</p>
  <div id="footer-legal"></div>
  <button type="button" class="btn btn--sm mt-2" id="footer-add-legal">+ Add legal link</button>

  <input type="hidden" id="footer-json-input" data-setting-key="` + settings.KeyFooterConfig + `" data-footer-seed="` + esc + `" value="` + esc + `">
</div>`
}

func osSettingsDesign(ctx context.Context, ss *settings.Store) string {
	primaryLight, primaryDark, customCSS := "#0f766e", "#2dd4bf", ""
	faviconState := "Using the default mark."
	if ss != nil {
		if v := ss.Get(ctx, settings.ForPrimary(), settings.KeyThemePrimaryLight); v != "" {
			primaryLight = v
		}
		if v := ss.Get(ctx, settings.ForPrimary(), settings.KeyThemePrimaryDark); v != "" {
			primaryDark = v
		}
		customCSS = ss.Get(ctx, settings.ForPrimary(), settings.KeyThemeCustomCSS)
		if ss.Get(ctx, settings.ForPrimary(), settings.KeyBrandFavicon) != "" {
			faviconState = "Custom favicon active — stored in the database."
		}
	}

	return `<div class="settings-section">
  <div class="settings-callout">
    <strong>Design now lives in the Theme Studio.</strong>
    <span class="text-sm muted">Logo, colours, layout, hero, fonts, navigation, article pages and the social share image are all edited there with a live preview.</span>
    <a class="btn btn--primary btn--sm mt-2" href="/os/theme">Open Theme Studio →</a>
  </div>
</div>
<div class="settings-section">
  <div class="settings-block-title">Branding</div>
  <div class="field">
    <label class="field-label">Logo &amp; favicon</label>
    <div class="settings-row" style="align-items:center;gap:1rem">
      <img id="brand-favicon-img" src="/favicon.ico?t=` + strconv.FormatInt(time.Now().Unix(), 10) + `" alt="Current favicon" width="40" height="40" style="border-radius:6px;background:var(--surface-2,#1a1a1a)">
      <div class="settings-row-info">
        <div class="settings-row-label">Site mark</div>
        <div class="settings-row-hint" id="brand-favicon-state">` + html.EscapeString(faviconState) + `</div>
      </div>
    </div>
    <span class="field-hint">PNG or ICO, square, ≤ 256 KB. Used as the favicon (browser tab) and the nav-bar logo on the public site. Applies immediately.</span>
    <div class="theme-actions" style="display:flex;gap:.5rem;align-items:center;margin-top:.5rem;flex-wrap:wrap">
      <input type="file" id="brand-favicon-file" accept="image/png,image/x-icon,.png,.ico" class="input" style="max-width:18rem">
      <button type="button" class="btn btn--primary btn--sm" id="brand-favicon-upload">Upload</button>
      <button type="button" class="btn btn--sm" id="brand-favicon-remove">Remove (use default)</button>
      <span id="brand-favicon-status" class="text-xs muted" role="status" aria-live="polite"></span>
    </div>
  </div>
</div>
<div class="settings-section">
  <div class="settings-block-title">Theme colours</div>
  <div class="settings-row">
    <div class="settings-row-info">
      <div class="settings-row-label">Primary colour (light mode)</div>
      <div class="settings-row-hint">Main brand colour used on the public site</div>
    </div>
    <input type="color" data-setting-key="` + settings.KeyThemePrimaryLight + `" value="` + html.EscapeString(primaryLight) + `">
  </div>
  <div class="settings-row">
    <div class="settings-row-info">
      <div class="settings-row-label">Primary colour (dark mode)</div>
    </div>
    <input type="color" data-setting-key="` + settings.KeyThemePrimaryDark + `" value="` + html.EscapeString(primaryDark) + `">
  </div>
  <div class="settings-block-title mt-4">Custom CSS</div>
  <div class="field">
    <label class="field-label" for="s-custom-css">Custom stylesheet (injected on public pages only)</label>
    <textarea id="s-custom-css" class="textarea font-mono" rows="8"
      data-setting-key="` + settings.KeyThemeCustomCSS + `"
      placeholder="/* Your custom CSS here */">` + html.EscapeString(customCSS) + `</textarea>
    <span class="field-hint">Applied to every public page. Never loaded in the admin panel.</span>
  </div>
</div>`
}

func osSettingsMembers(ctx context.Context, ss *settings.Store) string {
	membershipBtns := ""
	if ss != nil && ss.Get(ctx, settings.ForPrimary(), settings.KeyMembershipButtons) == "true" {
		membershipBtns = " checked"
	}
	return `<div class="settings-section">
  <div class="settings-block-title">Memberships</div>
  <div class="settings-row">
    <div class="settings-row-info">
      <div class="settings-row-label">Enable memberships</div>
      <div class="settings-row-hint">Allow readers to create free or paid accounts</div>
    </div>
    <input type="checkbox" class="toggle" data-setting-key="members.enabled" checked>
  </div>
  <div class="settings-row">
    <div class="settings-row-info">
      <div class="settings-row-label">Show Sign in / Sign up on the site</div>
      <div class="settings-row-hint">Display public Sign in &amp; Sign up buttons in the homepage navigation (like Ghost)</div>
    </div>
    <input type="checkbox" class="toggle" data-setting-key="` + settings.KeyMembershipButtons + `"` + membershipBtns + `>
  </div>
  <div class="settings-row">
    <div class="settings-row-info">
      <div class="settings-row-label">Magic-link sign-in</div>
      <div class="settings-row-hint">Passwordless email links (no password required for members)</div>
    </div>
    <input type="checkbox" class="toggle" data-setting-key="members.magic_link" checked>
  </div>
  <p class="text-sm muted mt-4">Stripe webhook secret and paid tier configuration are set via environment variables. See documentation for details.</p>
</div>`
}

func osSettingsEmail(ctx context.Context, ss *settings.Store) string {
	from := ""
	if ss != nil {
		from = ss.Get(ctx, settings.ForPrimary(), "smtp.from")
	}
	return `<div class="settings-section">
  <div class="settings-block-title">SMTP</div>
  <p class="text-sm muted mb-4">Configure via environment variables: <code>SMTP_HOST</code>, <code>SMTP_PORT</code>, <code>SMTP_USER</code>, <code>SMTP_PASS</code>, <code>SMTP_FROM</code>, <code>SMTP_TLS</code>.</p>
  <div class="field">
    <label class="field-label" for="s-smtp-from">From address (display only)</label>
    <input id="s-smtp-from" class="input" type="email" data-setting-key="smtp.from"
      value="` + html.EscapeString(from) + `" placeholder="VayuPress &lt;hello@example.com&gt;">
  </div>
</div>`
}

func osSettingsSecurity(_ context.Context, _ *settings.Store) string {
	return `<div class="settings-section">
  <div class="settings-block-title">Security</div>
  <p class="text-sm muted">Two-factor authentication (TOTP) and session management live in the dedicated <a href="/os/security">Security</a> panel.</p>
</div>`
}

func osSettingsAdvanced(_ context.Context, _ *settings.Store) string {
	return `<div class="settings-section">
  <div class="settings-block-title">Cache</div>
  <div class="settings-row">
    <div class="settings-row-info">
      <div class="settings-row-label">Cache directory</div>
      <div class="settings-row-hint">Set via <code>CACHE_DIR</code> environment variable</div>
    </div>
    <code class="font-mono text-xs muted">` + html.EscapeString(config.Cfg.CacheDir) + `</code>
  </div>
  <div class="section-divider"></div>
  <div class="settings-block-title">Danger zone</div>
  <p class="text-sm muted">Destructive actions and data export are available in the classic console.</p>
  <a class="btn btn--ghost btn--sm mt-3" href="/admin" target="_blank">Open classic console ↗</a>
</div>`
}

// ── JSON APIs ─────────────────────────────────────────────────────────────────

// handleOSActivity returns recent admin activity as JSON for the dashboard feed.
func (a *App) handleOSActivity(w http.ResponseWriter, r *http.Request) {
	type activityItem struct {
		Kind string `json:"kind"`
		Icon string `json:"icon"`
		Text string `json:"text"`
		Time string `json:"time"`
		Href string `json:"href,omitempty"` // Wave 2.3: every row links to where the work happens
	}

	// Wave 2.3 member gating: the feed used to show member emails to every
	// signed-in role. Members are an admin surface (/os/members), so member
	// rows are included only for viewers who could actually open that page —
	// shown == reachable, the same RBAC parity the sidebar and palette hold.
	lvl := accessAdmin
	if u := currentUser(r); u != nil {
		// Mail-only is a members-store property, not a console-user one; the
		// client-role floor inside accessLevelFor covers confinement here.
		lvl = accessLevelFor(u.Role, false)
	}

	items := []activityItem{}

	// Recent articles — with an honest verb. The ArticleService list projection
	// carries no status (and hardcoding "published" for every row was the lie
	// this feed told), so the feed reads the five newest rows directly, status
	// included: a draft row says "drafted" and links into the editor either way.
	if dbpkg.DB != nil {
		if rows, err := dbpkg.Reader().QueryContext(r.Context(),
			`SELECT slug,title,COALESCE(status,'published'),created_at FROM articles ORDER BY created_at DESC LIMIT 5`); err == nil {
			for rows.Next() {
				var slug, title, status string
				var created time.Time
				if rows.Scan(&slug, &title, &status, &created) == nil {
					verb := "Article published"
					if status == "draft" {
						verb = "Article drafted"
					}
					items = append(items, activityItem{
						Kind: "post",
						Icon: "✍",
						Text: verb + ": " + title,
						Time: created.UTC().Format(time.RFC3339),
						Href: "/os/editor/" + slug,
					})
				}
			}
			_ = rows.Err() // best-effort feed; a read failure just yields fewer rows
			rows.Close()
		}
	}

	// Recent members (gated to admins — see above).
	if lvl >= osPathMinLevel("/os/members") && a.members != nil {
		list, err := a.members.List(r.Context(), 3)
		if err == nil {
			for _, m := range list {
				items = append(items, activityItem{
					Kind: "member",
					Icon: "👤",
					Text: "Member joined: " + m.Email,
					Time: m.CreatedAt.UTC().Format(time.RFC3339),
					Href: "/os/members",
				})
			}
		}
	}

	// Sort by time descending (simple bubble — small list)
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].Time > items[i].Time {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
	if len(items) > 8 {
		items = items[:8]
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(items)
}

// handleOSCmdIndex returns the command palette search index as JSON.
//
// Wave 1 fixes two lies this endpoint used to tell: its three "actions" carried
// empty Fn strings (the buttons rendered but did nothing), and its 11-page
// registry covered ~17% of the console while the input promised "Search posts,
// members, settings…". The registry below now mirrors the sidebar/hubs and is
// gated by the SAME osPathMinLevel predicate, so shown == reachable holds here
// too. Actions are dispatched client-side through the vpActions registry
// (static/js/admin-os.js), not window[fn] string lookup.
func (a *App) handleOSCmdIndex(w http.ResponseWriter, r *http.Request) {
	type cmdPost struct{ Label, Slug string }
	type cmdAction struct{ Label, Icon, Hint, Fn string }
	type cmdSetting struct{ Label, Icon, Href string }

	posts := []cmdPost{}
	if res, err := a.articles.List(r.Context(), 1, 50, ""); err == nil {
		for _, p := range res.Articles {
			posts = append(posts, cmdPost{Label: p.Title, Slug: p.Slug})
		}
	}

	actions := []cmdAction{
		{Label: "New Post", Icon: "✍", Hint: "Open the block editor", Fn: "newPost"},
		{Label: "SEO Dashboard", Icon: "🔍", Hint: "Indexing and search health", Fn: "goSEO"},
		{Label: "Regenerate SEO artefacts", Icon: "⟳", Hint: "Rebuild sitemap, RSS & robots.txt", Fn: "regenSEO"},
	}

	allPages := []cmdSetting{
		// Content workspace
		{Label: "Posts", Icon: "📝", Href: "/os/posts"},
		{Label: "Pages", Icon: "📄", Href: "/os/pages"},
		{Label: "Comments", Icon: "💬", Href: "/os/comments"},
		{Label: "Messages", Icon: "✉️", Href: "/os/messages"},
		{Label: "Media library", Icon: "🖼", Href: "/os/media"},
		{Label: "Website", Icon: "🌐", Href: "/os/website"},
		// Hubs
		{Label: "Dashboard", Icon: "🏠", Href: "/os"},
		{Label: "Growth hub", Icon: "📈", Href: "/os/growth"},
		{Label: "Optimize hub", Icon: "🚀", Href: "/os/optimize"},
		{Label: "Operations hub", Icon: "🛠", Href: "/os/operations"},
		// Growth family
		{Label: "Members", Icon: "👥", Href: "/os/members"},
		{Label: "Newsletter", Icon: "📰", Href: "/os/newsletter"},
		{Label: "Monetization", Icon: "💰", Href: "/os/monetization"},
		{Label: "Advertising", Icon: "📣", Href: "/os/ads"},
		{Label: "My Profile", Icon: "🙋", Href: "/os/profile"},
		// Optimize family
		{Label: "SEO Dashboard", Icon: "🔍", Href: "/os/seo"},
		{Label: "Analytics", Icon: "📊", Href: "/os/analytics"},
		{Label: "VayuShield", Icon: "🛡", Href: "/os/shield"},
		{Label: "Theme Studio", Icon: "🎨", Href: "/os/theme"},
		{Label: "Theme Store", Icon: "🛍", Href: "/os/theme/store"},
		{Label: "Tools & Plugins", Icon: "🧩", Href: "/os/tools"},
		{Label: "Domains", Icon: "🌍", Href: "/os/domains"},
		{Label: "API Keys", Icon: "🔑", Href: "/os/apikeys"},
		{Label: "Connector", Icon: "🔌", Href: "/os/connector"},
		{Label: "General settings", Icon: "⚙", Href: "/os/settings/general"},
		{Label: "Design & theme settings", Icon: "🎨", Href: "/os/settings/design"},
		{Label: "Email settings", Icon: "✉", Href: "/os/settings/email"},
		{Label: "Members settings", Icon: "👥", Href: "/os/settings/members"},
		{Label: "Security settings", Icon: "🔒", Href: "/os/settings/security"},
		// Operations family
		{Label: "Monitoring", Icon: "📉", Href: "/os/monitoring"},
		{Label: "Storage & System", Icon: "💾", Href: "/os/storage"},
		{Label: "Security posture", Icon: "🔒", Href: "/os/security"},
		{Label: "System modes", Icon: "🧭", Href: "/os/modes"},
		{Label: "Policy", Icon: "📜", Href: "/os/policy"},
		{Label: "Topology", Icon: "🔗", Href: "/os/topology"},
		{Label: "VayuFlow automations", Icon: "⚡", Href: "/os/vayuflow"},
		{Label: "Backup & Recovery", Icon: "🗄", Href: "/os/vayukeep"},
		{Label: "Governance", Icon: "⚖", Href: "/os/governance"},
		{Label: "Update & Migration", Icon: "⬆", Href: "/os/update"},
		{Label: "Architecture decisions", Icon: "📚", Href: "/os/adr"},
		{Label: "DNS", Icon: "🌐", Href: "/os/dns"},
		{Label: "System hub", Icon: "🧱", Href: "/os/system"},
		// Products & spaces
		{Label: "VayuMail inbox", Icon: "📮", Href: "/os/vayumail/inbox"},
		{Label: "VayuTalk", Icon: "🗨", Href: "/os/talk"},
		{Label: "Tor space", Icon: "🧅", Href: "/os/tor"},
		{Label: "Spaces (worlds)", Icon: "🌗", Href: "/os/spaces"},
	}

	// Same predicate the sidebar uses: an entry only reaches the palette when
	// this session could actually open it.
	lvl := accessAdmin
	cfg := a.getOSSettings(r.Context())
	if cfg != nil {
		lvl = cfg.AccessLevel
	}
	sPages := make([]cmdSetting, 0, len(allPages))
	for _, p := range allPages {
		if lvl >= osPathMinLevel(p.Href) {
			sPages = append(sPages, p)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"posts":    posts,
		"actions":  actions,
		"settings": sPages,
	})
}

// handleOSSettingsAPI persists a single settings key/value from the VayuOS UI.
func (a *App) handleOSSettingsAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-json", "Invalid request body", "")
		return
	}
	if a.siteSettings == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "settings-error", "settings not initialised", "")
		return
	}
	if err := a.siteSettings.SetMany(r.Context(), settings.ForPrimary(), map[string]string{body.Key: body.Value}); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "settings-error", err.Error(), "")
		return
	}
	a.reloadRenderSettings(r.Context())
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

// reloadRenderSettings re-reads the site settings and pushes them into the live
// render pipeline, then drops cached pages so a settings change takes effect
// immediately rather than on the next restart. It is the single source of truth
// for the settings→render mapping, shared by the VayuOS settings API and the
// update_site_settings MCP tool. A no-op if the settings store is unavailable.
func (a *App) reloadRenderSettings(ctx context.Context) {
	if a.siteSettings == nil {
		return
	}
	sv, err := a.siteSettings.GetAll(ctx, settings.ForPrimary())
	if err != nil {
		return
	}
	// Display timezone. Stored timestamps stay UTC; this only decides what is
	// rendered, so applying it here means a change takes effect on the next page
	// without a restart. An invalid name is ignored (the previous zone is kept)
	// rather than leaving every timestamp unrenderable.
	// An invalid name is ignored (the previous zone is kept) rather than leaving
	// every timestamp unrenderable; the settings form validates before saving.
	_ = config.SetSiteTimeZone(sv[settings.KeySiteTimezone])
	render.SetActiveSettings(render.SiteSettings{
		Name:            sv[settings.KeySiteName],
		Tagline:         sv[settings.KeySiteTagline],
		Description:     sv[settings.KeySiteDescription],
		Author:          sv[settings.KeySiteAuthor],
		AuthorBio:       sv[settings.KeyAuthorBio],
		ShowMembership:  sv[settings.KeyMembershipButtons] == "true",
		PrimaryLight:    sv[settings.KeyThemePrimaryLight],
		PrimaryDark:     sv[settings.KeyThemePrimaryDark],
		AccentLight:     sv[settings.KeyThemeAccentLight],
		AccentDark:      sv[settings.KeyThemeAccentDark],
		CustomCSS:       sv[settings.KeyThemeCustomCSS],
		Keywords:        sv[settings.KeyHeadKeywords],
		ThemeColor:      sv[settings.KeyHeadThemeColor],
		Robots:          sv[settings.KeyHeadRobots],
		VerifyGoogle:    sv[settings.KeyHeadVerifyGoogle],
		VerifyBing:      sv[settings.KeyHeadVerifyBing],
		NavJSON:         sv[settings.KeyNavItems],
		FooterJSON:      sv[settings.KeyFooterConfig],
		OGImage:         render.OGImagePath(sv[settings.KeyThemeOGImage]),
		ShowHero:        sv[settings.KeyHomeHero] == "true",
		CommentsEnabled: sv[settings.KeyFeatureComments] != "off",
	})
	render.CachePurgeAll()
}

// handleOSQuickCreatePost creates a draft post from the dashboard quick-compose.
func (a *App) handleOSQuickCreatePost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Title string `json:"title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-json", "Invalid request body", "")
		return
	}
	title := strings.TrimSpace(body.Title)
	if title == "" {
		writeAPIError(w, r, http.StatusBadRequest, "empty-title", "Title is required", "")
		return
	}
	// Generate a unique slug from the title (shared with the native editor).
	slug := a.uniqueArticleSlug(r.Context(), title)
	// Create the draft. Content must be non-empty to pass article validation, so
	// we seed a single space: it trims to empty, so handleOSEditor treats the
	// post as an empty draft and opens the block editor, and the placeholder is
	// replaced by the rendered blocks on the first save. CreateDraft (Wave 1)
	// makes the status travel inside the queued insert itself, so the post is
	// never briefly live between enqueue and a follow-up UPDATE.
	if _, err := a.articles.CreateDraft(r.Context(), title, slug, " ", nil); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "create-error", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"slug": slug})
}

// handleOSSearchReindex triggers a full search index rebuild without requiring a
// CSRF token so that operators can call it with an API key from the shell.
// Example: curl -X POST https://yourdomain.com/os/api/search/reindex -H "X-API-Key: KEY"
func (a *App) handleOSSearchReindex(w http.ResponseWriter, r *http.Request) {
	a.handleSearchReindex(w, r)
}

// handleOSFeedRegenerate regenerates feed.xml (and sitemap.xml) from the
// current article store. Useful after a bulk migration that bypassed the
// normal write queue. Accessible with an API key so no browser session is needed.
// Example: curl -X POST https://yourdomain.com/os/api/feed/regenerate -H "X-API-Key: KEY"
func (a *App) handleOSFeedRegenerate(w http.ResponseWriter, r *http.Request) {
	go generateRSS()
	go generateSitemap()
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "regenerating", "note": "feed.xml and sitemap.xml are being rebuilt in the background"})
}
