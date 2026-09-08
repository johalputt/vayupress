// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/johalputt/vayupress/internal/logging"
	"github.com/johalputt/vayupress/internal/mode"
	"github.com/johalputt/vayupress/internal/render"
	"github.com/johalputt/vayupress/internal/settings"
)

// hexColorRe matches #rgb and #rrggbb CSS hex colours (case-insensitive).
var hexColorRe = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

// verifyTokenRe matches search-engine verification tokens: letters, digits and
// the punctuation those providers use. Anything else is rejected so the value
// can only ever render inside a meta content="" attribute.
var verifyTokenRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Page background colours the primary palette renders against. These mirror
// --pico-background-color in static/css/custom.css and are used for WCAG
// contrast checks on save.
const (
	lightModeBG  = "#f8fafc"
	darkModeBG   = "#0a0f1a"
	wcagAANormal = 4.5 // WCAG 2.x AA contrast ratio for normal-size text/links
)

// srgbToLinear linearises one 0â€“255 sRGB channel (WCAG relative-luminance step).
func srgbToLinear(c float64) float64 {
	c /= 255.0
	if c <= 0.03928 {
		return c / 12.92
	}
	return math.Pow((c+0.055)/1.055, 2.4)
}

// relLuminance returns the WCAG relative luminance of a #rgb / #rrggbb colour.
func relLuminance(hexColor string) float64 {
	h := strings.TrimPrefix(hexColor, "#")
	if len(h) == 3 {
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	if len(h) != 6 {
		return 0
	}
	ch := func(s string) float64 {
		n, _ := strconv.ParseInt(s, 16, 0)
		return srgbToLinear(float64(n))
	}
	return 0.2126*ch(h[0:2]) + 0.7152*ch(h[2:4]) + 0.0722*ch(h[4:6])
}

// contrastRatio returns the WCAG contrast ratio (1.0â€“21.0) between two colours.
func contrastRatio(a, b string) float64 {
	la, lb := relLuminance(a), relLuminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// contrastWarnings returns advisory (non-blocking) WCAG AA warnings for the
// primary palette colours against their page backgrounds. Primary is used as
// the link/interactive-text colour, so failing AA hurts readability â€” but theme
// sovereignty means we warn, not forbid.
func contrastWarnings(primaryLight, primaryDark string) []string {
	var out []string
	if primaryLight != "" {
		if cr := contrastRatio(primaryLight, lightModeBG); cr < wcagAANormal {
			out = append(out, fmt.Sprintf("Light primary %s has low contrast (%.1f:1) on the light background â€” WCAG AA wants â‰¥ %.1f:1.", primaryLight, cr, wcagAANormal))
		}
	}
	if primaryDark != "" {
		if cr := contrastRatio(primaryDark, darkModeBG); cr < wcagAANormal {
			out = append(out, fmt.Sprintf("Dark primary %s has low contrast (%.1f:1) on the dark background â€” WCAG AA wants â‰¥ %.1f:1.", primaryDark, cr, wcagAANormal))
		}
	}
	return out
}

// robotsChoices lists the <meta name="robots"> options in display order. The
// label is shown in the <select>; the value is what gets persisted and must be
// a member of settings.RobotsOptions.
var robotsChoices = []struct{ value, label string }{
	{"", "Default (no directive â€” fully indexable)"},
	{"index,follow", "index, follow"},
	{"index,nofollow", "index, nofollow"},
	{"noindex,follow", "noindex, follow"},
	{"noindex,nofollow", "noindex, nofollow"},
}

// robotsOptionsHTML renders the <option> elements for the robots <select>,
// marking current as selected.
func robotsOptionsHTML(current string) string {
	var sb strings.Builder
	for _, c := range robotsChoices {
		sel := ""
		if c.value == current {
			sel = " selected"
		}
		sb.WriteString(`<option value="` + template.HTMLEscapeString(c.value) + `"` + sel + `>` + template.HTMLEscapeString(c.label) + `</option>`)
	}
	return sb.String()
}

// handleThemeCSS serves the dynamic per-site theme stylesheet at /theme.css.
// Served from the same origin (text/css) so it satisfies the strict
// `style-src 'self'` CSP. An ETag over the CSS content lets browsers revalidate
// cheaply; no-cache forces revalidation so palette changes propagate even to
// disk-cached HTML pages on the next request.
func (a *App) handleThemeCSS(w http.ResponseWriter, r *http.Request) {
	// VayuDomains per-domain branding: a secondary domain with its own accent
	// serves a branded stylesheet (its own ETag); the primary and single-domain
	// installs take the original path â€” same ETag, same bytes â€” byte-identical.
	// Each domain is a distinct origin (own Host), so browser caches never collide.
	etag, css := render.ThemeCSSETag(), render.ThemeCSS()
	if s, ok := a.brandForRequest(r); ok {
		etag, css = render.ThemeCSSETagFor(s), render.ThemeCSSFor(s)
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("ETag", etag)
	// Palette changes are infrequent; a short max-age lets browsers serve from
	// cache without a round-trip, while the ETag still yields cheap 304s and
	// caps propagation lag (â‰¤60 s) after a save. CachePurgeAll() already
	// regenerates the HTML pages on save.
	w.Header().Set("Cache-Control", "public, max-age=60")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	fmt.Fprint(w, css)
}

// handleThemeToggleJS serves the public sun/moon theme switcher script.
// Same-origin static asset â†’ satisfies `script-src 'self'` without a nonce.
func (a *App) handleThemeToggleJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	fmt.Fprint(w, render.ThemeToggleJS)
}

// handleVideoFacadeJS serves the public click-to-load video facade script.
// Same-origin static asset â†’ satisfies `script-src 'self'` without a nonce.
func (a *App) handleVideoFacadeJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	fmt.Fprint(w, render.VideoFacadeJS)
}

// handleCommentsJS serves the public comment widget script.
// Same-origin static asset â†’ satisfies `script-src 'self'` without a nonce.
func (a *App) handleCommentsJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	fmt.Fprint(w, render.CommentsJS)
}

// handleContactJS serves the public contact-form widget (same-origin, strict
// CSP). Static text, long-cached; the ?v= content hash busts stale copies.
func (a *App) handleContactJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	fmt.Fprint(w, render.ContactJS)
}

// handlePostCardMediaJS serves the post-card cover-image fallback script, which
// hides broken/expired cover images on the home and tag pages.
// Same-origin static asset â†’ satisfies `script-src 'self'` without a nonce.
func (a *App) handlePostCardMediaJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	fmt.Fprint(w, render.PostCardMediaJS)
}

// handleTrendingWidgetJS serves the public Trending & pinned posts widget script
// that hydrates [data-vayu-trending] sections from /api/trending. Same-origin
// static asset â†’ satisfies `script-src 'self'` without a nonce. This route was
// previously missing, so the bare /static/js/trending.js 404'd and the widget
// never loaded â€” taking the trending AND pinned-posts lists down with it.
func (a *App) handleTrendingWidgetJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	fmt.Fprint(w, render.TrendingJS)
}

// handleSearchWidgetJS serves the VayuFind instant-search modal script. Same
// pattern as the other public scripts: a content-versioned, same-origin asset
// that satisfies script-src 'self' without a nonce.
func (a *App) handleSearchWidgetJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	fmt.Fprint(w, render.SearchModalJS)
}

// handleHTMXJS serves the self-hosted HTMX library at /static/js/htmx.min.js.
// The file is compiled into the binary via the module-root StaticFS embed and
// mirrored to STATIC_DIR on boot by syncEmbeddedStatic (ADR-0099), so it ships
// inside the executable and survives a binary-only self-update with no separate
// asset copy. Serving it same-origin satisfies the strict `script-src 'self'`
// CSP WITHOUT a nonce and WITHOUT any external host, so the admin panel can use
// hx-* progressive enhancement while staying entirely CDN-free. Headers mirror
// handleThemeToggleJS (long cache; the ?v= content hash busts stale copies).
func (a *App) handleHTMXJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	data, err := fs.ReadFile(embeddedStaticFS, "js/htmx.min.js")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(data)
}

// fontAllowlist is the set of self-hosted web fonts served at /static/fonts.
// It is a strict allowlist (no arbitrary filenames) so the route can never read
// anything but these vetted, OFL-licensed woff2 files from the embedded FS.
// The set is deliberately wider than the built-in theme needs. A hosted domain
// serving a hand-built bundle has exactly one way to use a web font under
// `font-src 'self'`: request it from this origin. Vendoring only the three faces
// the default theme happens to use meant every operator building their own site
// either shipped no real typography or reached for a font host and got a silent
// CSP refusal â€” the freedom was theoretical. These are the display, body and
// mono families the product's own site uses, so a bundle can look finished
// without leaving the origin. Every file is SIL OFL; the licences are vendored
// beside them in static/fonts/.
var fontAllowlist = map[string]bool{
	"space-grotesk-latin-400.woff2":  true,
	"space-grotesk-latin-500.woff2":  true,
	"space-grotesk-latin-600.woff2":  true,
	"space-grotesk-latin-700.woff2":  true,
	"inter-latin-300.woff2":          true,
	"inter-latin-400.woff2":          true,
	"inter-latin-500.woff2":          true,
	"inter-latin-600.woff2":          true,
	"jetbrains-mono-latin-400.woff2": true,
	"jetbrains-mono-latin-500.woff2": true,
}

// handleStaticFont serves an allowlisted, self-hosted woff2 web font from the
// embedded StaticFS at /static/fonts/{file}. Same-origin (CSP font-src 'self'),
// immutable long-cache; used by the Vayu theme's @font-face. No external/CDN
// font request is ever made.
func (a *App) handleStaticFont(w http.ResponseWriter, r *http.Request) {
	file := chi.URLParam(r, "file")
	if !fontAllowlist[file] {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(embeddedStaticFS, "fonts/"+file)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "font/woff2")
	w.Header().Set("Cache-Control", "public, immutable, max-age=31536000")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

// vayuWebAllowlist is the set of first-party web-building assets any hosted
// domain's own bundle may load.
//
// WHY THIS EXISTS. A hand-built site on this install serves under
//
//	script-src 'self' 'nonce-â€¦'; style-src 'self'; font-src 'self'
//
// which is correct and is not going to be relaxed. But it left operators with a
// choice between a plain page and a broken one: every mainstream way to build a
// site â€” a utility CSS framework, a small reactive library, a real typeface â€”
// arrives from a third-party host, gets refused, and renders as unstyled text
// with nothing saying why. The policy was doing its job and the product was
// making creativity the thing you paid for it with.
//
// So the pieces are served from THIS origin instead. Same-origin means the CSP
// admits them unchanged: no directive is widened, no exception is carved, and
// the operator gets the tools rather than the trade-off.
//
// The Alpine build here is the CSP variant, which evaluates component objects
// registered through Alpine.data instead of compiling inline expression strings.
// That distinction is the whole point: the standard build needs 'unsafe-eval',
// and shipping it would have meant weakening the policy for every page on the
// install to make one page interactive.
// alpine.min.js is the STANDARD build and is useless without the per-domain
// eval opt-in (SiteConfig.AllowEval) â€” it compiles the expression strings in
// markup at runtime, which the baseline policy refuses. It is served anyway,
// because the alternative is an operator who has taken that decision being told
// to fetch the file from a third-party host, which trades a policy they chose to
// relax for a supply chain they cannot see. Serving it here keeps the code
// first-party, versioned with the binary, and reviewable.
var vayuWebAllowlist = map[string]string{
	"tailwind.css":      "text/css; charset=utf-8",
	"alpine-csp.min.js": "application/javascript; charset=utf-8",
	"alpine.min.js":     "application/javascript; charset=utf-8",
}

// handleVayuWebAsset serves an allowlisted first-party web-building asset at
// /static/vayuweb/{file}, for use by hand-built site bundles.
func (a *App) handleVayuWebAsset(w http.ResponseWriter, r *http.Request) {
	file := chi.URLParam(r, "file")
	ctype, ok := vayuWebAllowlist[file]
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(embeddedStaticFS, "vayuweb/"+file)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "public, immutable, max-age=31536000")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

// handleThemeGet was the /admin/theme theme-editor page. The route is gone:
// the console's theme surface lives at /os/theme and the legacy path now
// redirects there (admin_legacy.go), which left this handler with no caller â€”
// staticcheck's U1000 rightly flagged it as dead. themeEditorPage stays: the
// theme-contrast tests render through it directly.

// themeExportVersion is the schema version of an exported theme bundle. Bump it
// only on a breaking change to the export shape so importers can refuse bundles
// they don't understand (fail-closed) rather than silently mis-applying them.
const themeExportVersion = 1

// handleThemeExport streams the theme as a downloadable JSON bundle.
//
// It emits the settings the theme editor round-trips and NOTHING ELSE, which is
// narrower than "the settings allowlist" and the distinction is the whole point:
// AllKeys says what may be WRITTEN, and a great deal that may be written is
// credentials, network policy or facts about this machine. settings.NotPortable
// draws that line and this handler honours it.
//
// The previous version of this comment claimed the bundle carried "no secrets"
// and was "safe to share". It carried a live API key.
func (a *App) handleThemeExport(w http.ResponseWriter, r *http.Request) {
	vals, err := a.siteSettings.GetAll(r.Context(), settings.ForPrimary())
	if err != nil {
		http.Error(w, "failed to load settings", 500)
		return
	}
	// Emit only what a THEME is, which is not the same as what is writable.
	//
	// This loop used to walk settings.AllKeys, and the doc comment above it
	// promised "no secrets â€¦ safe to share". Both were wrong: the bundle carried
	// tor.space_api_key â€” a live API key â€” plus the shield's allow and deny CIDR
	// lists, the cluster peers, payment configuration, contact addresses and the
	// VayuKeep backup destination. The UI invites an operator to download this
	// and "apply it everywhere", which is precisely the action that hands all of
	// that to somebody else.
	//
	// settings.NotPortable is the authoritative set of keys that are not part of
	// a look. It lives in the settings package rather than here, because the
	// theme editor's conformance test needs the same answer and the two drifting
	// apart is what produced the leak: the test knew these keys had no editor
	// field while the exporter shipped them anyway.
	out := make(map[string]string, len(settings.AllKeys))
	for key := range settings.AllKeys {
		if settings.NotPortable[key] {
			continue
		}
		out[key] = vals[key]
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="vayupress-theme.json"`)
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"vayupress_theme": themeExportVersion,
		"settings":        out,
	})
}

// handleThemeReset restores every setting to its compile-time default and
// propagates the change through the render pipeline identically to a Save.
// It is a CSRF-protected POST â€” idempotent on a clean install, but a
// deliberate, irreversible write on a customised one. The operator must
// explicitly confirm in the browser before the request is sent.
func (a *App) handleThemeReset(w http.ResponseWriter, r *http.Request) {
	cur := mode.Global.Current()
	if cur == mode.ModeReadOnly || cur == mode.ModeQuarantined {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(503)
		json.NewEncoder(w).Encode(map[string]string{"error": "settings cannot be reset in " + string(cur) + " mode"}) //nolint:errcheck
		return
	}

	if err := a.siteSettings.SetMany(r.Context(), settings.ForPrimary(), settings.Defaults); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": "reset failed: " + err.Error()}) //nolint:errcheck
		return
	}

	if newVals, err := a.siteSettings.GetAll(r.Context(), settings.ForPrimary()); err == nil {
		render.SetActiveSettings(render.SiteSettings{
			Name:            newVals[settings.KeySiteName],
			Tagline:         newVals[settings.KeySiteTagline],
			Description:     newVals[settings.KeySiteDescription],
			Author:          newVals[settings.KeySiteAuthor],
			AuthorBio:       newVals[settings.KeyAuthorBio],
			ShowMembership:  newVals[settings.KeyMembershipButtons] == "true",
			PrimaryLight:    newVals[settings.KeyThemePrimaryLight],
			PrimaryDark:     newVals[settings.KeyThemePrimaryDark],
			AccentLight:     newVals[settings.KeyThemeAccentLight],
			AccentDark:      newVals[settings.KeyThemeAccentDark],
			CustomCSS:       newVals[settings.KeyThemeCustomCSS],
			Keywords:        newVals[settings.KeyHeadKeywords],
			ThemeColor:      newVals[settings.KeyHeadThemeColor],
			Robots:          newVals[settings.KeyHeadRobots],
			VerifyGoogle:    newVals[settings.KeyHeadVerifyGoogle],
			VerifyBing:      newVals[settings.KeyHeadVerifyBing],
			NavJSON:         newVals[settings.KeyNavItems],
			FooterJSON:      newVals[settings.KeyFooterConfig],
			OGImage:         render.OGImagePath(newVals[settings.KeyThemeOGImage]),
			ShowHero:        newVals[settings.KeyHomeHero] == "true",
			CommentsEnabled: newVals[settings.KeyFeatureComments] != "off",
		})
	}

	render.CachePurgeAll()
	go generateSitemap()
	go generateRSS()
	go generateRobots()

	logging.LogJSON(logging.LogFields{
		Level: "info", Component: "theme", Severity: "info",
		Msg: "site settings reset to defaults", RequestID: getRequestID(r),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck
}

// handleThemeSave processes the JSON POST from the theme editor.
// The browser sends application/json via fetch with the X-CSRF-Token header.
func (a *App) handleThemeSave(w http.ResponseWriter, r *http.Request) {
	cur := mode.Global.Current()
	if cur == mode.ModeReadOnly || cur == mode.ModeQuarantined {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(503)
		json.NewEncoder(w).Encode(map[string]string{"error": "settings cannot be saved in " + string(cur) + " mode"}) //nolint:errcheck
		return
	}

	fail := func(code int, msg string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
	}

	var body struct {
		SiteName        string `json:"site.name"`
		SiteTagline     string `json:"site.tagline"`
		SiteDescription string `json:"site.description"`
		SiteAuthor      string `json:"site.author"`
		PrimaryLight    string `json:"theme.primary_light"`
		PrimaryDark     string `json:"theme.primary_dark"`
		AccentLight     string `json:"theme.accent_light"`
		AccentDark      string `json:"theme.accent_dark"`
		CustomCSS       string `json:"theme.custom_css"`
		Keywords        string `json:"head.keywords"`
		ThemeColor      string `json:"head.theme_color"`
		Robots          string `json:"head.robots"`
		VerifyGoogle    string `json:"head.verify_google"`
		VerifyBing      string `json:"head.verify_bing"`
	}
	// Cap the request body before decoding. The largest legitimate field is the
	// 64 KB custom CSS (checked again post-decode); 128 KB leaves generous room
	// for the other small fields while refusing an oversized body up front rather
	// than streaming it into the decoder.
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(400, "invalid JSON: "+err.Error())
		return
	}

	customCSS := strings.TrimSpace(body.CustomCSS)
	if len(customCSS) > 64*1024 {
		fail(400, "Custom CSS exceeds the 64 KB limit")
		return
	}

	// Validate colour fields are #rgb / #rrggbb so they can't break the served
	// stylesheet or smuggle extra CSS declarations into the variable block.
	for label, val := range map[string]string{
		"Primary (light)": body.PrimaryLight,
		"Primary (dark)":  body.PrimaryDark,
		"Accent (light)":  body.AccentLight,
		"Accent (dark)":   body.AccentDark,
		"Theme colour":    body.ThemeColor,
	} {
		if v := strings.TrimSpace(val); v != "" && !hexColorRe.MatchString(v) {
			fail(400, label+" must be a hex colour like #0d9488")
			return
		}
	}

	// Declarative <head> capabilities: each is allowlisted/tokenised so only a
	// safe, escaped <meta> subset can ever reach the document head.
	keywords := strings.TrimSpace(body.Keywords)
	if len(keywords) > 256 {
		fail(400, "Keywords exceed the 256-character limit")
		return
	}
	robots := strings.TrimSpace(body.Robots)
	if !settings.RobotsOptions[robots] {
		fail(400, "Robots directive is not an allowed value")
		return
	}
	verifyGoogle := strings.TrimSpace(body.VerifyGoogle)
	verifyBing := strings.TrimSpace(body.VerifyBing)
	for label, tok := range map[string]string{
		"Google verification": verifyGoogle,
		"Bing verification":   verifyBing,
	} {
		if tok != "" && !verifyTokenRe.MatchString(tok) {
			fail(400, label+" token may contain only letters, digits, '-', '_', and '.'")
			return
		}
	}

	kv := map[string]string{
		settings.KeySiteName:          strings.TrimSpace(body.SiteName),
		settings.KeySiteTagline:       strings.TrimSpace(body.SiteTagline),
		settings.KeySiteDescription:   strings.TrimSpace(body.SiteDescription),
		settings.KeySiteAuthor:        strings.TrimSpace(body.SiteAuthor),
		settings.KeyThemePrimaryLight: strings.TrimSpace(body.PrimaryLight),
		settings.KeyThemePrimaryDark:  strings.TrimSpace(body.PrimaryDark),
		settings.KeyThemeAccentLight:  strings.TrimSpace(body.AccentLight),
		settings.KeyThemeAccentDark:   strings.TrimSpace(body.AccentDark),
		settings.KeyThemeCustomCSS:    customCSS,
		settings.KeyHeadKeywords:      keywords,
		settings.KeyHeadThemeColor:    strings.TrimSpace(body.ThemeColor),
		settings.KeyHeadRobots:        robots,
		settings.KeyHeadVerifyGoogle:  verifyGoogle,
		settings.KeyHeadVerifyBing:    verifyBing,
	}

	if err := a.siteSettings.SetMany(r.Context(), settings.ForPrimary(), kv); err != nil {
		fail(500, "save failed: "+err.Error())
		return
	}

	// Push updated values into the render pipeline immediately.
	if newVals, err := a.siteSettings.GetAll(r.Context(), settings.ForPrimary()); err == nil {
		render.SetActiveSettings(render.SiteSettings{
			Name:            newVals[settings.KeySiteName],
			Tagline:         newVals[settings.KeySiteTagline],
			Description:     newVals[settings.KeySiteDescription],
			Author:          newVals[settings.KeySiteAuthor],
			AuthorBio:       newVals[settings.KeyAuthorBio],
			ShowMembership:  newVals[settings.KeyMembershipButtons] == "true",
			PrimaryLight:    newVals[settings.KeyThemePrimaryLight],
			PrimaryDark:     newVals[settings.KeyThemePrimaryDark],
			AccentLight:     newVals[settings.KeyThemeAccentLight],
			AccentDark:      newVals[settings.KeyThemeAccentDark],
			CustomCSS:       newVals[settings.KeyThemeCustomCSS],
			Keywords:        newVals[settings.KeyHeadKeywords],
			ThemeColor:      newVals[settings.KeyHeadThemeColor],
			Robots:          newVals[settings.KeyHeadRobots],
			VerifyGoogle:    newVals[settings.KeyHeadVerifyGoogle],
			VerifyBing:      newVals[settings.KeyHeadVerifyBing],
			NavJSON:         newVals[settings.KeyNavItems],
			FooterJSON:      newVals[settings.KeyFooterConfig],
			OGImage:         render.OGImagePath(newVals[settings.KeyThemeOGImage]),
			ShowHero:        newVals[settings.KeyHomeHero] == "true",
			CommentsEnabled: newVals[settings.KeyFeatureComments] != "off",
		})
	}

	// Identity (name/tagline/description) and custom <head> are baked into the
	// cached HTML, so purge all rendered fragments and regenerate the feeds.
	// The palette propagates separately via /theme.css revalidation.
	render.CachePurgeAll()
	go generateSitemap()
	go generateRSS()
	go generateRobots()

	logging.LogJSON(logging.LogFields{
		Level: "info", Component: "theme", Severity: "info",
		Msg: "site settings updated", RequestID: getRequestID(r),
	})

	// Advisory WCAG AA contrast warnings â€” the save succeeds regardless; theme
	// sovereignty means we surface accessibility risks, not veto them.
	warnings := contrastWarnings(
		strings.TrimSpace(body.PrimaryLight),
		strings.TrimSpace(body.PrimaryDark),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"status":   "ok",
		"warnings": warnings,
	})
}
