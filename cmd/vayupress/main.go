// SPDX-License-Identifier: Apache-2.0

// VayuPress — main.go  v1.2.0
// Bootstrap, route wiring, and graceful shutdown only.
// Domain logic lives in internal/* packages (ADR-0045 – ADR-0050).
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	_ "github.com/mattn/go-sqlite3"
	"github.com/microcosm-cc/bluemonday"

	"github.com/johalputt/vayupress/internal/ads"
	"github.com/johalputt/vayupress/internal/aiassist"
	"github.com/johalputt/vayupress/internal/analytics"
	"github.com/johalputt/vayupress/internal/anonaudit"
	"github.com/johalputt/vayupress/internal/api"
	"github.com/johalputt/vayupress/internal/apikeys"
	"github.com/johalputt/vayupress/internal/auth"
	"github.com/johalputt/vayupress/internal/budget"
	"github.com/johalputt/vayupress/internal/collections"
	"github.com/johalputt/vayupress/internal/comments"
	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/domain"
	"github.com/johalputt/vayupress/internal/email"
	"github.com/johalputt/vayupress/internal/emailtmpl"
	"github.com/johalputt/vayupress/internal/events"
	"github.com/johalputt/vayupress/internal/fault"
	"github.com/johalputt/vayupress/internal/health"
	"github.com/johalputt/vayupress/internal/httputil"
	"github.com/johalputt/vayupress/internal/i18n"
	"github.com/johalputt/vayupress/internal/lifecycle"
	"github.com/johalputt/vayupress/internal/logging"
	"github.com/johalputt/vayupress/internal/members"
	"github.com/johalputt/vayupress/internal/metrics"
	"github.com/johalputt/vayupress/internal/mode"
	"github.com/johalputt/vayupress/internal/newsletter"
	"github.com/johalputt/vayupress/internal/oauth"
	"github.com/johalputt/vayupress/internal/outbox"
	"github.com/johalputt/vayupress/internal/payments"
	"github.com/johalputt/vayupress/internal/plugins"
	"github.com/johalputt/vayupress/internal/policy"
	"github.com/johalputt/vayupress/internal/preview"
	"github.com/johalputt/vayupress/internal/queue"
	"github.com/johalputt/vayupress/internal/redirects"
	"github.com/johalputt/vayupress/internal/render"
	"github.com/johalputt/vayupress/internal/resource"
	"github.com/johalputt/vayupress/internal/safefetch"
	"github.com/johalputt/vayupress/internal/scheduler"
	"github.com/johalputt/vayupress/internal/search"
	"github.com/johalputt/vayupress/internal/secrets"
	"github.com/johalputt/vayupress/internal/settings"
	"github.com/johalputt/vayupress/internal/social"
	"github.com/johalputt/vayupress/internal/theme"
	"github.com/johalputt/vayupress/internal/trace"
	"github.com/johalputt/vayupress/internal/update"
	"github.com/johalputt/vayupress/internal/users"
	"github.com/johalputt/vayupress/internal/vayuflow"
	mailpkg "github.com/johalputt/vayupress/internal/vayuos/mail"
	"github.com/johalputt/vayupress/internal/vayuveil"
	"github.com/johalputt/vayupress/internal/versions"
	"github.com/johalputt/vayupress/internal/webhooks"
	"github.com/johalputt/vayupress/internal/webmention"
	"github.com/johalputt/vayupress/internal/ws"
)

// Version is the fallback build version. CI stamps the real version via
// -ldflags "-X main.Version=<.release-version>", and scripts/update-vayupress.sh
// reads .release-version too — keep this in sync with .release-version so an
// un-stamped `go build` still reports an honest version.
var Version = "3.17.61"
var bootTime = time.Now()

// onionSafeBindAddr picks the HTTP listen address (ADR-0141).
//
// A Tor Space (OnionMode) is reached ONLY through Tor's HiddenServicePort →
// 127.0.0.1, so it binds loopback and its content is never exposed on the host's
// public clearnet IP — closing an onion-deanonymisation vector.
//
// A clearnet install used to bind every interface unconditionally, which meant
// the whole app — the admin console included — was served on http://<host>:8080
// with no nginx, no TLS and no Tier 3 shaping in front of it, to anyone who
// scanned the port. The kernel tier does not cover it either: its chain policy is
// accept and its rules only name 80 and 443. The onion reasoning above applies
// just as well here; it had simply never been generalised.
//
// The default is now loopback, because on the overwhelmingly common deployment a
// reverse proxy on the same host is the only thing that should reach the app.
// Two escapes exist, and both are needed:
//
//   - BIND_ADDR is honoured verbatim. "0.0.0.0" is the explicit opt-in for an
//     install that really does serve directly.
//   - Containers bind all interfaces automatically. docker-compose.yml exposes
//     8080 on the private Compose network and both Caddyfiles proxy to
//     "vayupress:8080" BY HOSTNAME — cross-container, so a loopback bind inside
//     the netns is unreachable and the site would simply stop working. Detecting
//     this beats breaking every containerised install to close a port that the
//     container runtime already isolates.
func onionSafeBindAddr(port string, onion bool) string {
	if onion {
		return "127.0.0.1:" + port
	}
	if b := strings.TrimSpace(config.EnvOr("BIND_ADDR", "")); b != "" {
		if strings.Contains(b, ":") && !strings.HasPrefix(b, "[") {
			return b // already host:port (or an IPv6 literal the operator bracketed)
		}
		return b + ":" + port
	}
	if runningInContainer() {
		return ":" + port
	}
	return "127.0.0.1:" + port
}

// runningInContainer reports whether this process is inside a container, where
// binding loopback would make the app unreachable from a sibling container.
func runningInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	// cgroup v1 names the runtime in the path; v2 exposes it here too on the
	// runtimes that matter. A read failure means "not a container" — the safe
	// direction, since the cost of guessing wrong is a bind that is too tight
	// rather than a port opened to the internet.
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		for _, marker := range []string{"docker", "containerd", "kubepods", "podman", "lxc"} {
			if strings.Contains(s, marker) {
				return true
			}
		}
	}
	return false
}

// Immutable package-level values (compiled once, never mutated).
var htmlTagRe = regexp.MustCompile(`<[^>]+>`)

// =============================================================================
// Response helpers (thin wrappers over internal/httputil)
// =============================================================================

func writeJSON(w http.ResponseWriter, r *http.Request, code int, v interface{}) {
	httputil.WriteJSON(w, code, v)
}

func writeAPIError(w http.ResponseWriter, r *http.Request, code int, errCode, msg, docsURL string) {
	reqID := ""
	if r != nil {
		reqID = getRequestID(r)
	}
	httputil.WriteError(w, code, errCode, msg, reqID, docsURL)
}

func readJSONDirect(r *http.Request, v interface{}) error {
	return httputil.DecodeJSON(r, v)
}

// bootstrapDefaultAdmin creates a ready-to-use administrator on a brand-new
// install so the operator can log in immediately without the CLI. The account is
// admin@<domain> with a strong random password and the must-change-password flag
// set (the console forces a new password on first login). The credentials are
// written to a root-only file next to the database AND logged once, so they are
// easy to find however the operator runs the service.
func (a *App) bootstrapDefaultAdmin(ctx context.Context) {
	domain := strings.TrimSpace(config.Cfg.Domain)
	if domain == "" || domain == "localhost" {
		domain = "localhost"
	}
	email := "admin@" + domain
	pass, err := generateInitialPassword()
	if err != nil {
		// No CSPRNG at bootstrap means no unpredictable credential. A
		// time-derived fallback would be guessable from boot logs, so refuse to
		// create the account rather than mint a known password (audit:
		// time-derived fallback password).
		logging.LogError("users", "default admin bootstrap aborted: no secure randomness available", err.Error())
		logging.LogInfo("users", "create one manually: vayupress user add <email> <password> --admin")
		return
	}
	if _, err := a.userStore.CreateBootstrapAdmin(ctx, email, "Administrator", pass); err != nil {
		logging.LogError("users", "default admin bootstrap failed", err.Error())
		logging.LogInfo("users", "create one manually: vayupress user add <email> <password> --admin")
		return
	}

	// Persist the credentials to a root-only file beside the DB so they survive a
	// scrolled-past log. Best-effort: if the write fails, the operator is told to
	// bootstrap by hand — the password itself is never logged (audit: a
	// credential in a log line lands in journald rotations and every `docker
	// logs` scrollback forever).
	credPath := filepath.Join(filepath.Dir(config.Cfg.DBPath), "initial-admin.txt")
	content := "VayuPress initial administrator (CHANGE THE PASSWORD ON FIRST LOGIN)\n" +
		"URL:      /os/login\n" +
		"Email:    " + email + "\n" +
		"Password: " + pass + "\n"
	if err := os.WriteFile(credPath, []byte(content), 0o600); err != nil {
		logging.LogWarn("users", "could not write initial-admin.txt ("+err.Error()+"); create the admin manually: vayupress user add <email> <password> --admin")
	}

	logging.LogInfo("users", "════════════════════════════════════════════════════════")
	logging.LogInfo("users", "Default admin created — sign in at /os/login and change the password")
	logging.LogInfo("users", "  Email:    "+email)
	logging.LogInfo("users", "  Password saved to: "+credPath+" (root-only file)")
	logging.LogInfo("users", "════════════════════════════════════════════════════════")
}

// generateInitialPassword returns a strong, readable 20-character random password
// (no ambiguous characters) for the bootstrapped admin. It fails closed: if the
// CSPRNG is unavailable there is NO time-derived fallback, which would be
// guessable from boot logs.
func generateInitialPassword() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// =============================================================================
// Sitemap / RSS / robots

// =============================================================================

// warmStartupDelay is how long the boot-time cache warm waits for the box to
// settle before it starts the (paced) re-render. Tunable via VAYU_WARM_DELAY_SEC
// (clamped to 0..600s); defaults to a gentle 4s.
func warmStartupDelay() time.Duration {
	if n, err := strconv.Atoi(config.EnvOr("VAYU_WARM_DELAY_SEC", "4")); err == nil && n >= 0 && n <= 600 {
		return time.Duration(n) * time.Second
	}
	return 4 * time.Second
}

// searchSaveInterval is how often the persisted search index snapshot is
// refreshed so a restart reconciles only recent changes. Tunable via
// VAYU_SEARCH_SAVE_MIN (clamped to 1..1440 minutes); defaults to 10 minutes.
func searchSaveInterval() time.Duration {
	if n, err := strconv.Atoi(config.EnvOr("VAYU_SEARCH_SAVE_MIN", "10")); err == nil && n >= 1 && n <= 1440 {
		return time.Duration(n) * time.Minute
	}
	return 10 * time.Minute
}

// generateSitemap writes the historic global sitemap (every published article,
// primary host) to sitemap.xml. It is the single-domain / primary artefact and is
// byte-identical to the pre-VayuDomains output; the per-domain variant is written
// by writeSitemapScoped on the multi-domain serve path (ADR-0132 Stage 2c).
func generateSitemap() { writeSitemapScoped(config.Cfg.Domain, "", false, "sitemap.xml") }

// writeSitemapScoped renders a sitemap for one host into rel. With scoped=false it
// reproduces the historic global sitemap exactly (no domain filter, primary host).
// With scoped=true it lists only the given domain's articles (domain_id=scope)
// under that domain's host — the artefact served on a secondary domain.
// sitemapChunk is how many post URLs go in one sitemap file.
//
// The protocol caps a single sitemap at 50,000 URLs and 50 MB. Staying under
// that with headroom is not fussiness: a file that breaches the cap can be
// rejected WHOLE, so the failure is not "the last few are ignored" but "none of
// them are seen".
// A var, not a const, so a test can shrink it and exercise the chunk boundary
// with a handful of rows instead of 45,000. The boundary is the whole point of
// this code; a test that cannot reach it is testing the easy half.
var sitemapChunk = 45000

// sitemapChildRel derives a child filename from the index's own name, so a
// scoped index (sitemap_d_<domain>.xml) gets matching children. The caller's
// value never becomes a path component: n is an int and the base is our own
// constant-derived string.
func sitemapChildRel(indexRel string, n int) string {
	return strings.TrimSuffix(indexRel, ".xml") + "-" + strconv.Itoa(n) + ".xml"
}

// sitemapTagsRel is the child holding the taxonomy.
func sitemapTagsRel(indexRel string) string {
	return strings.TrimSuffix(indexRel, ".xml") + "-tags.xml"
}

// writeSitemapScoped writes a sitemap INDEX plus its children.
//
// It used to write one file with `LIMIT 50000` and then append every tag page
// after it. On a site of 234,000 posts that silently omitted four fifths of the
// content — those URLs were never announced to anything — and the appended tag
// pages pushed the file past the 50,000-URL cap, which invites a search engine
// to discard the entire document rather than the overflow. A sitemap that is
// both truncated and over the limit is worse than none: it looks authoritative
// and describes a site that does not exist.
func writeSitemapScoped(host, scope string, scoped bool, rel string) {
	domClause := ""
	var domArgs []any
	if scoped {
		domClause = " AND domain_id=?"
		domArgs = []any{scope}
	}
	rows, err := dbpkg.Reader().Query(`SELECT slug,updated_at FROM articles WHERE COALESCE(status,'published')='published' AND COALESCE(is_page,0)=0`+domClause+` ORDER BY updated_at DESC`, domArgs...)
	if err != nil {
		return
	}
	defer rows.Close()

	var children []string
	var sb strings.Builder
	n, inChunk := 0, 0
	openChunk := func() {
		sb.Reset()
		sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)
		inChunk = 0
	}
	closeChunk := func() {
		if inChunk == 0 {
			return
		}
		sb.WriteString("</urlset>")
		n++
		child := sitemapChildRel(rel, n)
		render.CacheWrite(child, sb.String()) //nolint:errcheck
		children = append(children, child)
	}
	openChunk()
	for rows.Next() {
		var slug string
		var updated time.Time
		rows.Scan(&slug, &updated) //nolint:errcheck
		var locBuf strings.Builder
		xml.EscapeText(&locBuf, []byte(fmt.Sprintf("https://%s/%s", host, slug))) //nolint:errcheck
		fmt.Fprintf(&sb, "<url><loc>%s</loc><lastmod>%s</lastmod></url>", locBuf.String(), updated.Format("2006-01-02"))
		inChunk++
		if inChunk >= sitemapChunk {
			closeChunk()
			openChunk()
		}
	}
	_ = rows.Err() // best-effort sitemap; regenerated on the next change
	closeChunk()

	// Tags get their own child rather than riding on the last post chunk, so the
	// taxonomy cannot be what tips a file over the cap.
	sb.Reset()
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)
	before := sb.Len()
	sitemapAppendTagPages(&sb, host, scope, scoped)
	if sb.Len() > before {
		sb.WriteString("</urlset>")
		tagsRel := sitemapTagsRel(rel)
		render.CacheWrite(tagsRel, sb.String()) //nolint:errcheck
		children = append(children, tagsRel)
	}

	// The index itself. Always an index, even for one child: one shape to serve,
	// one shape to test, and room to grow without changing what robots.txt points
	// at or what an operator has already submitted to a search console.
	var idx strings.Builder
	idx.WriteString(`<?xml version="1.0" encoding="UTF-8"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)
	today := time.Now().UTC().Format("2006-01-02")
	for _, c := range children {
		var locBuf strings.Builder
		xml.EscapeText(&locBuf, []byte(fmt.Sprintf("https://%s/%s", host, c))) //nolint:errcheck
		fmt.Fprintf(&idx, "<sitemap><loc>%s</loc><lastmod>%s</lastmod></sitemap>", locBuf.String(), today)
	}
	idx.WriteString("</sitemapindex>")
	render.CacheWrite(rel, idx.String()) //nolint:errcheck
}

// sitemapAppendTagPages adds the topic index (/tags) and every per-tag listing
// (/tags/<tag>) to the sitemap so search engines discover the taxonomy. Tags are
// gathered from published articles, deduplicated case-insensitively, and the URL
// path segment is escaped to match the live route's decoding. When scoped, only
// the given domain's tags are enumerated and links carry that domain's host.
func sitemapAppendTagPages(sb *strings.Builder, host, scope string, scoped bool) {
	domClause := ""
	var domArgs []any
	if scoped {
		domClause = " AND domain_id=?"
		domArgs = []any{scope}
	}
	rows, err := dbpkg.Reader().Query(`SELECT tags FROM articles WHERE tags != '' AND COALESCE(status,'published')='published'`+domClause, domArgs...)
	if err != nil {
		return
	}
	defer rows.Close()
	seen := make(map[string]string) // lower(tag) -> first-seen display form
	for rows.Next() {
		var csv string
		if rows.Scan(&csv) != nil {
			continue
		}
		for _, t := range api.SplitTags(csv) {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if _, ok := seen[strings.ToLower(t)]; !ok {
				seen[strings.ToLower(t)] = t
			}
		}
	}
	_ = rows.Err() // best-effort tag enumeration for the sitemap
	// Topic index.
	var idxBuf strings.Builder
	xml.EscapeText(&idxBuf, []byte(fmt.Sprintf("https://%s/tags", host))) //nolint:errcheck
	fmt.Fprintf(sb, "<url><loc>%s</loc></url>", idxBuf.String())
	for _, display := range seen {
		var locBuf strings.Builder
		loc := fmt.Sprintf("https://%s/tags/%s", host, url.PathEscape(display))
		xml.EscapeText(&locBuf, []byte(loc)) //nolint:errcheck
		fmt.Fprintf(sb, "<url><loc>%s</loc></url>", locBuf.String())
	}
}

// generateRSS writes the historic global feed (latest 50 published articles,
// primary host) to feed.xml — the single-domain / primary artefact, byte-identical
// to the pre-VayuDomains output. writeRSSScoped produces the per-domain variant.
func generateRSS() { writeRSSScoped(config.Cfg.Domain, "", false, "feed.xml") }

// writeRSSScoped renders an RSS feed for one host into rel. With scoped=false it
// reproduces the historic global feed exactly; with scoped=true it carries only
// the given domain's latest articles under that domain's host.
func writeRSSScoped(host, scope string, scoped bool, rel string) {
	domClause := ""
	var domArgs []any
	if scoped {
		domClause = " AND domain_id=?"
		domArgs = []any{scope}
	}
	rows, err := dbpkg.Reader().Query(`SELECT title,slug,content,created_at FROM articles WHERE COALESCE(status,'published')='published' AND COALESCE(is_page,0)=0`+domClause+` ORDER BY created_at DESC LIMIT 50`, domArgs...)
	if err != nil {
		return
	}
	defer rows.Close()
	var items strings.Builder
	for rows.Next() {
		var title, slug, content string
		var created time.Time
		rows.Scan(&title, &slug, &content, &created)
		plain := htmlTagRe.ReplaceAllString(bluemonday.StrictPolicy().Sanitize(content), "")
		if len(plain) > 500 {
			plain = plain[:500] + "..."
		}
		var linkBuf, guidBuf strings.Builder
		xml.EscapeText(&linkBuf, []byte(fmt.Sprintf("https://%s/%s", host, slug))) //nolint:errcheck
		xml.EscapeText(&guidBuf, []byte(fmt.Sprintf("https://%s/%s", host, slug))) //nolint:errcheck
		// CDATA wraps title/plain — strip any embedded ]]> sequences defensively
		safeTitle := strings.ReplaceAll(title, "]]>", "]]]]><![CDATA[>")
		safePlain := strings.ReplaceAll(plain, "]]>", "]]]]><![CDATA[>")
		fmt.Fprintf(&items, "<item><title><![CDATA[%s]]></title><link>%s</link><guid isPermaLink=\"true\">%s</guid><pubDate>%s</pubDate><description><![CDATA[%s]]></description></item>",
			safeTitle, linkBuf.String(), guidBuf.String(), created.Format(time.RFC1123Z), safePlain)
	}
	_ = rows.Err() // best-effort RSS feed; regenerated on the next change
	rss := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>%s</title><link>https://%s</link><description>%s</description>%s</channel></rss>`,
		host, host, host, items.String())
	render.CacheWrite(rel, rss) //nolint:errcheck
}

// generateRobots writes the historic global robots.txt (primary host).
// writeRobotsScoped produces a per-domain variant pointing at that host's sitemap.
func generateRobots() { writeRobotsScoped(config.Cfg.Domain, "robots.txt") }

func writeRobotsScoped(host, rel string) {
	// The trailing comment advertises /llms.txt. There is no standard robots.txt
	// directive for it, and inventing one risks a strict parser rejecting the
	// file — a comment is ignored by every parser and still found by anyone
	// reading robots.txt to discover what a site offers.
	render.CacheWrite(rel, fmt.Sprintf("User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /admin\n\nSitemap: https://%s/sitemap.xml\n# LLM index: https://%s/llms.txt\n", host, host)) //nolint:errcheck
}

// =============================================================================
// main
// =============================================================================

// secretKEKFilePath returns the host-bound file whose contents wrap the secrets
// DEK when VAYU_SECRET is not set (audit L6) — so the at-rest key lives outside
// the database. Override with VAYU_SECRET_KEK_FILE; otherwise it sits beside the
// database (a stable, service-owned, 0600 location), mirroring the CSRF secret.
// Empty when no stable location is known (the DEK then falls back to in-DB
// storage with a loud warning).
func secretKEKFilePath() string {
	if p := strings.TrimSpace(os.Getenv("VAYU_SECRET_KEK_FILE")); p != "" {
		return p
	}
	if db := strings.TrimSpace(config.Cfg.DBPath); db != "" {
		return filepath.Join(filepath.Dir(db), ".vayu-secret-kek")
	}
	return ""
}

func main() {
	log.SetFlags(0)

	// obfs4 pluggable-transport mode: tor execs this same binary as its bridge
	// transport (see VayuTor's managedTor.resolvePT). Handle it FIRST — before any
	// config/DB/server init — since stdout is the PT protocol channel, and exit.
	if len(os.Args) > 1 && os.Args[1] == obfs4Subcommand {
		runEmbeddedObfs4()
		os.Exit(0)
	}

	// VayuVeil (ADR-0150): refuse to be dumped, BEFORE anything sensitive is
	// loaded.
	//
	// The ordering is the point. This runs before config.Load, before the
	// database opens and before the keystore is unsealed, so there is no window
	// in which a core file or a same-user /proc/<pid>/mem read could reach a
	// session token, the keystore key, decrypted mail or PGP material. Gating it
	// on a stored setting would mean reading the database first, which is exactly
	// the window it exists to close — so it is unconditional, and the escape
	// hatch is an environment variable rather than a row in a table.
	//
	// VAYU_ALLOW_COREDUMP=1 keeps the process dumpable for an operator who is
	// genuinely debugging a crash. The posture report reads the kernel back
	// either way, so it says what is actually true rather than which branch ran.
	if os.Getenv("VAYU_ALLOW_COREDUMP") != "1" {
		if err := vayuveil.ApplyProcessHardening(); err != nil {
			// Not fatal. A platform that cannot do this still serves; the report
			// tells the operator it is not enforcing rather than the binary
			// refusing to start over a hardening step.
			log.Printf("vayuveil: could not harden this process against being dumped: %v", err)
		}
	}
	// Logged from the kernel's answer, not from whether the call above returned
	// nil. An operator reading the log learns what is true rather than which
	// branch ran, which is the same rule the panel page follows.
	logVeilPosture(vayuveil.VerifyProcessHardening(), vayuveil.ReadSandbox())

	// Give the GC a memory ceiling to aim at (cgroup-aware; honours an explicit
	// GOMEMLIMIT). Keeps steady RSS bounded and avoids OOM-kill overshoot on
	// containers/VPS. No-op on bare hosts with no cgroup limit. (RAM audit 2026-07)
	applyMemorySoftLimit()

	// CLI subcommands run before the server boots. `vayupress update
	// <check|apply|history>` applies a signed binary update, gated and
	// signature-verified (ADR-0064).
	//
	// This comment used to claim the CLI was the ONLY path and that the web layer
	// was read-only. That stopped being true when /os/api/update/apply shipped,
	// and the stale sentence was enough to make a reader doubt that an operator
	// can update from the panel at all — which is the whole premise of the
	// product. A comment that describes a constraint the code no longer has is
	// the same defect as a panel row that overstates what is enforcing.
	if len(os.Args) > 1 && os.Args[1] == "update" {
		config.Load()
		if err := dbpkg.Init(); err != nil {
			fmt.Fprintln(os.Stderr, "DB init failed:", err)
			os.Exit(1)
		}
		if err := update.RunCLI(context.Background(), os.Args[2:], os.Stdout, dbpkg.DB, Version); err != nil {
			fmt.Fprintln(os.Stderr, "update:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// talk subcommand: record the hostname advertised for the VayuTalk relay.
	//
	// Same shape and same reason as `domains` below — a privileged helper needs
	// to record one fact and the unprivileged server cannot obtain a certificate
	// itself. LoadLocalCLI for the same reason too: this reads and writes local
	// state and serves nothing, so API_KEY is not its business, and requiring it
	// is what silently broke provisioning for a week.
	if len(os.Args) > 1 && os.Args[1] == "talk" {
		config.LoadLocalCLI()
		// InitCLI, not Init — see internal/db/cli.go. This runs from the
		// privileged subdomain helper while the server is serving traffic, and
		// Init is the SERVER's opening sequence: it takes the write lock to
		// create a table that exists, scans 87 migrations, maps half a gigabyte
		// and opens two dozen readers. The server's single write connection
		// blocks behind that, every page view needs a write, and visitors get
		// 502 from a process that never went down.
		if err := dbpkg.InitCLI(); err != nil {
			fmt.Fprintln(os.Stderr, "DB init failed:", err)
			os.Exit(1)
		}
		if err := runTalkCLI(os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "talk:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// domains subcommand: list registered domains + record per-domain TLS state.
	// It is the read/notify surface the privileged TLS+nginx helper drives from
	// (the server runs unprivileged and cannot certbot/reload nginx itself).
	if len(os.Args) > 1 && os.Args[1] == "domains" {
		// LoadLocalCLI, not Load: this subcommand reads and writes the local
		// registry and serves nothing, so API_KEY is not its business. Requiring
		// it made the privileged provisioning helper — which runs from a systemd
		// unit that carried no EnvironmentFile — exit fatal before reading a
		// single row, for a week, silently.
		config.LoadLocalCLI()
		// InitCLI for the same reason as `talk` above: this is what the
		// provisioning helper calls once per domain, while the site is live.
		if err := dbpkg.InitCLI(); err != nil {
			fmt.Fprintln(os.Stderr, "DB init failed:", err)
			os.Exit(1)
		}
		if err := runDomainsCLI(os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "domains:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// user subcommand: manage accounts (bootstrap the first admin, etc.).
	if len(os.Args) > 1 && os.Args[1] == "user" {
		config.Load()
		if err := dbpkg.Init(); err != nil {
			fmt.Fprintln(os.Stderr, "DB init failed:", err)
			os.Exit(1)
		}
		if err := runUserCLI(os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "user:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// mail subcommand: VayuMail break-glass and recovery inspection (ADR-0144).
	// Runs WITHOUT starting the server, so it works on a host whose service is
	// down — which is often the situation that made it necessary.
	if len(os.Args) > 1 && os.Args[1] == "mail" {
		config.Load()
		if err := dbpkg.Init(); err != nil {
			fmt.Fprintln(os.Stderr, "DB init failed:", err)
			os.Exit(1)
		}
		accts, err := mailpkg.NewAccountStore(dbpkg.DB)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mail:", err)
			os.Exit(1)
		}
		if err := runMailCLI(context.Background(), os.Args[2:], os.Stdout, accts); err != nil {
			fmt.Fprintln(os.Stderr, "mail:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// migrate subcommand: import Markdown folders into the VayuPress database.
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		config.Load()
		if err := dbpkg.Init(); err != nil {
			fmt.Fprintln(os.Stderr, "DB init failed:", err)
			os.Exit(1)
		}
		if err := runMigrate(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "migrate:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// backup / restore subcommands: operator-only encrypted backups (see
	// internal/backup and cmd/vayupress/backup_cli.go).
	if len(os.Args) > 1 && (os.Args[1] == "backup" || os.Args[1] == "restore") {
		config.Load()
		if err := runBackupCLI(os.Args[1], os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, os.Args[1]+":", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	logging.LogInfo("main", fmt.Sprintf("VayuPress v%s starting — P1–P26 active", Version))
	config.Load()
	logging.LogInfo("main", fmt.Sprintf("domain=%s port=%s workers=%d config_version=%s maintenance=%v",
		config.Cfg.Domain, config.Cfg.Port, config.Cfg.WorkerCount, config.ConfigVersion, config.Cfg.MaintenanceMode))

	// Initialise App — the single owner of all mutable runtime state (ADR-0046).
	a := &App{
		policy:         bluemonday.UGCPolicy(),
		outboundClient: &http.Client{Timeout: 5 * time.Second, Transport: safeOutboundTransport()},
		pluginRegistry: plugins.NewRegistry(),
		eventBus:       events.NewBus(),
	}
	a.pluginManager = plugins.New(a.pluginRegistry)

	auth.InitCSRFSecret()
	initPprofMux()
	auth.StartBucketSweeper(context.Background())

	staticDir := config.EnvOr("STATIC_DIR", "/var/www/vayupress/static")
	// Refresh the admin CSS/JS that ship inside this binary into STATIC_DIR
	// BEFORE render.Init (which writes the authoritative minified public-site
	// CSS). This makes a one-click self-update — which replaces only the binary —
	// also update every admin asset, with no separate file-copy step (ADR-0099).
	syncEmbeddedStatic(staticDir)
	render.Init(staticDir)

	docsDir := config.EnvOr("VAYU_DOCS_DIR", "/var/www/vayupress/docs")
	os.MkdirAll(docsDir, 0755)
	// ADRs are shipped as canonical files under docs/adr and synced to the docs
	// location by the deploy script; the registry reads them straight from disk.
	// (We no longer write bootstrap stub ADRs here — they produced duplicate ADR
	// numbers alongside the canonical files and polluted the registry.)

	if os.Getenv("VAYU_PLUGINS_ENABLED") == "true" {
		a.pluginManager.Start(plugins.DefaultPoolSize, plugins.DefaultQueueDepth)
	}

	// Pending database restore (staged by a VayuOS backup import). This MUST run
	// before the database is opened: it atomically swaps a validated snapshot
	// over the live DB (taking a safety backup of the current file first), so the
	// restore is crash-safe and completes on the very next start.
	if restored, err := update.ApplyPendingRestore(config.Cfg.DBPath, config.Cfg.CacheDir+"/update-backups"); err != nil {
		logging.LogError("main", "pending restore failed", err.Error())
	} else if restored {
		logging.LogInfo("main", "database restore applied from staged snapshot")
	}

	if err := dbpkg.Init(); err != nil {
		logging.LogError("main", "DB init failed", err.Error())
		os.Exit(1)
	}
	logging.LogInfo("main", "database ready — WAL adaptive + migrations + checksum drift verified (ADR-0033/0034)")

	// Governance budget actuation (Ω12) — OFF by default. Only when an operator
	// explicitly sets GOVERNANCE_ACTUATION=true does an exhausted budget drive an
	// automatic mode escalation; otherwise budgets remain recommend-only.
	if config.Cfg.GovernanceActuation {
		budget.GlobalActuator.SetEnabled(true)
		logging.LogJSON(logging.LogFields{
			Level: "warn", Component: "budget-actuator", Severity: "notice",
			Msg: "governance budget actuation ENABLED — exhausted budgets will drive automatic mode escalation",
		})
	} else {
		logging.LogInfo("budget-actuator", "governance budget actuation disabled (recommend-only) — set GOVERNANCE_ACTUATION=true to enable")
	}

	// Site settings store — warm cache and push initial values into the render pipeline.
	a.siteSettings = settings.New(dbpkg.DB)
	// API key management (migration 041/042): VayuPress's own rotatable bearer
	// tokens plus encrypted-at-rest third-party service credentials.
	//
	// The credential store uses envelope encryption: a persistent random DEK
	// (in the secret_keyring table) protects every secret, so rotating the API
	// key never makes a stored secret undecryptable — rotation is 100%
	// automated, with nothing to re-enter. The DEK is, by default, self-managed;
	// if VAYU_SECRET is set it additionally wraps the DEK for defence-in-depth.
	// Note this is intentionally NOT config.Cfg.APIKey, which the operator may
	// rotate freely.
	a.apiKeys = apikeys.New(dbpkg.DB)
	a.oauth = oauth.New(dbpkg.DB)
	a.secrets = secrets.New(dbpkg.DB, []byte(config.EnvOr("VAYU_SECRET", "")), secretKEKFilePath())
	auth.SetExtraAPIKeyVerifier(a.apiKeys.Verify)
	// Rich resolver (ADR-0134): lets the auth layer stamp each key's grant set
	// into the request context so the permission middleware can enforce
	// section:action capabilities per route.
	auth.SetExtraAPIKeyResolver(a.apiKeys.Resolve)
	// Auto-provision the internal/system key. Internal automation reads it live
	// via a.InternalAPIKey(), so a rotation propagates with no manual step.
	if err := a.apiKeys.EnsureInternal(context.Background()); err != nil {
		logging.LogError("apikeys", "failed to provision internal system key", err.Error())
	}
	if sv, err := a.siteSettings.GetAll(context.Background(), settings.ForPrimary()); err == nil {
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
	}

	// VayuDomains registry (migration 059) — seed the primary domain from the
	// configured host so an existing single-domain install is described exactly
	// as it already runs (byte-identical). site_type tracks the live site.mode.
	a.domains = domain.New(dbpkg.DB, dbpkg.RDB)
	if host := strings.TrimSpace(config.Cfg.Domain); host != "" && host != "localhost" {
		// The raw site.mode string is the site_type vocabulary; EnsurePrimary
		// coerces the empty/blog case to "blog" itself.
		siteMode := strings.TrimSpace(a.siteSettings.Get(context.Background(), settings.ForPrimary(), settings.KeySiteMode))
		if err := a.domains.EnsurePrimary(context.Background(), host, siteMode); err != nil {
			logging.LogError("domains", "seed primary domain", err.Error())
		} else {
			logging.LogInfo("domains", "primary domain registered: "+host)
		}
	}

	// Load persisted design-token theme into the render pipeline.
	if tok, err := theme.Load(context.Background(), dbpkg.DB); err == nil {
		if css, err := theme.CompileCSS(tok); err == nil {
			render.SetThemeCSS(css)
		}
	}

	// Plugin feature stores — wired after DB is confirmed ready.
	a.commentStore = comments.New(dbpkg.DB)
	a.versionStore = versions.New(dbpkg.DB)
	a.collectionStore = collections.New(dbpkg.DB)
	a.newsletterStore = newsletter.New(dbpkg.DB)
	a.webmentionStore = webmention.New(dbpkg.DB)
	if rdMgr, err := redirects.New(dbpkg.DB); err != nil {
		logging.LogError("main", "redirect manager init", err.Error())
	} else {
		a.redirectMgr = rdMgr
	}
	previewSecret := config.EnvOr("VAYU_SECRET", config.EnvOr("VAYU_API_KEY", ""))
	a.previewSigner = preview.New(previewSecret)
	a.updateStore = update.New(dbpkg.DB)

	// Email delivery (Tier 1) — sovereign SMTP, no-op when unconfigured.
	a.mailer = email.New(email.Config{
		Host:     config.Cfg.SMTPHost,
		Port:     config.Cfg.SMTPPort,
		Username: config.Cfg.SMTPUsername,
		Password: config.Cfg.SMTPPassword,
		From:     config.Cfg.SMTPFrom,
		TLS:      email.TLSMode(config.Cfg.SMTPTLS),
	})
	if a.mailer.Enabled() {
		logging.LogInfo("email", "SMTP delivery configured — host="+config.Cfg.SMTPHost)
	} else {
		// No external SMTP: fall back to the built-in VayuMail engine so
		// transactional mail (sign-in links, welcome, newsletter confirmations)
		// still sends on a sovereign single-binary deployment. The closure reads
		// a.vayuMail lazily at send time (it is wired later in boot).
		a.mailer.SetFallback(a.sendViaVayuMail)
		logging.LogInfo("email", "SMTP not configured — transactional mail will be delivered via the built-in VayuMail engine when DOMAIN is set")
	}

	// Scheduled publishing (Tier 1).
	a.scheduler = scheduler.New(dbpkg.DB)

	// Announce the install's world (ADR-0141). Tor/anonymous mode suppresses every
	// clearnet callback (IndexNow, social auto-post, Cloudflare purge, …) and arms
	// the central safefetch egress kill-switch, so EVERY server-side outbound fetch
	// (webhooks, remote-image import, embed unfurl, and any future caller) fails
	// closed rather than dialing a clearnet host from the onion server's real IP.
	safefetch.SetBlockClearnetEgress(config.Cfg.OnionMode)
	if config.Cfg.OnionMode {
		// Belt-and-suspenders: make the PROCESS-WIDE default HTTP transport refuse
		// clearnet too, so even a caller that bypasses safefetch (http.DefaultClient
		// or a third-party library) cannot leak the onion server's real IP.
		http.DefaultTransport = safefetch.GuardedDefaultTransport()
		// Opt-in: route outbound over Tor instead of blocking (ADR-0143). No-op
		// unless VAYUTOR_ROUTE_EGRESS + VAYUOS_TOR_SOCKS_ADDR are set; fail-safe.
		configureTorEgressRouting()
		logging.LogInfo("vayuos", "VAYUOS_MODE=tor — anonymous Tor Space: clearnet callbacks disabled")
		checks := anonaudit.Run(anonAuditInputs())
		pass, warn, fail := anonaudit.Summary(checks)
		logging.LogInfo("anonymity", fmt.Sprintf("Tor Space anonymity self-audit: %d protected, %d to review, %d at risk (see /os/spaces)", pass, warn, fail))
		for _, c := range checks {
			if c.Status == anonaudit.Fail {
				logging.LogError("anonymity", "anonymity control AT RISK: "+c.Title, c.Detail)
			}
		}
	}

	// Privacy-first analytics + outbound webhooks + social posting (Tier 2).
	a.analytics = analytics.New(dbpkg.DB)
	// Route the admin Analytics panel's heavy aggregate reads at the WAL read
	// pool so they never serialise behind the pageview write stream on the single
	// writer connection (which made the Analytics tab 502). Writes stay on the
	// writer; WAL preserves read-your-writes.
	// The admin Analytics panel reads run on the DEDICATED admin pool so they are
	// isolated from public/bot read load. (The only public consumer, the trending
	// widget, is memoised ~24h and single-flighted, so it borrows this pool at
	// most once a day — negligible.)
	a.analytics.UseReader(dbpkg.AdminReader())
	// Every host this install answers for, so referrer lists exclude internal
	// navigation on ALL of them and not only the primary. Without this a hosted
	// domain's own hostname sits at the top of the operator's referrer list,
	// counted as an external site referring traffic to itself.
	a.analytics.UseSelfHosts(a.registeredHosts)
	// Start the view-count flusher. Without it every view is buffered and never
	// written, so this line is pinned by a test: a recorder that counts into a
	// buffer nobody drains is the same defect as a setting nobody reads.
	a.analytics.StartCollector(context.Background())
	// Start the /collect batch flusher. Without it every collected beacon is
	// buffered and never written — same pinned-defect class as above.
	a.analytics.StartEventCollector(context.Background())
	// Weekly analytics digest (2025 plan Wave 4): opt-in via VAYU_REPORT_EMAIL;
	// disabled silently when unset.
	a.startScheduledReports(context.Background())
	// Daily rollup ladder (2025 plan Wave 4): rebuild yesterday+today every 6h
	// so long-range uniques merge sketches instead of scanning raw pageviews.
	a.analytics.StartRollupLadder(context.Background(), 6*time.Hour)
	a.webhooks = webhooks.New(dbpkg.DB, a.outboundClient)
	a.social = social.New(social.MastodonConfig{
		Instance: config.Cfg.MastodonInstance,
		Token:    config.Cfg.MastodonToken,
	}, a.outboundClient)
	if a.social.Enabled() {
		logging.LogInfo("social", "auto-posting enabled — mastodon="+config.Cfg.MastodonInstance)
	}
	a.aiAssist = aiassist.New(aiassist.Config{URL: config.Cfg.AIURL, Model: config.Cfg.AIModel}, a.outboundClient)
	if a.aiAssist.Enabled() {
		logging.LogInfo("ai", "writing assistant enabled — url="+config.Cfg.AIURL+" model="+a.aiAssist.Model())
	}

	// Reader memberships & paywalls (Tier 2).
	a.members = members.New(dbpkg.DB)
	// Monetization (Tier 5): order ledger + advertising slots. Stores are always
	// wired; the public surfaces stay dark until the operator enables the
	// feature flags (feature.payments / feature.ads) in Tools & Plugins.
	a.payments = payments.New(dbpkg.DB)
	a.ads = ads.New(dbpkg.DB)
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-queue.DoneCh:
				return
			case <-ticker.C:
				if n, err := a.members.PurgeExpired(context.Background()); err == nil && n > 0 {
					logging.LogInfo("members", fmt.Sprintf("purged %d expired member tokens/sessions", n))
				}
				// Entitlement expiry (audit): a paid period that ended with no
				// renewal must end the entitlement, whatever gateway took the
				// payment — Stripe webhooks renew themselves, PayPal/direct/
				// generic orders never did until this sweep existed. A failed
				// sweep must be LOUD: silence here hides a paid-entitlement
				// divergence behind a healthy-looking log.
				if n, err := a.members.ExpireLapsedSubscriptions(context.Background()); err != nil {
					logging.LogError("members", "lapsed-subscription sweep failed; lapsed subscriptions stay active until the next tick", err.Error())
				} else if n > 0 {
					logging.LogInfo("members", fmt.Sprintf("expired %d lapsed subscription(s) past their paid period", n))
				}
			}
		}
	}()
	// Self-healing disk hygiene: prune the timestamped SQLite snapshots the shell
	// update path drops next to the live DB (and their orphaned journals), keeping
	// only the newest few. Runs once at boot so an already-cluttered box is tidied
	// immediately, then daily. Never touches the live DB or its WAL/SHM/journal.
	if removed, reclaimed := update.SweepDBBackupsDefault(config.Cfg.DBPath); removed > 0 {
		logging.LogInfo("update", fmt.Sprintf("pruned %d stale DB backup file(s), reclaimed %d MiB", removed, reclaimed/(1<<20)))
	}
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-queue.DoneCh:
				return
			case <-ticker.C:
				if n, err := a.analytics.Purge(context.Background(), config.Cfg.AnalyticsRetainDays); err == nil && n > 0 {
					logging.LogInfo("analytics", fmt.Sprintf("purged %d aggregate rows older than %dd", n, config.Cfg.AnalyticsRetainDays))
				}
				// VayuAnalytics: data-minimisation sweep of detailed session/pageview rows.
				if n, err := a.analytics.PurgeOlderThan(context.Background(), config.Cfg.AnalyticsRetainDays); err == nil && n > 0 {
					logging.LogInfo("analytics", fmt.Sprintf("purged %d detailed rows older than %dd", n, config.Cfg.AnalyticsRetainDays))
				}
				// Daily DB-backup hygiene (see the boot sweep above).
				if removed, reclaimed := update.SweepDBBackupsDefault(config.Cfg.DBPath); removed > 0 {
					logging.LogInfo("update", fmt.Sprintf("pruned %d stale DB backup file(s), reclaimed %d MiB", removed, reclaimed/(1<<20)))
				}
				// VayuAPI hygiene (ADR-0134): hard-delete keys whose expiry passed
				// more than the grace window ago. Expiry itself is enforced live;
				// this only tidies long-dead rows out of the admin list.
				if a.apiKeys != nil {
					if n, err := a.apiKeys.Cleanup(context.Background()); err == nil && n > 0 {
						logging.LogInfo("apikeys", fmt.Sprintf("purged %d long-expired API key(s)", n))
					}
				}
			}
		}
	}()

	// Multi-author accounts + login sessions (Tier 1). Writes go to the single
	// writer connection, but the per-request auth reads (session validation +
	// account lookup, which run on EVERY VayuOS admin request) use the DEDICATED
	// ADMIN read pool. This is the isolation guarantee: even if the public read
	// pool is fully saturated by a bot flood or a cold-cache render storm, the
	// admin auth gate draws from its own reserved connections, so VayuOS always
	// authenticates and loads — the public side can never take the control plane
	// down with it.
	a.userStore = users.New(dbpkg.DB)
	a.userStore.UseReader(dbpkg.AdminReader())
	// TOTP seeds are second factors: seal them at rest with the service-credential
	// DEK (VAYU_SECRET / host key file wrapped — audit). Legacy plaintext rows
	// keep verifying and re-seal on their next write.
	a.userStore.UseTOTPCodec(a.secrets)
	a.sessions = auth.NewSessionStore(dbpkg.DB)
	a.sessions.UseReader(dbpkg.AdminReader())
	if n, err := a.userStore.Count(context.Background()); err == nil && n == 0 {
		a.bootstrapDefaultAdmin(context.Background())
	}
	// Backfill human-readable author handles for any pre-051 accounts so every
	// staff member has a /author/<username> URL. Idempotent + cheap.
	a.userStore.BackfillUsernames(context.Background())
	// Resolve the article byline's author name → public profile slug + avatar so
	// the byline can link to /author/<slug> with a picture. Cached per name.
	a.installAuthorResolver()
	// Periodic expired-session sweep.
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-queue.DoneCh:
				return
			case <-ticker.C:
				if n, err := a.sessions.PurgeExpired(context.Background()); err == nil && n > 0 {
					logging.LogInfo("auth", fmt.Sprintf("purged %d expired sessions", n))
				}
			}
		}
	}()

	// ── VayuOS control layer (Phase 2): Publishing · Mail · PGP ──────────────
	a.bootVayuOS()

	// ── VayuShield + VayuAnalytics Enterprise: bot protection + engagement ───
	a.bootVayuShield()
	// Replication last: it depends on the sovereign lane for its pressure signal,
	// and starting it after the shield means a slow or unreachable backup target
	// can never delay the site coming up.
	a.bootVayuKeep(context.Background())

	// Mode journal — durable SQLite-backed transition log (Ω6).
	dbPath := config.EnvOr("DB_PATH", "./vayupress.db")
	modeJournalPath := dbPath + ".modes"
	if modeJournal, past, err := mode.OpenJournal(modeJournalPath, mode.Global); err != nil {
		logging.LogJSON(logging.LogFields{Level: "warn", Component: "mode", Msg: "mode journal unavailable (non-fatal): " + err.Error()})
	} else {
		logging.LogInfo("mode", fmt.Sprintf("mode journal open — %d prior transitions loaded", len(past)))
		// Replay the persisted state (audit): a crash in read-only/quarantined
		// used to reboot into NORMAL and accept writes nobody re-authorised.
		// Restore seeds silently — no new journal row, no duplicated history.
		if len(past) > 0 {
			last := past[len(past)-1]
			mode.Global.Restore(last.To)
			logging.LogInfo("mode", fmt.Sprintf("mode restored from journal: %s (reason=%s)", last.To, last.Reason))
		}
		defer modeJournal.Close()
	}

	// Policy journal — persists evaluation runs to SQLite for the provenance inspector.
	policy.GlobalJournal = policy.NewJournal(dbpkg.DB)
	go func() {
		runPolicyEval := func() {
			report := policy.Global.EvaluateAll(policy.Context{})
			if _, err := policy.GlobalJournal.Record(report); err != nil {
				logging.LogJSON(logging.LogFields{Level: "warn", Component: "policy", Msg: "journal write failed: " + err.Error()})
			}
		}
		runPolicyEval() // seed one run immediately on start
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			runPolicyEval()
		}
	}()

	// Resource governance — limiters and watchdog (ADR-0055).
	resource.Register("articles.write", config.Cfg.WorkerCount*4)
	resource.Register("plugin.exec", config.Cfg.PluginMaxConcurrent)
	resource.Global = resource.NewWatchdog(250 * time.Millisecond)

	// Wire article service with repository pattern (ADR-0050).
	a.articles = &api.ArticleService{
		Repo:  dbpkg.NewArticleRepo(dbpkg.DB),
		Queue: queue.NewSQLiteWriter(dbpkg.DB, config.Cfg.QueueHardLimit),
		StorageCheckFn: func() (int64, int64) {
			return dbpkg.StorageUsedBytes(), dbpkg.StorageQuotaBytes()
		},
	}

	// Wire VayuFlow — the deterministic automation engine (ADR-0151).
	//
	// The content writer is VayuFlow's OWN adapter, not ArticleService: that
	// service creates articles without setting a status, and an empty status is
	// read as published. An automation capped at draft must never travel that
	// path.
	a.flowStore = vayuflow.NewStore(dbpkg.DB)
	a.flowRuns = vayuflow.NewRunStore(dbpkg.DB)
	a.flowRunner = vayuflow.NewRunner(a.flowStore, a.flowRuns, a.flowRoleResolver())
	a.flowTicker = vayuflow.NewTicker(a.flowStore, a.flowRunner, time.UTC)
	a.flowInbox = vayuflow.NewInbox(dbpkg.DB)
	a.flowDrainer = vayuflow.NewDrainer(a.flowInbox, a.flowStore, a.flowRunner)
	vayuflow.SetContentWriter(flowContent{repo: dbpkg.NewArticleRepo(dbpkg.DB)})
	vayuflow.SetModelRunner(flowModel{c: a.aiAssist})
	vayuflow.SetFetcher(flowFetcher{})
	vayuflow.SetMailSender(flowMailer{eng: a.vayuMail, from: a.transactionalFrom})
	// Runs left mid-flight by a previous process become "interrupted" — never
	// retried, because a step that already sent mail must not be replayed.
	if n, err := a.flowRuns.RecoverInterrupted(context.Background()); err != nil {
		log.Printf("vayuflow: could not recover in-flight runs: %v", err)
	} else if n > 0 {
		log.Printf("vayuflow: %d run(s) were in flight at shutdown and are marked interrupted; "+
			"retry is an operator decision", n)
	}
	// The ticker stops with the rest of the background workers, on the same
	// shutdown signal, so a draining process does not start new automations.
	flowCtx, stopFlow := context.WithCancel(context.Background())
	go func() { <-queue.DoneCh; stopFlow() }()
	go a.flowTicker.Run(flowCtx, nil)
	go a.flowDrainer.Run(flowCtx, 5*time.Second, nil)

	// Wire search service — VayuFind, the built-in dependency-free engine
	// (ADR-0050/0101). Load the index in the BACKGROUND: on a large article store
	// this full scan can take minutes, and running it synchronously here delayed
	// the HTTP listener (below) from binding — so the site returned 502 for the
	// whole load and a slow-but-healthy start looked like a crash. Search returns
	// empty until the first load completes, then serves normally and is maintained
	// incrementally by the article event handlers.
	// Read from the READ POOL, never the single writer connection. The initial
	// Load scans every published article, which on a large database takes minutes;
	// on the writer (SetMaxOpenConns(1)) that scan would monopolise the one writer
	// connection and block the main startup thread's next write (UPDATE write_jobs
	// below) — so the listener never bound and the site 502'd. The read pool has
	// several query_only connections, so the scan runs without blocking writes.
	a.search = search.NewService(dbpkg.Reader())
	searchIdxPath := filepath.Join(config.Cfg.CacheDir, "search-index.gob")
	go func() {
		start := time.Now()
		// Prefer restoring the persisted index and reconciling only what changed
		// (incremental) — a full rescan of every article runs only when there is no
		// usable snapshot (ADR-0110). Either way this is off the startup path.
		if ok, _ := a.search.LoadIndex(context.Background(), searchIdxPath); ok {
			logging.LogInfo("search", fmt.Sprintf("search index restored + reconciled (%dms)", time.Since(start).Milliseconds()))
		} else if err := a.search.Load(context.Background()); err != nil {
			logging.LogError("search", "initial index load failed (search will populate as content changes)", err.Error())
			return
		} else {
			logging.LogInfo("search", fmt.Sprintf("search index built (%dms)", time.Since(start).Milliseconds()))
		}
		// The initial Load/reconcile scans published articles into a large,
		// short-lived working set (the old map, scan buffers, decoded rows). Now
		// that the live index is in place, hand that transient memory back to the
		// OS immediately instead of waiting for a later GC to release it lazily —
		// this is the boot-time RSS spike operators saw after a restart. (L4)
		debug.FreeOSMemory()
		// Persist now (so the very next start is incremental) and refresh the
		// snapshot periodically + on shutdown; the in-memory index is kept current
		// by the article event handlers between saves.
		_ = a.search.SaveIndex(context.Background(), searchIdxPath)
		t := time.NewTicker(searchSaveInterval())
		defer t.Stop()
		for {
			select {
			case <-queue.DoneCh:
				_ = a.search.SaveIndex(context.Background(), searchIdxPath)
				return
			case <-t.C:
				_ = a.search.SaveIndex(context.Background(), searchIdxPath)
			}
		}
	}()
	// Honour the operator's Search toggle (Tools & Plugins). Default ON; when
	// off, search returns no results and the public box/modal are hidden.
	if a.siteSettings != nil {
		searchOn := a.siteSettings.FeatureEnabled(context.Background(), settings.ForPrimary(), settings.KeyFeatureSearch)
		search.SetEnabled(searchOn)
		// The public search box/modal visibility tracks the same toggle.
		render.SetSearchEnabled(searchOn)
		// Blog base path: "/blog" in business_subpath mode (website at "/"),
		// "/" otherwise. Governs blog canonical/pagination/nav URLs.
		render.SetBlogBase(blogBaseForMode(strings.TrimSpace(a.siteSettings.Get(context.Background(), settings.ForPrimary(), settings.KeySiteMode))))
	}

	// Tier 4 services: GraphQL, live collaboration stream, email templates, i18n.
	a.initGraphQL()
	a.collab = ws.New(64)
	a.emailTmpl = emailtmpl.New()
	a.i18n = i18n.New()
	a.loadEmailTemplateOverrides()
	a.loadI18nFromDB()

	if n, err := dbpkg.DB.Exec(`UPDATE write_jobs SET status='pending' WHERE status='processing'`); err == nil {
		if rows, _ := n.RowsAffected(); rows > 0 {
			logging.LogInfo("main", fmt.Sprintf("recovered %d stale processing jobs", rows))
		}
	}

	dbpkg.InitStorageCachedBytes()
	// Background footprint sizing for the Storage & System page — keeps the
	// multi-GB render-cache tree walk off the request path (Storage page was
	// blocking for 4-8s per load, inflating the HTTP p95).
	startFootprintRefresher(config.Cfg.CacheDir, config.Cfg.MediaDir, updateBackupDir())
	dbpkg.StartWALCheckpointGoroutine(queue.DoneCh)
	dbpkg.StartStuckJobReaper(queue.DoneCh)
	dbpkg.StartJobRetentionSweeper(queue.DoneCh)
	dbpkg.StartArticleTagsBackfill(queue.DoneCh)
	dbpkg.StartIndexSelfCheck(queue.DoneCh)
	a.startMetricsSnapshotCollector()
	a.startDashboardWarmer(queue.DoneCh)
	a.startSearchReconciler(queue.DoneCh)
	a.startScheduler(queue.DoneCh)
	a.startUpdateWatcher(queue.DoneCh)
	a.startCacheWarmer(queue.DoneCh)

	// Wire queue injections.
	queue.RenderFn = render.RenderArticle
	queue.SetCacheWriteFn(func(relPath, content string) {
		render.CacheWrite(relPath, content) //nolint:errcheck
	})
	queue.EventBus = a.eventBus

	// Register domain event handlers after all services are wired (ADR-0050).
	a.registerEventHandlers()

	// Wire health package injections.
	health.Version = Version
	health.ConfigVersion = config.ConfigVersion
	health.BootTime = bootTime
	health.SearchPingFn = func(_, _ string, _ interface{}) error {
		return a.search.Ping(context.Background())
	}
	health.WriteJSON = writeJSON
	health.WriteAPIError = writeAPIError
	// Recon gate (audit): health detail answers loopback peers or API-key
	// holders only; anonymous probes get the bare status shape.
	health.TrustedProbeFn = func(r *http.Request) bool {
		return isLoopbackPeer(r) || auth.HasValidAPIKey(r)
	}

	// Wire render package version.
	render.Version = Version

	// Drop stale pre-rendered public HTML when the renderer changed (new release,
	// edited templates, or restyled cards) so a redeploy always serves the
	// current design instead of a cached older home/tag page.
	render.ReconcileCacheVersion()

	// Background cache warm + feed/sitemap generation. Deliberately gentle: it
	// waits a few seconds for the box to settle after boot, then paces itself
	// (render.WarmCache throttles per article) so re-rendering the public cache
	// after a deploy never saturates a small VPS. Set VAYU_WARM_ON_BOOT=0 to skip
	// it entirely (public pages then render lazily on first request). Tune the
	// settle delay with VAYU_WARM_DELAY_SEC and the per-article pace with
	// VAYU_WARM_THROTTLE_MS.
	go func() {
		if config.EnvOr("VAYU_WARM_ON_BOOT", "1") == "0" {
			logging.LogInfo("cache-warm", "skipped on boot (VAYU_WARM_ON_BOOT=0)")
			return
		}
		select {
		case <-queue.DoneCh:
			return
		case <-time.After(warmStartupDelay()):
		}
		logging.LogInfo("cache-warm", "starting (throttled)...")
		render.WarmCache(api.SplitTags)
		generateSitemap()
		generateRSS()
		generateRobots()
		logging.LogInfo("cache-warm", "complete")
	}()

	// Lifecycle manager — ordered startup and shutdown (ADR-0051).
	lc := lifecycle.New()
	lc.Register("queue-workers", func(_ context.Context) error {
		queue.StartWorkerPool(&metrics.WorkerWg)
		logging.LogInfo("main", fmt.Sprintf("started %d write workers (maintenance_mode=%v)", config.Cfg.WorkerCount, config.Cfg.MaintenanceMode))
		return nil
	}, nil)

	// Outbox relay — dispatches events written atomically with article mutations (ADR-0051/0052/0053).
	outboxRelay := outbox.NewRelay(dbpkg.DB, func(ctx context.Context, _ string, payload []byte) error {
		var env events.Envelope
		if err := json.Unmarshal(payload, &env); err != nil {
			fault.GlobalEscalator.Record(fault.FaultOutboxCommit)
			return err
		}
		// Thread correlation through dispatch context for downstream log correlation.
		ctx = trace.WithCorrelationID(ctx, env.CorrelationID)
		ctx = trace.WithCausationID(ctx, env.CausationID)
		ctx, dispatchSpan := trace.Start(ctx, "outbox.dispatch."+env.EventType)
		dispatchSpan.SetAttribute("event_id", env.EventID)
		dispatchSpan.SetAttribute("event_type", env.EventType)
		dispatchSpan.SetAttribute("causation_id", env.CausationID)
		logging.LogJSON(logging.LogFields{
			Level: "info", Component: "outbox",
			CorrelationID: env.CorrelationID,
			CausationID:   env.CausationID,
			Msg:           "dispatching " + env.EventType + " event_id=" + env.EventID,
		})
		switch env.EventType {
		case "article.created.v1":
			var ev events.ArticleCreated
			if err := json.Unmarshal(env.Payload, &ev); err != nil {
				return err
			}
			a.eventBus.Publish(ctx, ev)
			// Durably record the trigger for VayuFlow. This is deliberately NOT
			// a bus subscription: Publish recovers handler panics and returns
			// nothing, so a subscriber that failed would be invisible and the
			// outbox would mark this row delivered anyway — durable up to the
			// last link and lossy at it. Returning the error here keeps the row
			// pending so it is retried.
			if err := a.flowInboxAppend(ctx, vayuflow.EventArticleCreated, env.EventID,
				vayuflow.Subject{Slug: ev.Slug, Tags: ev.Tags}); err != nil {
				return err
			}
		case "article.updated.v1":
			var ev events.ArticleUpdated
			if err := json.Unmarshal(env.Payload, &ev); err != nil {
				return err
			}
			a.eventBus.Publish(ctx, ev)
			if err := a.flowInboxAppend(ctx, vayuflow.EventArticleUpdated, env.EventID,
				vayuflow.Subject{Slug: ev.Slug, Tags: ev.Tags}); err != nil {
				return err
			}
		case "article.deleted.v1":
			var ev events.ArticleDeleted
			if err := json.Unmarshal(env.Payload, &ev); err != nil {
				return err
			}
			a.eventBus.Publish(ctx, ev)
			if err := a.flowInboxAppend(ctx, vayuflow.EventArticleDeleted, env.EventID,
				vayuflow.Subject{Slug: ev.Slug}); err != nil {
				return err
			}
		case "cache.invalidated.v1":
			var ev events.CacheInvalidated
			if err := json.Unmarshal(env.Payload, &ev); err != nil {
				return err
			}
			a.eventBus.Publish(ctx, ev)
		default:
			logging.LogJSON(logging.LogFields{Level: "warn", Component: "outbox", CorrelationID: env.CorrelationID, Msg: "unknown event type: " + env.EventType})
		}
		dispatchSpan.End()
		return nil
	}, queue.DoneCh)
	lc.Register("outbox-relay", func(_ context.Context) error {
		outboxRelay.Start()
		logging.LogInfo("main", "outbox relay started")
		return nil
	}, nil)

	if err := lc.Start(context.Background()); err != nil {
		logging.LogError("main", "lifecycle start failed", err.Error())
		os.Exit(1)
	}

	logging.LogInfo("main", fmt.Sprintf("startup complete in %dms", time.Since(bootTime).Milliseconds()))

	r := chi.NewRouter()
	a.registerRoutes(r, staticDir)
	// Hand the assembled chain to the diagnostics, so "what does this domain
	// serve" is answered by the real router rather than by a second
	// implementation that can only ever agree with itself.
	a.setRootHandler(r)

	srv := &http.Server{
		Addr:        onionSafeBindAddr(config.Cfg.Port, config.Cfg.OnionMode),
		Handler:     r,
		ReadTimeout: 15 * time.Second,
		// ReadHeaderTimeout bounds how long a client may take to send the request
		// headers. Without it a slow-loris client can hold a connection (and a
		// server goroutine) open indefinitely during the header phase, starving
		// legitimate requests and inflating tail latency. 10s is generous for a
		// real client on a bad network yet closes the slow-loris vector.
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// Reject oversized header floods (a cheap DoS) before they allocate.
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logging.LogInfo("main", fmt.Sprintf("received %v — graceful shutdown", sig))

		// Phase 1: stop ingress
		httpCtx, httpCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer httpCancel()
		if err := srv.Shutdown(httpCtx); err != nil {
			logging.LogError("main", "HTTP shutdown", err.Error())
		}
		logging.LogInfo("main", "phase 1 complete — ingress stopped")

		// Phase 2: drain write queue (45s)
		close(queue.DoneCh)
		drainDone := make(chan struct{})
		go func() { metrics.WorkerWg.Wait(); close(drainDone) }()
		select {
		case <-drainDone:
			logging.LogInfo("main", "phase 2 complete — write queue drained")
		case <-time.After(45 * time.Second):
			logging.LogJSON(logging.LogFields{Level: "warn", Component: "main", Msg: "phase 2 timeout (45s) — in-flight jobs retried on next startup"})
		}

		// Phase 3: stop plugin pool + subprocess pools + resource watchdog
		if os.Getenv("VAYU_PLUGINS_ENABLED") == "true" {
			a.pluginManager.Shutdown()
			plugins.ShutdownSubprocesses()
		}
		// Close the opt-in SIEM CEF sink last-written state (nil when disabled).
		if a.siemSink != nil {
			_ = a.siemSink.Close()
		}
		// Tear down onion services (their lifetime is bound to VayuPress) and
		// flush the aggregate visit counter to the DB before it closes.
		if a.vayuTor != nil {
			_ = a.vayuTor.Stop(context.Background())
		}
		// Drain the Anonymous Tor Space child (ADR-0141): it is a detached process
		// the OS does not kill when the parent exits, so signal it to close its
		// listener and WAL-checkpoint its own SQLite. Shutdown() also latches the
		// supervisor off so a stray reconcile tick can't respawn it mid-shutdown.
		if a.torSpace != nil {
			a.torSpace.Shutdown()
		}
		if resource.Global != nil {
			resource.Global.Stop()
		}
		logging.LogInfo("main", "phase 3 complete — plugin pool + watchdog stopped")

		// Phase 4: WAL checkpoint before close
		if dbpkg.DB != nil {
			if _, err := dbpkg.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
				logging.LogError("main", "WAL checkpoint on shutdown", err.Error())
				fault.GlobalEscalator.Record(fault.FaultWALWrite)
			} else {
				logging.LogInfo("main", "phase 4 complete — WAL checkpointed")
			}
		}

		// Phase 5: flush final metrics snapshot
		a.collectAdminMetrics()
		logging.LogInfo("main", "phase 5 complete — metrics flushed")

		// Phase 6: close database
		if dbpkg.DB != nil {
			if err := dbpkg.DB.Close(); err != nil {
				logging.LogError("main", "DB close", err.Error())
			} else {
				logging.LogInfo("main", "phase 6 complete — database closed")
			}
		}

		logging.LogInfo("main", "shutdown complete — goodbye")
		os.Exit(0)
	}()

	// Serve on an inherited socket when systemd passed one, otherwise bind as
	// this service always has (ADR-0155 P5). An install without the socket unit
	// takes the identical path it took before this existed.
	ln, how, err := serveListener(srv.Addr, config.Cfg.OnionMode)
	if err != nil {
		logging.LogError("main", "listen failed", err.Error())
		os.Exit(1)
	}
	// Record what this boot cost, now that the listener is known — the answer
	// differs depending on whether it queues or refuses, and an operator reading
	// the panel needs the number WITH that context (ADR-0155 P4). After the
	// service is serving, never before: a diagnostic that can delay a start is
	// worse than no diagnostic.
	if a.siteSettings != nil {
		go recordStartupCost(context.Background(), a.siteSettings, time.Since(bootTime))
	}
	// Watch the single write connection for contention. SQLite has one writer, so
	// anything holding it makes every other writer queue — and until this existed
	// there was no way, from inside the product, to see that queue or to know it
	// had happened. It samples DBStats and takes no connection of its own, which
	// is what lets it answer during the incident it describes.
	dbpkg.StartStallWatch(nil)
	logging.LogInfo("main", fmt.Sprintf("listening on :%s (v%s) — %s", config.Cfg.Port, Version, how))
	if err := srv.Serve(ln); err != http.ErrServerClosed {
		logging.LogError("main", "Serve error", err.Error())
		os.Exit(1)
	}
}
