// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/microcosm-cc/bluemonday"

	"github.com/johalputt/vayupress/internal/ads"
	"github.com/johalputt/vayupress/internal/aiassist"
	"github.com/johalputt/vayupress/internal/analytics"
	"github.com/johalputt/vayupress/internal/api"
	"github.com/johalputt/vayupress/internal/apikeys"
	"github.com/johalputt/vayupress/internal/auth"
	"github.com/johalputt/vayupress/internal/collections"
	"github.com/johalputt/vayupress/internal/comments"
	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/domain"
	"github.com/johalputt/vayupress/internal/email"
	"github.com/johalputt/vayupress/internal/emailtmpl"
	"github.com/johalputt/vayupress/internal/events"
	"github.com/johalputt/vayupress/internal/graphqlapi"
	"github.com/johalputt/vayupress/internal/i18n"
	"github.com/johalputt/vayupress/internal/logging"
	"github.com/johalputt/vayupress/internal/members"
	"github.com/johalputt/vayupress/internal/metrics"
	"github.com/johalputt/vayupress/internal/mode"
	"github.com/johalputt/vayupress/internal/newsletter"
	"github.com/johalputt/vayupress/internal/oauth"
	"github.com/johalputt/vayupress/internal/payments"
	"github.com/johalputt/vayupress/internal/plugins"
	"github.com/johalputt/vayupress/internal/preview"
	"github.com/johalputt/vayupress/internal/queue"
	"github.com/johalputt/vayupress/internal/redirects"
	"github.com/johalputt/vayupress/internal/render"
	"github.com/johalputt/vayupress/internal/safefetch"
	"github.com/johalputt/vayupress/internal/scheduler"
	"github.com/johalputt/vayupress/internal/search"
	"github.com/johalputt/vayupress/internal/secrets"
	"github.com/johalputt/vayupress/internal/settings"
	"github.com/johalputt/vayupress/internal/siemsink"
	"github.com/johalputt/vayupress/internal/social"
	"github.com/johalputt/vayupress/internal/update"
	"github.com/johalputt/vayupress/internal/users"
	vasession "github.com/johalputt/vayupress/internal/vayuanalytics/session"
	vastore "github.com/johalputt/vayupress/internal/vayuanalytics/store"
	"github.com/johalputt/vayupress/internal/vayuflow"
	"github.com/johalputt/vayupress/internal/vayukeep"
	vkernel "github.com/johalputt/vayupress/internal/vayuos/kernel"
	vmail "github.com/johalputt/vayupress/internal/vayuos/mail"
	vpgp "github.com/johalputt/vayupress/internal/vayuos/pgp"
	"github.com/johalputt/vayupress/internal/vayuos/secwatch"
	"github.com/johalputt/vayupress/internal/vayuos/torspace"
	vtalk "github.com/johalputt/vayupress/internal/vayuos/vayutalk"
	vtor "github.com/johalputt/vayupress/internal/vayuos/vayutor"
	"github.com/johalputt/vayupress/internal/vayushield"
	"github.com/johalputt/vayupress/internal/vayushield/intel"
	"github.com/johalputt/vayupress/internal/vayushield/offload"
	"github.com/johalputt/vayupress/internal/vayushield/sovereign"
	"github.com/johalputt/vayupress/internal/vayushield/verifiedbot"
	"github.com/johalputt/vayupress/internal/versions"
	"github.com/johalputt/vayupress/internal/webhooks"
	"github.com/johalputt/vayupress/internal/webmention"
	"github.com/johalputt/vayupress/internal/ws"
)

// App holds all mutable runtime state. Handlers are methods on *App so that
// they depend on explicit fields rather than package-level globals (ADR-0046).
type App struct {
	// HTTP
	outboundClient *http.Client

	// bgWG tracks fire-and-forget background goroutines this App launched
	// (currently the async IndexNow announcement). Tests drain it in cleanup so
	// a goroutine never outlives the test that spawned it — under -race a
	// survivor reading config globals while the NEXT test's harness reloads
	// them is a data race, not a style problem.
	bgWG sync.WaitGroup

	// siemSink holds the opt-in CEF export file (VAYU_SIEM_FILE) so graceful
	// shutdown can close it; nil when the operator did not opt in.
	siemSink *siemsink.Sink

	// router is the fully-assembled request handler, kept so the console and the
	// connector can replay a request for a hosted domain and report what a
	// visitor actually gets (site_preview.go). Nothing serves traffic from here —
	// it is the same handler the listener uses, stored so a diagnostic can ask
	// the real chain instead of reimplementing it and agreeing with itself.
	routerHandler atomic.Value // http.Handler

	// Sanitization
	policy *bluemonday.Policy

	// Article business logic
	articles *api.ArticleService

	// Search service (VayuFind — built-in, dependency-free)
	search search.Service

	// Domain event bus
	eventBus *events.Bus

	// Plugin subsystem
	pluginRegistry *plugins.Registry
	pluginManager  *plugins.Manager

	// Vacuum lifecycle
	vacuumMu      sync.Mutex
	vacuumLastRun time.Time

	// Smoke test
	smokeTestMutex sync.Mutex

	// Admin metrics snapshot cache
	metricsSnapshot atomic.Value

	// Benchmark state
	lastBenchmark    *benchmarkResult
	lastBenchmarkMu  sync.Mutex
	benchmarkRunning int32

	// Search reindex state (Ω-search reconciler)
	reindexRunning int32
	lastReindex    *reindexResult
	lastReindexMu  sync.Mutex

	// Site/theme settings store (migration 006)
	siteSettings *settings.Store

	// VayuDomains registry (migration 059) — the multi-domain host registry.
	// Stage 1: seeded with the primary domain and used for host resolution.
	domains *domain.Registry

	// API key management (migration 041): VayuPress's own rotatable bearer
	// tokens, plus encrypted-at-rest third-party service credentials.
	apiKeys *apikeys.Store
	secrets *secrets.Store

	// Resolved IndexNow key, cached. Resolving it means a SQL row read plus an
	// AES-GCM open, and three hot paths need it on unauthenticated requests (the
	// root key-file shortcut in handleArticlePage, the key-file handler, and the
	// shield/L0 bypass predicates). Doing that work per request put a decrypt on
	// every article view; the cache turns it into one atomic load. Invalidated
	// explicitly on every credential mutation, with a short TTL as the backstop
	// for an out-of-band change.
	indexNowKeyCache atomic.Pointer[indexNowKeyEntry]

	// OAuth 2.1 authorization server (migration 066, ADR-0140) — the one-click
	// "Connect" flow on claude.ai. Access tokens are scoped apikeys, so this only
	// holds clients, PKCE codes, and refresh tokens.
	oauth *oauth.Store

	// Plugin stores (wired at startup when DB is ready)
	commentStore    *comments.Store
	versionStore    *versions.Store
	collectionStore *collections.Store
	newsletterStore *newsletter.Store
	webmentionStore *webmention.Store
	redirectMgr     *redirects.Manager
	previewSigner   *preview.Signer
	updateStore     *update.Store

	// Email delivery (Tier 1) — no-op when SMTP is unconfigured.
	mailer *email.Sender

	// Scheduled publishing (Tier 1).
	scheduler *scheduler.Store

	// Multi-author accounts + login sessions (Tier 1).
	userStore *users.Store

	// VayuFlow — the deterministic automation engine (ADR-0151). Nil when the
	// engine could not be constructed; the panel says so rather than pretending
	// flows are armed.
	flowStore   *vayuflow.Store
	flowRuns    *vayuflow.RunStore
	flowRunner  *vayuflow.Runner
	flowTicker  *vayuflow.Ticker
	flowInbox   *vayuflow.Inbox
	flowDrainer *vayuflow.Drainer
	sessions    *auth.SessionStore

	// Privacy-first analytics (Tier 2).
	analytics *analytics.Store

	// Outbound webhooks (Tier 2).
	webhooks *webhooks.Store

	// Social auto-posting (Tier 2).
	social *social.Poster

	// AI writing assistant — local Ollama, opt-in (Tier 2).
	aiAssist *aiassist.Client

	// Reader memberships & paywalls (Tier 2).
	members *members.Store

	// Monetization (Tier 5): sovereign payment order ledger + gateway registry,
	// and the activation-gated advertising surface. Both are off by default and
	// only act once the operator enables the corresponding module.
	payments *payments.Store
	ads      *ads.Store

	// Read-only public GraphQL API (Tier 4).
	graphql *graphqlapi.Service
	// Real-time collaboration / live admin event stream (Tier 4).
	collab *ws.Hub
	// Operator-customisable email templates (Tier 4).
	emailTmpl *emailtmpl.Store
	// UI/content internationalisation (Tier 4).
	i18n *i18n.Catalog

	// VayuKeep — automatic encrypted replication (ADR-0145). nil when the
	// subsystem refused to start; vayuKeepErr then carries the reason, which the
	// operations page surfaces rather than showing an absent-and-therefore-fine
	// panel.
	vayuKeep    *vayukeep.Engine
	vayuKeepErr string
	keepSup     keepSupervisor

	// VayuOS — native control layer (Phase 2): mail sovereignty + PGP privacy.
	vayuKernel *vkernel.Bus
	vayuHealth *vkernel.HealthMonitor
	vayuPGP    *vpgp.Engine
	vayuMail   *vmail.Engine
	vayuTalk   *vtalk.Engine
	vayuTor    *vtor.Engine
	torSpace   *torspace.Supervisor // Anonymous Tor Space child supervisor (ADR-0141); nil in a child
	vayuSec    *secwatch.Watcher

	// avatarCache memoises the set of mailbox addresses that have an uploaded
	// profile picture, so rendering a mailbox/message list shows photos without
	// issuing one avatar-presence query per row. Refreshed on a short TTL and
	// invalidated immediately on upload/remove.
	avatarCache mailAvatarSet

	// VayuShield + VayuAnalytics Enterprise — sovereign bot protection and
	// cookieless engagement analytics. vayuShield is always non-nil once
	// bootVayuShield runs (its Middleware is a transparent pass-through when
	// protection is disabled), so callers need no nil-guard beyond the boot check.
	vayuShield   *vayushield.Manager
	vaEngagement *vastore.Store
	vaSessions   *vasession.Hasher

	// shieldOffload is the Aegis L1 exporter: it writes the shield's live jail
	// verdicts into the control dir for the root agent to enforce in-kernel.
	shieldOffload *offload.Exporter

	// verifiedBots authenticates search-engine / AI crawlers by published IP
	// range + forward-confirmed reverse DNS, so the shield can fast-path a real
	// Googlebot/Bingbot/GPTBot past every gate without trusting a spoofable UA.
	verifiedBots *verifiedbot.Verifier

	// shieldIntel holds the third-party network-intelligence feeds an operator
	// has opted into: which addresses belong to datacenters, and which belong to
	// networks a credible publisher lists as hostile. Always non-nil once
	// bootVayuShield runs, and empty — costing one length check per request —
	// until a feed is enabled.
	shieldIntel *intel.Fetcher

	// trustedSessions caches operator-session validation (TTL) so the shield's
	// operator-immunity check stays off the SQLite read path under load.
	trustedSessions *trustedSessionCache

	// sovereign is the Aegis L0 admin-sovereignty gate: a lock-free admission
	// controller mounted BEFORE VayuShield that caps PUBLIC concurrency and sheds
	// the overflow cheaply, guaranteeing the admin control plane (VayuOS, Save,
	// refresh) and verified readers always keep CPU headroom during a flood. It is
	// always non-nil once bootVayuShield runs.
	sovereign *sovereign.Gate
}

// startScheduler runs the background ticker that promotes due scheduled posts to
// live articles via the normal create pipeline. Disabled when SchedulerTickSec<=0.
func (a *App) startScheduler(done <-chan struct{}) {
	tick := config.Cfg.SchedulerTickSec
	if tick <= 0 || a.scheduler == nil {
		logging.LogInfo("scheduler", "scheduled publishing disabled (SCHEDULER_TICK_SEC<=0)")
		return
	}
	logging.LogInfo("scheduler", fmt.Sprintf("scheduled publishing active — tick=%ds", tick))
	go func() {
		ticker := time.NewTicker(time.Duration(tick) * time.Second)
		defer ticker.Stop()
		a.publishDuePosts() // run once at startup to catch anything missed while down
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				a.publishDuePosts()
			}
		}
	}()
}

// publishDuePosts promotes every post whose publish_at has arrived.
func (a *App) publishDuePosts() {
	ctx := context.Background()
	due, err := a.scheduler.Due(ctx, time.Now(), 50)
	if err != nil {
		logging.LogError("scheduler", "due query failed", err.Error())
		return
	}
	for _, p := range due {
		if _, err := a.articles.Create(ctx, p.Title, p.Slug, p.Content, p.Tags); err != nil {
			logging.LogError("scheduler", "publish failed: "+p.Slug, err.Error())
			if mErr := a.scheduler.MarkFailed(ctx, p.ID, err.Error()); mErr != nil {
				logging.LogError("scheduler", "mark-failed failed", mErr.Error())
			}
			continue
		}
		if err := a.scheduler.MarkPublished(ctx, p.ID); err != nil {
			logging.LogError("scheduler", "mark-published failed", err.Error())
		}
		logging.LogInfo("scheduler", "published scheduled post: "+p.Slug)
	}
}

// dispatchWebhook fans an event out to registered outbound webhooks (Tier 2).
// No-op when no webhook store is wired. Runs asynchronously and best-effort.
func (a *App) dispatchWebhook(event string, payload interface{}) {
	if a.webhooks == nil {
		return
	}
	// Tor/anonymous mode (ADR-0141): a Tor Space must make NO clearnet callback.
	// A webhook delivery opens a direct clearnet TCP connection from the server's
	// real IP to the (clearnet) webhook host, correlating the anonymous onion's
	// publish/payment timeline with that IP — the same deanonymisation the sibling
	// shareToSocial/purgeCloudflare/pingIndexNow guards prevent. Suppress delivery
	// here (avoids even spawning the goroutine); safefetch's egress kill-switch is
	// the transport-level backstop for anything that slips past a call-site guard.
	if config.Cfg.OnionMode {
		return
	}
	go a.webhooks.Dispatch(context.Background(), event, payload)
}

// shareToSocial auto-posts a newly published article to configured social
// networks (Tier 2). No-op when social posting is unconfigured. The article
// title is looked up from the store; failures are logged, never fatal.
func (a *App) shareToSocial(slug string) {
	// Tor/anonymous mode (ADR-0141): never auto-post to a clearnet social network —
	// it would publish the onion URL and phone home, de-anonymising the install.
	if config.Cfg.OnionMode {
		return
	}
	if a.social == nil || !a.social.Enabled() {
		return
	}
	go func() {
		var title string
		if err := dbpkg.Reader().QueryRow(`SELECT title FROM articles WHERE slug=?`, slug).Scan(&title); err != nil {
			return
		}
		link := "https://" + config.Cfg.Domain + "/" + slug
		if err := a.social.Share(context.Background(), title, link); err != nil {
			logging.LogError("social", "share failed: "+slug, err.Error())
		}
	}()
}

// RegisterHook registers a plugin hook with the App's plugin registry.
func (a *App) RegisterHook(event string, fn plugins.HookFunc) {
	a.pluginRegistry.Register(event, fn)
}

// FireHook dispatches an event to the App's plugin manager (noop if VAYU_PLUGINS_ENABLED != true).
func (a *App) FireHook(event string, payload map[string]interface{}) {
	if os.Getenv("VAYU_PLUGINS_ENABLED") != "true" {
		return
	}
	a.pluginManager.Fire(event, payload)
}

// =============================================================================
// CDN / search-engine side effects
// =============================================================================

func (a *App) purgeCloudflare(slug string) {
	// Tor/anonymous mode (ADR-0141): a Tor Space has no clearnet CDN in front of
	// it, and must never call the Cloudflare API (an outbound clearnet request).
	if config.Cfg.OnionMode {
		return
	}
	if config.Cfg.CFZoneID == "" || config.Cfg.CFAPIToken == "" {
		return
	}
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/purge_cache", config.Cfg.CFZoneID)
	body, err := json.Marshal(map[string][]string{"files": {"https://" + config.Cfg.Domain + "/" + slug}})
	if err != nil {
		logging.LogError("cloudflare", "marshal failed: "+slug, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		logging.LogError("cloudflare", "build request failed: "+slug, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.Cfg.CFAPIToken)
	resp, err := a.outboundClient.Do(req)
	if err != nil {
		logging.LogError("cloudflare", "purge failed: "+slug, err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		logging.LogError("cloudflare", "purge rejected: "+slug, fmt.Sprintf("status %d", resp.StatusCode))
	}
}

// indexNowKey resolves the active IndexNow key, preferring a credential managed
// from the VayuOS API Keys console (encrypted at rest) and falling back to the
// INDEXNOW_KEY environment variable. This lets operators set/rotate the key
// from the admin panel without an env change or restart.
func (a *App) indexNowKey() string {
	if a.secrets != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		// Trim: a key pasted into the admin field often carries a trailing newline
		// or space. Left untrimmed it silently breaks BOTH sides of IndexNow — the
		// keyLocation URL becomes malformed and the verification-file handler's
		// exact match fails — so every submission is rejected. Trimming here fixes
		// the ping and the key file together, from one source of truth.
		if secret, _ := a.secrets.ProviderSecret(ctx, secrets.ProviderIndexNow); strings.TrimSpace(secret) != "" {
			return strings.TrimSpace(secret)
		}
	}
	return strings.TrimSpace(config.Cfg.IndexNowKey)
}

// indexNowKeyEntry is one cached resolution of the active IndexNow key.
type indexNowKeyEntry struct {
	key string
	at  time.Time
}

// indexNowKeyCacheTTL bounds how long a resolved key is reused before it is
// re-read from the credential store. Mutations invalidate the cache outright, so
// this only covers a change made outside the admin console (a direct DB edit, or
// a second process rotating the credential).
const indexNowKeyCacheTTL = 30 * time.Second

// cachedIndexNowKey is indexNowKey for the hot, unauthenticated paths: the root
// key-file shortcut that runs before every article render, the /.well-known
// key-file handler, and the shield/L0 bypass predicates. Those all run per
// request, and indexNowKey costs a SQL read plus an AES-GCM open — so calling it
// directly made a key lookup part of the cost of viewing any post, and made the
// bypass predicate an amplifier a flood of "/anything.txt" could pull on.
//
// A stale value is harmless in both directions: the key file 404s (or the bypass
// declines) for at most one TTL after a rotation, and callers that must see a
// just-written key call invalidateIndexNowKey first.
func (a *App) cachedIndexNowKey() string {
	if e := a.indexNowKeyCache.Load(); e != nil && time.Since(e.at) < indexNowKeyCacheTTL {
		return e.key
	}
	k := a.indexNowKey()
	a.indexNowKeyCache.Store(&indexNowKeyEntry{key: k, at: time.Now()})
	return k
}

// invalidateIndexNowKey drops the cached key so the next resolve re-reads the
// credential store. Called after every credential write, so a key set, rotated
// or deleted in the API Keys console takes effect on the very next request
// rather than up to a TTL later.
func (a *App) invalidateIndexNowKey() { a.indexNowKeyCache.Store(nil) }

// isIndexNowKeyPath reports whether the request is for the site-root IndexNow
// verification file — https://<domain>/<key>.txt, the exact URL announced as
// keyLocation on every submission.
//
// It exists because that URL is fetched by a search engine's key verifier: a
// machine client with no JavaScript, no cookies and no way to solve a bot
// challenge. Serving it an interstitial is indistinguishable from not serving
// the key at all — the engine returns 202 ("received, key validation pending"),
// the validation never completes, and the URLs are dropped with no error
// anywhere. The /.well-known copy of the same file has always been bypassed;
// the root copy is the one IndexNow actually reads, because a key only vouches
// for URLs at or below its own directory.
//
// The match is deliberately exact — the literal active key, nothing else. A
// looser rule (any "*.txt") would hand an attacker an unshielded route into the
// themed 404 renderer, which is far more expensive than this handler's 32-byte
// write. The shape pre-filter keeps the cached-key load off every other request.
func (a *App) isIndexNowKeyPath(r *http.Request) bool {
	p := r.URL.Path
	if len(p) < len("/12345678.txt") || p[0] != '/' ||
		!strings.HasSuffix(p, ".txt") || strings.Contains(p[1:], "/") {
		return false
	}
	k := a.cachedIndexNowKey()
	return k != "" && p == "/"+k+".txt"
}

// goPingIndexNow launches the IndexNow announcement as TRACKED background
// work: the goroutine is registered on a.bgWG so a test (or a graceful
// shutdown) can wait for it. An untracked `go a.pingIndexNow(...)` used to
// outlive its test and read the config globals while the next test's harness
// re-loaded them — a genuine data race the -race build rightly killed.
func (a *App) goPingIndexNow(slug string) {
	a.bgWG.Add(1)
	go func() {
		defer a.bgWG.Done()
		a.pingIndexNow(slug)
	}()
}

// pingIndexNow announces a published post's URL to IndexNow. It returns the
// outcome — state is one of "submitted", "failed", or "skipped" — and records
// every real attempt (submitted/failed) to indexnow_submissions so the Posts
// manager can show a per-post status and offer a manual re-ping. Skips (no key,
// draft, read-only mode) are not recorded; they leave the last-known row intact.
// Async callers (`go a.pingIndexNow(...)`) simply ignore the return values.
func (a *App) pingIndexNow(slug string) (state, detail string) {
	// Tor/anonymous mode (ADR-0141): never make the clearnet IndexNow callback —
	// it would submit the (onion) URL to a public search endpoint and phone home,
	// de-anonymising the install. Clearnet installs are unaffected.
	if config.Cfg.OnionMode {
		return "skipped", "Tor/anonymous mode — clearnet callbacks disabled"
	}
	// If the operator has blocked search engines and AI crawlers (VayuOS → Power
	// & Maintenance), do not turn around and invite them via IndexNow.
	if a.crawlersBlocked(context.Background()) {
		return "skipped", "search-engine/AI crawler blocking is on"
	}
	indexNowKey := a.indexNowKey()
	if indexNowKey == "" {
		return "skipped", "no IndexNow key configured"
	}
	// Only announce URLs that are actually public. A draft (or a not-yet-published
	// post) returns 404/noindex, so pinging it wastes the submission and can train
	// search engines on a dead URL. This single guard makes every caller correct —
	// create, update, and the publish toggle — without each having to re-check.
	if dbpkg.DB != nil {
		var status string
		if err := dbpkg.Reader().QueryRow(
			`SELECT COALESCE(status,'published') FROM articles WHERE slug=?`, slug).Scan(&status); err != nil {
			return "skipped", "unknown slug" // nothing public to announce
		}
		if status != "published" {
			logging.LogJSON(logging.LogFields{
				Level: "info", Component: "indexnow", Severity: "info",
				Msg: "submission skipped — post is not published", Path: slug, Error: status,
			})
			return "skipped", "post is not published"
		}
	}
	// Governance: IndexNow is an outbound mutation announcement. Suppress it in
	// any mode where the system has withdrawn from normal write/federation
	// activity, and journal the suppression so the timeline stays truthful.
	if m := mode.Global.Current(); m == mode.ModeReadOnly || m == mode.ModeQuarantined || m == mode.ModeMaintenance {
		logging.LogJSON(logging.LogFields{
			Level: "info", Component: "indexnow", Severity: "info",
			Msg: "submission suppressed by system mode", Path: slug, Error: string(m),
		})
		return "skipped", "suppressed by system mode (" + string(m) + ")"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	status, err := a.indexNowSubmit(ctx, indexNowKey, []string{"https://" + config.Cfg.Domain + "/" + slug})
	if err != nil {
		logging.LogError("indexnow", "submission failed: "+slug, err.Error())
		dbpkg.RecordIndexNow(slug, dbpkg.IndexNowFailed, 0, err.Error())
		return "failed", err.Error()
	}
	// IndexNow returns 200/202 on accept; surface anything else for operators.
	if status >= 300 {
		detail := fmt.Sprintf("endpoint returned HTTP %d (%s)", status, indexNowStatusHint(status))
		logging.LogError("indexnow", "submission rejected: "+slug, detail)
		dbpkg.RecordIndexNow(slug, dbpkg.IndexNowFailed, status, detail)
		return "failed", detail
	}
	// IndexNow overloads its 2xx codes and they do NOT mean the same thing: 200
	// is "URL submitted successfully", 202 is "received — key validation
	// pending". A 202 whose key file the engine cannot then read is dropped
	// silently: no error is returned, no retry happens, and nothing ever appears
	// in the engine's console. Recording it as a completed submission is exactly
	// how an install reports a green "✓ IndexNow" on every post while zero URLs
	// are actually received, so keep the distinction all the way to the badge.
	if status == http.StatusAccepted {
		detail := "received — the engine is still validating your key file at https://" +
			config.Cfg.Domain + "/" + indexNowKey + ".txt"
		logging.LogInfo("indexnow", "received, key validation pending: "+slug)
		dbpkg.RecordIndexNow(slug, dbpkg.IndexNowPending, status, detail)
		return "pending", detail
	}
	logging.LogInfo("indexnow", "submitted "+slug)
	dbpkg.RecordIndexNow(slug, dbpkg.IndexNowSubmitted, status, "")
	return "submitted", ""
}

// indexNowKeyFileCheck fetches the site's own IndexNow verification file the way
// a search engine's key verifier does, and returns "" when it is served
// correctly or an operator-facing explanation when it is not.
//
// This is the check that was missing. IndexNow's whole trust model is "prove you
// own the host by serving <key> at keyLocation" — so when that URL is 404, or
// behind a bot challenge, or answers with an HTML interstitial, every
// submission is discarded after the endpoint has already replied 200/202. The
// submission call alone therefore cannot tell an operator whether indexing
// works; only reading the file back can.
//
// It goes through safefetch (the SSRF-hardened fetcher) even though the URL is
// operator-configured and not request-derived: same guard, one code path, and
// the Tor-Space egress kill-switch applies for free.
func (a *App) indexNowKeyFileCheck(ctx context.Context, domain, key string) string {
	u := "https://" + domain + "/" + key + ".txt"
	res, err := safefetch.New(safefetch.Options{
		MaxBytes:       32 << 10,
		Timeout:        8 * time.Second,
		AllowedSchemes: []string{"https"},
		UserAgent:      "VayuPress-IndexNow-Verify/1.0 (+https://" + domain + ")",
	}).Get(ctx, u)
	if err != nil {
		return indexNowKeyFileVerdict(u, key, 0, nil, err)
	}
	return indexNowKeyFileVerdict(u, key, res.Status, res.Body, nil)
}

// indexNowKeyFileVerdict turns one key-file fetch into either "" (the file is
// served exactly as an engine requires) or the operator-facing reason it is not.
// Split out from the fetch so every branch is exercised by a test — a check that
// cannot be shown to fail when the thing it guards breaks is not a check.
func indexNowKeyFileVerdict(u, key string, status int, body []byte, err error) string {
	if err != nil {
		if errors.Is(err, safefetch.ErrBlockedAddress) {
			return "Your domain does not resolve to a public address from this server, so " + u +
				" could not be checked from here. Search engines fetch it over the public internet — confirm it is reachable externally before relying on IndexNow."
		}
		return "The key file at " + u + " could not be fetched: " + err.Error() +
			". Search engines read this file to validate your key; while it is unreachable every submitted URL is discarded."
	}
	switch {
	case status == http.StatusNotFound:
		return "The key file at " + u + " returned 404. Without it no engine can validate your key, so submissions are accepted and then dropped. Check that the site is serving the root key file."
	case status == http.StatusForbidden || status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable:
		return "The key file at " + u + " returned HTTP " + strconv.Itoa(status) +
			" — a proxy or firewall in front of your site is challenging machine clients. A search engine's verifier cannot solve a challenge, so it never reads your key. Add a skip/allow rule for /" + key + ".txt at the edge."
	case status != http.StatusOK:
		return "The key file at " + u + " returned HTTP " + strconv.Itoa(status) + " instead of 200, so engines cannot validate your key."
	case strings.TrimSpace(string(body)) != key:
		return "The URL " + u + " is reachable but its contents are not the key — it is most likely a bot-challenge or error page served in place of the file. Engines compare the body byte-for-byte against the key, so validation fails and submissions are dropped."
	}
	return ""
}

// indexNowSubmit performs the raw IndexNow submission: it POSTs the host, key,
// keyLocation and URL list to the shared IndexNow endpoint (which fans out to
// Bing, Yandex and every participating engine) and returns the HTTP status code.
// A status < 300 means accepted. It applies no gating — callers own the
// mode/onion/published/crawler-block checks — so it can be reused by the manual
// self-test as well as the on-publish ping. The key must already be trimmed.
func (a *App) indexNowSubmit(ctx context.Context, indexNowKey string, urls []string) (int, error) {
	body, err := json.Marshal(map[string]interface{}{
		"host": config.Cfg.Domain,
		"key":  indexNowKey,
		// Root key location: IndexNow only lets a key authorize URLs at or below
		// the key file's directory, so the key must live at the site root to cover
		// root-level post URLs (a /.well-known/ location caused HTTP 422). Served by
		// handleArticlePage's root-key shortcut.
		"keyLocation": "https://" + config.Cfg.Domain + "/" + indexNowKey + ".txt",
		"urlList":     urls,
	})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.indexnow.org/indexnow", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "VayuPress-IndexNow/1.0 (+https://"+config.Cfg.Domain+")")
	resp, err := a.outboundClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10)) // drain so the connection can be reused
	return resp.StatusCode, nil
}

// validIndexNowKey reports whether key meets IndexNow's format rule: 8–128
// characters, each a–z, A–Z, 0–9 or hyphen. An out-of-spec key is rejected by
// the endpoint, so validating up front turns a silent failure into clear advice.
func validIndexNowKey(key string) bool {
	if len(key) < 8 || len(key) > 128 {
		return false
	}
	for _, c := range key {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

// handleOSIndexNowTest runs a live, end-to-end IndexNow self-test and reports the
// exact outcome, so an operator can see at a glance whether instant indexing
// works — and if not, precisely why. It submits the site homepage (a public,
// idempotent URL) through the very same path the on-publish ping uses, and maps
// every failure mode to a specific, actionable message.
func (a *App) handleOSIndexNowTest(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "administrator access required", "")
		return
	}
	fail := func(detail string) {
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": false, "detail": detail})
	}
	if config.Cfg.OnionMode {
		fail("IndexNow is disabled in Tor/anonymous mode — clearnet callbacks are never made.")
		return
	}
	if a.crawlersBlocked(r.Context()) {
		fail("Search engines & AI crawlers are currently blocked (Power & Maintenance), so IndexNow is paused. Allow crawlers to use it.")
		return
	}
	key := a.indexNowKey()
	if key == "" {
		// Fully automatic: generate and store a key so the operator never handles
		// one manually — this button is the whole IndexNow setup, one click.
		if a.secrets == nil {
			fail("Automatic key setup is unavailable (secret storage off). Set the INDEXNOW_KEY environment variable instead.")
			return
		}
		gen := newIndexNowKey()
		if _, err := a.secrets.Upsert(r.Context(), secrets.ProviderIndexNow, "IndexNow key (auto)", "", gen, true, false); err != nil {
			fail("Could not save an auto-generated IndexNow key: " + err.Error())
			return
		}
		key = gen
		a.invalidateIndexNowKey() // serve the new key file on the very next request
		logging.LogInfo("indexnow", "auto-generated an IndexNow key on first connect")
	}
	if !validIndexNowKey(key) {
		fail("The IndexNow key is not a valid format — it must be 8–128 characters using only a–z, A–Z, 0–9 and hyphen. Fix it under API Keys → IndexNow.")
		return
	}
	d := strings.TrimSpace(config.Cfg.Domain)
	if d == "" || strings.HasPrefix(d, "localhost") || strings.HasPrefix(d, "127.0.0.1") {
		fail("Your site domain looks unset or local (" + d + "). IndexNow needs a real public domain to submit and to serve the verification file.")
		return
	}
	if m := mode.Global.Current(); m == mode.ModeReadOnly || m == mode.ModeQuarantined || m == mode.ModeMaintenance {
		fail("Submissions are suppressed while the system is in " + string(m) + " mode. Return to normal mode to submit.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	// Read the key file back FIRST. It is the precondition for everything that
	// follows: an engine only honours a submission after fetching keyLocation and
	// matching the body against the key, and it reports nothing when that fails —
	// the submission is simply discarded. Checking it first is what turns "we
	// pinged and got a 2xx" into "instant indexing actually works", and it is the
	// only part of this self-test that can detect the common real-world failure
	// (an edge proxy challenging the verifier).
	if problem := a.indexNowKeyFileCheck(ctx, d, key); problem != "" {
		fail(problem)
		return
	}
	status, err := a.indexNowSubmit(ctx, key, []string{"https://" + d + "/"})
	if err != nil {
		fail("Could not reach the IndexNow endpoint: " + err.Error() + ". Check outbound network / DNS from the server.")
		return
	}
	if status >= 300 {
		fail(fmt.Sprintf("IndexNow rejected the submission — HTTP %d (%s). Verify the key file is reachable at https://%s/%s.txt.", status, indexNowStatusHint(status), d, key))
		return
	}
	logging.LogInfo("indexnow", "self-test submitted homepage successfully")
	writeJSON(w, r, http.StatusOK, map[string]any{
		"ok":     true,
		"status": status,
		"detail": fmt.Sprintf("Connected — your key file at https://%s/%s.txt is served correctly and IndexNow accepted your submission (HTTP %d, %s). Every post you publish is now announced to Bing, Yandex and other participating engines.", d, key, status, indexNowStatusHint(status)),
	})
}

// newIndexNowKey mints a fresh IndexNow verification key: 32 lowercase hex
// characters, which satisfies IndexNow's 8–128 [a-zA-Z0-9-] format rule.
func newIndexNowKey() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%032x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// indexNowStatusHint translates an IndexNow HTTP status into a short, actionable
// explanation for operators (the protocol overloads a handful of codes).
func indexNowStatusHint(status int) string {
	switch status {
	case http.StatusOK:
		return "submitted"
	// 202 is NOT a success: the protocol defines it as "received — key
	// validation pending". If the engine then cannot read the key file, the URLs
	// are dropped and nothing is reported anywhere, so it must never be worded
	// like an acceptance.
	case http.StatusAccepted:
		return "received — key validation pending"
	case http.StatusBadRequest:
		return "invalid request format"
	case http.StatusForbidden:
		return "key not found or not matching the key file at keyLocation"
	case http.StatusUnprocessableEntity:
		return "URLs don't belong to the host, or the key doesn't match"
	case http.StatusTooManyRequests:
		return "rate limited — too many submissions"
	default:
		return "unexpected status"
	}
}

// =============================================================================
// Domain event subscriptions
// =============================================================================

// registerEventHandlers wires the article mutation event subscribers. Called
// after all services are initialised in main().
func (a *App) registerEventHandlers() {
	bus := a.eventBus

	// Search index + CDN purge + IndexNow on create / update.
	bus.Subscribe(events.ArticleCreated{}, func(ctx context.Context, ev interface{}) {
		e := ev.(events.ArticleCreated)
		a.bgWG.Add(1)
		go func() {
			defer a.bgWG.Done()
			var art dbpkg.Article
			var tagsStr string
			if dbpkg.Reader().QueryRow(`SELECT id,title,slug,content,tags,created_at,updated_at FROM articles WHERE slug=?`, e.Slug).
				Scan(&art.ID, &art.Title, &art.Slug, &art.Content, &tagsStr, &art.CreatedAt, &art.UpdatedAt) == nil {
				art.Tags = api.SplitTags(tagsStr)
				// Best-effort: search drift is healed by the periodic reconciler
				// (SEARCH_RECONCILE_MIN), so an indexing error here is recoverable.
				_ = a.search.Index(ctx, art.ID, art.Title, art.Slug,
					htmlTagRe.ReplaceAllString(a.policy.Sanitize(art.Content), ""),
					art.Tags, art.CreatedAt.Unix())
			}
			// Local cache invalidation is owned by the cache.invalidated.v1
			// subscriber below (emitted transactionally with this mutation).
			a.purgeCloudflare(e.Slug)
			a.pingIndexNow(e.Slug)
		}()
		a.FireHook("article.create", map[string]interface{}{"slug": e.Slug, "id": e.ID})
		a.dispatchWebhook("article.created.v1", map[string]interface{}{"slug": e.Slug, "id": e.ID})
		a.shareToSocial(e.Slug)
		a.broadcastEvent("article.created", map[string]interface{}{"slug": e.Slug, "id": e.ID})
	})

	bus.Subscribe(events.ArticleUpdated{}, func(ctx context.Context, ev interface{}) {
		e := ev.(events.ArticleUpdated)
		a.bgWG.Add(1)
		go func() {
			defer a.bgWG.Done()
			var art dbpkg.Article
			var tagsStr string
			if dbpkg.Reader().QueryRow(`SELECT id,title,slug,content,tags,created_at,updated_at FROM articles WHERE slug=?`, e.Slug).
				Scan(&art.ID, &art.Title, &art.Slug, &art.Content, &tagsStr, &art.CreatedAt, &art.UpdatedAt) == nil {
				art.Tags = api.SplitTags(tagsStr)
				// Best-effort: search drift is healed by the periodic reconciler
				// (SEARCH_RECONCILE_MIN), so an indexing error here is recoverable.
				_ = a.search.Index(ctx, art.ID, art.Title, art.Slug,
					htmlTagRe.ReplaceAllString(a.policy.Sanitize(art.Content), ""),
					art.Tags, art.CreatedAt.Unix())
			}
			// Local cache invalidation is owned by the cache.invalidated.v1
			// subscriber below (emitted transactionally with this mutation).
			a.purgeCloudflare(e.Slug)
			a.pingIndexNow(e.Slug)
		}()
		a.FireHook("article.update", map[string]interface{}{"slug": e.Slug})
		a.dispatchWebhook("article.updated.v1", map[string]interface{}{"slug": e.Slug})
		a.broadcastEvent("article.updated", map[string]interface{}{"slug": e.Slug})
	})

	bus.Subscribe(events.ArticleDeleted{}, func(ctx context.Context, ev interface{}) {
		e := ev.(events.ArticleDeleted)
		go func() {
			_ = a.search.Delete(ctx, e.ID)
			a.purgeCloudflare(e.Slug)
		}()
		a.FireHook("article.delete", map[string]interface{}{"slug": e.Slug, "id": e.ID})
		a.dispatchWebhook("article.deleted.v1", map[string]interface{}{"slug": e.Slug, "id": e.ID})
		a.broadcastEvent("article.deleted", map[string]interface{}{"slug": e.Slug, "id": e.ID})
	})

	// Cache invalidation is the single owner of local rendered-cache purging.
	// Emitted transactionally with every article mutation (including deletes,
	// which previously left a stale cached page behind), it purges the article
	// page, homepage, and affected tag pages, then regenerates the global feeds.
	bus.Subscribe(events.CacheInvalidated{}, func(_ context.Context, ev interface{}) {
		e := ev.(events.CacheInvalidated)
		render.CachePurge(e.Slug, e.Tags, generateSitemap, generateRSS, generateRobots)
		logging.LogJSON(logging.LogFields{
			Level: "info", Component: "cache", Severity: "info",
			Msg: "invalidated rendered fragments (" + e.Reason + ")", Path: e.Slug,
		})
	})
}

// =============================================================================
// Admin metrics snapshot
// =============================================================================

type adminMetricsSnapshot struct {
	TotalArticles  int
	TotalPages     int
	UnreadMessages int
	PendingJobs    int
	FailedJobs     int
	CompletedJobs  int
	StorageBytes   int64
	QuotaBytes     int64
	StoragePct     float64
	WorkersAlive   int64
	CacheHitRatio  float64
	UptimeSeconds  float64
	HTTPP95        int64
	WriteP99       int64
	RenderP99      int64
	RecentArticles []adminRecentArticle
	SnapshotAt     time.Time
}

type adminRecentArticle struct {
	Title     string
	Slug      string
	CreatedAt time.Time
}

func (a *App) collectAdminMetrics() {
	snap := &adminMetricsSnapshot{SnapshotAt: time.Now().UTC()}
	// Use the read pool, not the single writer connection, and index-only counts
	// instead of a full-table SUM over write_jobs. Previously this ran every 30s
	// as `SUM(CASE ...) FROM write_jobs` (a full scan reading every article_json
	// blob) on dbpkg.DB — on a large queue table that scan monopolised the lone
	// writer connection for seconds, stalling sessions/writes and causing
	// intermittent 502s. Each COUNT below is served by idx_jobs_status.
	rdb := dbpkg.Reader()
	_ = rdb.QueryRow(`SELECT COUNT(1) FROM articles`).Scan(&snap.TotalArticles)
	_ = rdb.QueryRow(`SELECT COUNT(1) FROM write_jobs WHERE status='pending'`).Scan(&snap.PendingJobs)
	_ = rdb.QueryRow(`SELECT COUNT(1) FROM write_jobs WHERE status='failed'`).Scan(&snap.FailedJobs)
	_ = rdb.QueryRow(`SELECT COUNT(1) FROM write_jobs WHERE status='completed'`).Scan(&snap.CompletedJobs)
	// Standalone pages (is_page=1) are tracked separately from blog posts so the
	// dashboard can surface each count distinctly. Best-effort; a pre-045 schema
	// without the column simply leaves the count at zero.
	// is_page is NOT NULL DEFAULT 0 (migration 045), so `is_page=1` is exact and
	// uses idx_articles_is_page — unlike COALESCE(is_page,0)=1, which forces a
	// full scan of the whole catalog every 30s.
	_ = rdb.QueryRow(`SELECT COUNT(1) FROM articles WHERE is_page=1`).Scan(&snap.TotalPages)
	// Unread contact messages (best-effort; missing table on a pre-046 schema
	// simply leaves the count at zero).
	_ = rdb.QueryRow(`SELECT COUNT(1) FROM contact_messages WHERE is_read=0`).Scan(&snap.UnreadMessages)
	snap.StorageBytes = dbpkg.StorageUsedBytes()
	snap.QuotaBytes = dbpkg.StorageQuotaBytes()
	if snap.QuotaBytes > 0 {
		snap.StoragePct = float64(snap.StorageBytes) / float64(snap.QuotaBytes) * 100
	}
	snap.WorkersAlive = atomic.LoadInt64(&metrics.WorkerLiveness)
	snap.CacheHitRatio = metrics.CacheHitRatio()
	snap.UptimeSeconds = time.Since(bootTime).Seconds()
	// Recent-window P95 (last ~15 min), not the all-time cumulative tail: the
	// dashboard shows how fast the site is right now, and a transient slow burst
	// ages out instead of pinning the number forever.
	snap.HTTPP95 = metrics.HTTPLatencyWindow.Percentile(95)
	snap.WriteP99 = metrics.QueueJobLatency.Percentile(99)
	snap.RenderP99 = metrics.RenderLatency.Percentile(99)
	rows, err := rdb.Query(`SELECT title,slug,created_at FROM articles ORDER BY created_at DESC LIMIT 15`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ra adminRecentArticle
			if scanErr := rows.Scan(&ra.Title, &ra.Slug, &ra.CreatedAt); scanErr != nil {
				logging.LogError("metrics", "scan recent article", scanErr.Error())
				continue
			}
			snap.RecentArticles = append(snap.RecentArticles, ra)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			logging.LogError("metrics", "iterate recent articles", rowsErr.Error())
		}
	}
	a.metricsSnapshot.Store(snap)
}

func (a *App) startMetricsSnapshotCollector() {
	a.collectAdminMetrics()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-queue.DoneCh:
				return
			case <-ticker.C:
				a.collectAdminMetrics()
			}
		}
	}()
}

func (a *App) getAdminSnapshot() *adminMetricsSnapshot {
	if v := a.metricsSnapshot.Load(); v != nil {
		return v.(*adminMetricsSnapshot)
	}
	a.collectAdminMetrics()
	if v := a.metricsSnapshot.Load(); v != nil {
		return v.(*adminMetricsSnapshot)
	}
	return &adminMetricsSnapshot{SnapshotAt: time.Now()}
}
