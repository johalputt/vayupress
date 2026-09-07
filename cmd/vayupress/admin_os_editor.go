// SPDX-License-Identifier: Apache-2.0

package main

// admin_os_editor.go — VayuOS block editor server endpoints (ADR-0068, Phase 3).
//
// The editor is a vanilla-JS, CSP-strict block editor (static/js/admin-os-editor.js).
// The canonical document is a JSON array of typed blocks. On save the server:
//   1. renders the blocks to sanitised HTML via internal/blockrender,
//   2. updates articles.content (so every reader/feed/search path is unchanged),
//   3. persists the raw blocks_json so the editor can re-hydrate losslessly.
//
// Security: block text is escaped + UGC-sanitised in blockrender (never trusted
// verbatim). Saves are session/API-key gated and CSRF-protected.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	htmlpkg "html"
	htmpl "html/template"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/johalputt/vayupress/internal/api"
	"github.com/johalputt/vayupress/internal/blockrender"
	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/logging"
	"github.com/johalputt/vayupress/internal/metrics"
	"github.com/johalputt/vayupress/internal/mode"
	"github.com/johalputt/vayupress/internal/render"
)

// authorSelectOptions renders <option> tags for every staff user, marking
// selectedID as selected, for the editor's Author picker. Empty when there is no
// user store.
func (a *App) authorSelectOptions(ctx context.Context, selectedID string) string {
	if a.userStore == nil {
		return ""
	}
	list, err := a.userStore.List(ctx)
	if err != nil {
		return ""
	}
	var sb strings.Builder
	for i := range list {
		u := &list[i]
		name := strings.TrimSpace(u.Name)
		if name == "" {
			name = authorFallbackName(u.Email)
		}
		sel := ""
		if u.ID == selectedID {
			sel = " selected"
		}
		sb.WriteString(`<option value="` + htmlpkg.EscapeString(u.ID) + `"` + sel + `>` + htmlpkg.EscapeString(name) + `</option>`)
	}
	return sb.String()
}

// currentUserIDOf returns the signed-in CMS user's id for the request, or "" for
// an API-key/anonymous caller. Used to attribute a new post to its author.
func currentUserIDOf(r *http.Request) string {
	if u := currentUser(r); u != nil {
		return u.ID
	}
	return ""
}

// loadBlocksJSON returns the stored block document for a slug, or "" if the
// article predates the block editor (or does not exist).
func loadBlocksJSON(ctx context.Context, slug string) string {
	if dbpkg.DB == nil {
		return ""
	}
	var bj string
	_ = dbpkg.Reader().QueryRowContext(ctx,
		`SELECT COALESCE(blocks_json,'') FROM articles WHERE slug = ?`, slug).Scan(&bj)
	return bj
}

// persistBlocksJSON writes the raw block document for a slug. It is a direct
// column update: the rendered HTML is saved through the normal article service
// so the write pipeline (cache purge, search index, feeds) stays authoritative.
func persistBlocksJSON(ctx context.Context, slug, blocksJSON string) error {
	if dbpkg.DB == nil {
		return nil
	}
	_, err := dbpkg.DB.ExecContext(ctx,
		`UPDATE articles SET blocks_json = ? WHERE slug = ?`, blocksJSON, slug)
	return err
}

// handleOSEditorSave persists a block document for an existing article. It
// renders blocks → HTML, updates the article content+title via the service,
// then stores the raw blocks for re-hydration.
func (a *App) handleOSEditorSave(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Slug        string            `json:"slug"`
		Title       string            `json:"title"`
		Blocks      []json.RawMessage `json:"blocks"`
		Tags        []string          `json:"tags"`
		PublishDate string            `json:"publishDate"`
		Meta        *PostMeta         `json:"meta"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-json", "Invalid request body", "")
		return
	}
	slug := strings.TrimSpace(body.Slug)
	isNew := slug == ""

	// Normalise tags: trim, drop blanks. A nil slice leaves tags unchanged on
	// update; a non-nil (possibly empty) slice replaces them (allows clearing).
	var tags []string
	if body.Tags != nil {
		tags = splitCSVTags(strings.Join(body.Tags, ","))
		if tags == nil {
			tags = []string{}
		}
	}

	// Re-marshal the blocks array to a canonical JSON string for storage+render.
	blocksJSON := "[]"
	if len(body.Blocks) > 0 {
		if raw, err := json.Marshal(body.Blocks); err == nil {
			blocksJSON = string(raw)
		}
	}

	// Make pasted third-party image links robust: resolve any image/gallery block
	// whose URL is a *page* (e.g. a Pixabay/Unsplash photo page) to the direct
	// image it advertises, so it renders instead of showing a broken image. This
	// only rewrites URL strings — nothing is downloaded or re-hosted — and is
	// bounded by a short deadline so a slow host never blocks the save.
	imgCtx, cancelImg := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancelImg()
	blocksJSON = a.resolveBlockImages(imgCtx, blocksJSON)

	contentHTML, _, err := blockrender.Render(blocksJSON)
	if err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "render-error", "Could not render blocks: "+err.Error(), "")
		return
	}

	// Auto-hero: when the author left the feature image blank, adopt the first
	// image in the body so the post gets a hero automatically; also resolve a
	// page-link feature image to its direct image. Storage-neutral (URL only).
	a.ensureFeatureImage(imgCtx, body.Meta, contentHTML)

	title := strings.TrimSpace(body.Title)

	// ── Native create path (no slug) ─────────────────────────────────────────
	// A brand-new post is created here through the same authoritative article
	// service the API uses — so /os owns the create flow end to end and no
	// longer delegates to the legacy editor. A title is required to derive the
	// slug; article validation needs non-empty content, so an empty document is
	// seeded with a single space that renders to nothing.
	if isNew {
		if title == "" {
			writeAPIError(w, r, http.StatusBadRequest, "missing-title", "A title is required to create a post", "")
			return
		}
		slug = a.uniqueArticleSlug(r.Context(), title)
		seed := contentHTML
		if strings.TrimSpace(seed) == "" {
			seed = " "
		}
		// Draft-first authoring (dashboard-upgrade Wave 1): a brand-new post is
		// born a DRAFT — the first ⌘S must never publish a half-thought to the
		// live site, the disk cache or RSS. Publishing happens via the explicit
		// topbar control (or the Posts manager), never as a side effect of saving.
		if _, err := a.articles.CreateDraft(r.Context(), title, slug, seed, tags); err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "create-error", err.Error(), "")
			return
		}
		if err := persistBlocksJSON(r.Context(), slug, blocksJSON); err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "persist-error", err.Error(), "")
			return
		}
		a.applyPostExtras(r.Context(), slug, body.Meta, body.PublishDate, tags, currentUserIDOf(r))
		writeJSON(w, r, http.StatusOK, map[string]string{"status": "created", "slug": slug, "postStatus": "draft"})
		return
	}

	// ── Update path (existing slug) ──────────────────────────────────────────
	// Ownership, before anything is written. Everything above this point creates;
	// everything below it overwrites somebody's page.
	if a.refuseArticleWrite(w, r, slug) {
		return
	}
	var titlePtr *string
	if title != "" {
		titlePtr = &title
	}
	if _, err := a.articles.Update(r.Context(), slug, titlePtr, &contentHTML, tags); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "update-error", err.Error(), "")
		return
	}

	// Persist the raw block document for lossless re-hydration.
	if err := persistBlocksJSON(r.Context(), slug, blocksJSON); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "persist-error", err.Error(), "")
		return
	}

	a.applyPostExtras(r.Context(), slug, body.Meta, body.PublishDate, tags, currentUserIDOf(r))
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "saved", "slug": slug})
}

// applyPostExtras persists the publishing-options side-car (PostMeta), an
// optional publish-date override, and purges the public caches so the article's
// head metadata / share cards refresh immediately. Each step is best-effort and
// independent of the queued content write (they touch disjoint columns).
func (a *App) applyPostExtras(ctx context.Context, slug string, meta *PostMeta, publishDate string, tags []string, editorID string) {
	if meta != nil {
		// Multi-author attribution: keep any author already assigned; otherwise
		// attribute the post to whoever is editing it (never re-attribute an
		// already-owned post, and never blank it out when the client omits it).
		if strings.TrimSpace(meta.AuthorID) == "" {
			if existing := loadPostMeta(ctx, slug).AuthorID; existing != "" {
				meta.AuthorID = existing
			} else {
				meta.AuthorID = editorID
			}
		}
		if err := savePostMeta(ctx, slug, *meta); err != nil {
			logging.LogError("os-editor", "save post meta failed", err.Error())
		}
	}
	if t, ok := parsePublishDate(publishDate); ok {
		if err := setPublishDate(ctx, slug, t); err != nil {
			logging.LogError("os-editor", "set publish date failed", err.Error())
		}
	}
	// Refresh the public surfaces (article page head meta, home cards, feeds).
	render.CachePurge(slug, tags, generateSitemap, generateRSS, generateRobots)
}

// parsePublishDate accepts the editor's datetime-local value (and a few common
// variants), interpreting a bare wall-clock time as UTC. A blank or unparseable
// value returns ok=false so the existing created_at is left untouched.
func parsePublishDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
		"2006-01-02 15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// handleOSPostStatus publishes or unpublishes (drafts) an article from the post
// manager. Unpublishing hides it from every public surface; both directions
// purge the public caches so the change is immediately visible.
// errPostNotFound marks a slug with no article row, so the single-post and bulk
// endpoints can both map it to a 404 / per-item failure without duplicating the
// lookup.
var errPostNotFound = errors.New("no article with that slug")

// applyPostStatus flips one post's published/draft state and performs the
// shared side effects: cache purge, IndexNow ping on publish, status-toggle
// metric. Shared by the JSON endpoint, the HTMX fragment endpoint and the bulk
// endpoint, so the three can never disagree about what a status flip does.
func (a *App) applyPostStatus(ctx context.Context, slug, status string) error {
	var tagsCSV string
	if err := dbpkg.Reader().QueryRowContext(ctx, `SELECT COALESCE(tags,'') FROM articles WHERE slug=?`, slug).Scan(&tagsCSV); err != nil {
		return errPostNotFound
	}
	if _, err := dbpkg.WDB.Exec(`UPDATE articles SET status=?, updated_at=? WHERE slug=?`, status, time.Now().UTC(), slug); err != nil {
		return err
	}
	// Purge public caches (article page, homepage, tag pages, sitemap, feed) so
	// an unpublish disappears — and a publish appears — without delay.
	render.CachePurge(slug, splitCSVTags(tagsCSV), generateSitemap, generateRSS, generateRobots)
	// Publishing a (previously draft) post makes its URL public for the first
	// time — announce it to IndexNow so search engines crawl it promptly. The
	// status-toggle path emits no ArticleUpdated event, so without this a newly
	// published post would never be submitted. pingIndexNow re-checks that the
	// post is published, so unpublishing never pings.
	if status == "published" {
		go a.pingIndexNow(slug)
	}
	atomic.AddInt64(&metrics.MetricPostStatusToggles, 1)
	return nil
}

func (a *App) handleOSPostStatus(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Slug   string `json:"slug"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-json", "Invalid request body", "")
		return
	}
	slug := strings.TrimSpace(body.Slug)
	status := strings.TrimSpace(body.Status)
	if slug == "" || (status != "published" && status != "draft") {
		writeAPIError(w, r, http.StatusBadRequest, "bad-input", "slug and a valid status (published|draft) are required", "")
		return
	}
	if err := a.applyPostStatus(r.Context(), slug, status); err != nil {
		if err == errPostNotFound {
			writeAPIError(w, r, http.StatusNotFound, "not-found", "No article with that slug", "")
			return
		}
		writeAPIError(w, r, http.StatusInternalServerError, "update-error", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": status, "slug": slug})
}

// handleOSPostToggleFragment is the HTMX counterpart to handleOSPostStatus: it
// flips a single post's published/draft status and returns an HTML fragment —
// the flipped toggle button plus an out-of-band update of that row's status pill
// — so the Posts manager updates the row in place with no full-page reload. The
// JSON handler above stays in use for the bulk actions. CSRF is enforced by the
// route's CSRFTokenMiddleware (the admin layout mirrors the vp_csrf cookie into
// the X-CSRF-Token header for every hx-* request).
func (a *App) handleOSPostToggleFragment(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimSpace(chi.URLParam(r, "slug"))
	status := strings.TrimSpace(r.FormValue("status"))
	// Strict slug allowlist before the slug is used or reflected into the fragment.
	if !api.IsValidSlug(slug) || (status != "published" && status != "draft") {
		http.Error(w, "a valid slug and status (published|draft) are required", http.StatusBadRequest)
		return
	}
	if err := a.applyPostStatus(r.Context(), slug, status); err != nil {
		if err == errPostNotFound {
			http.Error(w, "no article with that slug", http.StatusNotFound)
			return
		}
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	esc := htmlpkg.EscapeString(slug)
	// Wave 3.5: the publish toggle now exists twice per row (face + accordion).
	// Whichever copy was clicked is returned in place; the OTHER copy and the
	// status pill are updated out-of-band so both copies flip on one click.
	src := strings.TrimSpace(r.FormValue("src"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if src == "face" {
		fmt.Fprint(w, osPostStatusFaceButton(esc, status)+osPostStatusButtonOOB(esc, status)+osPostStatusOOB(esc, status))
		return
	}
	fmt.Fprint(w, osPostStatusButton(esc, status)+osPostStatusFaceButtonOOB(esc, status)+osPostStatusOOB(esc, status))
}

// handleOSPostShare issues a signed preview link for a DRAFT through the same
// signer the API uses, so a draft can be shared with a reviewer without making
// it public (Wave 4.4). Published posts are refused with a clear message —
// they are already reachable, and a "share" that shares nothing but a token is
// a lie. The link expires (48h default) and stops working the moment the
// signer's tokens do.
func (a *App) handleOSPostShare(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimSpace(chi.URLParam(r, "slug"))
	if !api.IsValidSlug(slug) {
		writeAPIError(w, r, http.StatusBadRequest, "bad-slug", "A valid slug is required", "")
		return
	}
	var status string
	if err := dbpkg.Reader().QueryRowContext(r.Context(), `SELECT COALESCE(status,'published') FROM articles WHERE slug=?`, slug).Scan(&status); err != nil {
		writeAPIError(w, r, http.StatusNotFound, "not-found", "No article with that slug", "")
		return
	}
	if status != "draft" {
		writeAPIError(w, r, http.StatusConflict, "not-a-draft", "Only drafts can be shared — this post is already public at /"+slug, "")
		return
	}
	if a.previewSigner == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "preview-disabled", "Preview links are not available on this install", "")
		return
	}
	token := a.previewSigner.Issue(slug, 48*time.Hour)
	writeJSON(w, r, http.StatusOK, map[string]string{
		"token": token,
		"url":   "https://" + r.Host + "/" + slug + "?preview=" + token,
		"ttl":   "48h",
	})
}

// handleOSPostIndexNowFragment lets an operator manually (re-)submit a single
// post's URL to IndexNow from the Posts manager — for when the automatic
// on-publish ping did not go through (no key at the time, a transient failure,
// or a proxy challenge). It submits synchronously so the result is immediate,
// then returns the flipped button plus an out-of-band update of that row's
// IndexNow badge. CSRF is enforced by the route's CSRFTokenMiddleware.
func (a *App) handleOSPostIndexNowFragment(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimSpace(chi.URLParam(r, "slug"))
	if !api.IsValidSlug(slug) {
		http.Error(w, "a valid slug is required", http.StatusBadRequest)
		return
	}
	var status string
	if err := dbpkg.Reader().QueryRowContext(r.Context(), `SELECT COALESCE(status,'published') FROM articles WHERE slug=?`, slug).Scan(&status); err != nil {
		http.Error(w, "no article with that slug", http.StatusNotFound)
		return
	}
	isDraft := status != "published"
	// Submit now; pingIndexNow records the outcome to indexnow_submissions.
	state, detail := a.pingIndexNow(slug)
	st, ok := dbpkg.IndexNowStatusOf(slug)
	if !ok && state == "skipped" {
		// Nothing was recorded (e.g. no IndexNow key configured, or a read-only
		// mode). Surface the reason inline so the operator isn't left guessing.
		st, ok = dbpkg.IndexNowStatus{State: dbpkg.IndexNowFailed, Detail: detail}, true
	}
	esc := htmlpkg.EscapeString(slug)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, osIndexNowButton(esc, st, ok, isDraft)+osIndexNowBadgeOOB(esc, st, ok, isDraft))
}

// handleOSPostPinFragment is the HTMX counterpart to handleOSPostPin: it flips a
// post's featured (pinned) flag and returns an HTML fragment — the flipped pin
// button plus an out-of-band update of the row's "📌 Pinned" badge — so the
// Posts manager updates in place with no full-page reload. The JSON handler
// below stays in use for the bulk/editor paths. CSRF is enforced by the route's
// CSRFTokenMiddleware.
func (a *App) handleOSPostPinFragment(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimSpace(chi.URLParam(r, "slug"))
	pinned := strings.TrimSpace(r.FormValue("pinned"))
	// Strict slug allowlist before the slug is used or reflected into the fragment.
	if !api.IsValidSlug(slug) || (pinned != "0" && pinned != "1") {
		http.Error(w, "a valid slug and pinned (0|1) are required", http.StatusBadRequest)
		return
	}
	var tagsCSV string
	if err := dbpkg.Reader().QueryRowContext(r.Context(), `SELECT COALESCE(tags,'') FROM articles WHERE slug=?`, slug).Scan(&tagsCSV); err != nil {
		http.Error(w, "no article with that slug", http.StatusNotFound)
		return
	}
	featured := pinned == "1"
	f := 0
	if featured {
		f = 1
	}
	if _, err := dbpkg.WDB.Exec(`UPDATE articles SET featured=?, updated_at=? WHERE slug=?`, f, time.Now().UTC(), slug); err != nil {
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	// Same public-surface refresh as the JSON path so the trending/pinned widget
	// reflects the change immediately.
	invalidateTrendingCache()
	render.CachePurge(slug, splitCSVTags(tagsCSV), generateSitemap, generateRSS, generateRobots)
	atomic.AddInt64(&metrics.MetricPostPinToggles, 1)
	esc := htmlpkg.EscapeString(slug)
	// Wave 3.5: same dual-copy parity as the status fragment — the clicked copy
	// is returned in place, the other copy and the pinned badge go out-of-band.
	src := strings.TrimSpace(r.FormValue("src"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if src == "face" {
		fmt.Fprint(w, osPostPinFaceButton(esc, featured)+osPostPinButtonOOB(esc, featured)+osPostPinBadge(esc, featured, true))
		return
	}
	fmt.Fprint(w, osPostPinButton(esc, featured)+osPostPinFaceButtonOOB(esc, featured)+osPostPinBadge(esc, featured, true))
}

// handleOSPostPin pins or unpins (features) a post directly from the manager,
// flipping the same `featured` flag the editor exposes as "Feature this post".
// Pinned posts surface in the public Trending & pinned widget (homepage + under
// every post), so we drop the trending cache and purge public caches so the
// change appears immediately.
func (a *App) handleOSPostPin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Slug   string `json:"slug"`
		Pinned bool   `json:"pinned"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-json", "Invalid request body", "")
		return
	}
	slug := strings.TrimSpace(body.Slug)
	if slug == "" {
		writeAPIError(w, r, http.StatusBadRequest, "bad-input", "a slug is required", "")
		return
	}
	var tagsCSV string
	if err := dbpkg.Reader().QueryRowContext(r.Context(), `SELECT COALESCE(tags,'') FROM articles WHERE slug=?`, slug).Scan(&tagsCSV); err != nil {
		writeAPIError(w, r, http.StatusNotFound, "not-found", "No article with that slug", "")
		return
	}
	featured := 0
	if body.Pinned {
		featured = 1
	}
	if _, err := dbpkg.WDB.Exec(`UPDATE articles SET featured=?, updated_at=? WHERE slug=?`, featured, time.Now().UTC(), slug); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "update-error", err.Error(), "")
		return
	}
	// Refresh the public surfaces and the memoised trending/pinned payload.
	invalidateTrendingCache()
	render.CachePurge(slug, splitCSVTags(tagsCSV), generateSitemap, generateRSS, generateRobots)
	atomic.AddInt64(&metrics.MetricPostPinToggles, 1)
	writeJSON(w, r, http.StatusOK, map[string]bool{"pinned": body.Pinned})
}

// handleOSPostDelete permanently removes a post (or page) from the VayuOS
// manager. It is synchronous so the list reflects the deletion immediately:
// the article row carries its own blocks_json + publishing-options columns, so
// the row delete cleans those up; its comments are removed too. Public caches
// (article page, home, tags, sitemap, feed) are purged so the post disappears
// from the live site at once. Refused in read-only / quarantined mode.
func (a *App) handleOSPostDelete(w http.ResponseWriter, r *http.Request) {
	if cur := mode.Global.Current(); cur == mode.ModeReadOnly || cur == mode.ModeQuarantined {
		writeAPIError(w, r, http.StatusServiceUnavailable, "read-only", "posts cannot be deleted in "+string(cur)+" mode", "")
		return
	}
	slug := strings.TrimSpace(chi.URLParam(r, "slug"))
	if slug == "" {
		writeAPIError(w, r, http.StatusBadRequest, "bad-input", "a slug is required", "")
		return
	}
	if err := a.deletePostBySlug(r.Context(), r, slug); err != nil {
		if err == errPostNotFound {
			writeAPIError(w, r, http.StatusNotFound, "not-found", "No post with that slug", "")
			return
		}
		var refused *refusedWriteError
		if errors.As(err, &refused) {
			writeAPIError(w, r, http.StatusForbidden, "not-your-post", refused.Error(), "")
			return
		}
		writeAPIError(w, r, http.StatusInternalServerError, "delete-error", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "deleted", "slug": slug})
}

// refusedWriteError marks a per-slug write refusal (ownership or mode), so the
// single-post and bulk endpoints can map it to 403 without re-running the
// predicate or writing to the response from inside the helper.
type refusedWriteError struct{ reason string }

func (e *refusedWriteError) Error() string { return e.reason }

// deletePostBySlug removes one post and its comments, purges the public caches
// and writes the audit trail. Shared by the single DELETE endpoint and the bulk
// endpoint, so bulk deletion can never drift from single deletion. Deletion is
// the irreversible half: there is no snapshot to restore from, and the comments
// go with it.
func (a *App) deletePostBySlug(ctx context.Context, r *http.Request, slug string) error {
	if cur := mode.Global.Current(); cur == mode.ModeReadOnly || cur == mode.ModeQuarantined {
		return errors.New("posts cannot be deleted in " + string(cur) + " mode")
	}
	var id, tagsCSV string
	if err := dbpkg.Reader().QueryRowContext(ctx, `SELECT id,COALESCE(tags,'') FROM articles WHERE slug=?`, slug).Scan(&id, &tagsCSV); err != nil {
		return errPostNotFound
	}
	if reason := a.articleWriteRefusal(r, slug); reason != "" {
		dbpkg.AuditLog("article.write.refused", dbpkg.AuditActor(r), slug, reason)
		return &refusedWriteError{reason: reason}
	}
	if _, err := dbpkg.WDB.Exec(`DELETE FROM articles WHERE slug=?`, slug); err != nil {
		return err
	}
	// Best-effort cleanup of the post's comments (orphans otherwise).
	_, _ = dbpkg.WDB.Exec(`DELETE FROM comments WHERE article_id=?`, id)

	render.CachePurge(slug, splitCSVTags(tagsCSV), generateSitemap, generateRSS, generateRobots)
	dbpkg.AuditLog("article.delete", dbpkg.AuditActor(r), slug, "id="+id)
	logging.LogJSON(logging.LogFields{
		Level: "info", Component: "editor", Severity: "info",
		Msg: "post deleted: " + slug, RequestID: getRequestID(r),
	})
	return nil
}

// osBulkMaxSlugs caps one bulk request: the batch is N single-post operations
// (each with a cache purge), and an unbounded list would let one request pin
// the server for minutes. 200 covers any page of the posts manager (100/page)
// with headroom for a multi-page selection.
const osBulkMaxSlugs = 200

// bulkPostResult is the per-slug outcome of a bulk request.
type bulkPostResult struct {
	Slug   string `json:"slug"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Status string `json:"status,omitempty"`
	Pill   string `json:"pill,omitempty"`
	Button string `json:"button,omitempty"`
}

// handleOSPostsBulk is the ONE-request bulk endpoint for the Posts manager:
// POST /os/api/posts/bulk {"action":"published"|"draft"|"delete","slugs":[…]}.
// It replaces the client-side loop of N parallel fetches, which raced the
// server, gave no per-slug outcomes, and could only recover by reloading the
// page away. Each slug is applied independently through the SAME helpers as the
// single-post endpoints (applyPostStatus / deletePostBySlug), so a failure is
// reported per slug and the successes stand. Status actions additionally return
// each slug's flipped pill + toggle button (the same markup the HTMX fragment
// endpoint returns) so the rows update in place without a reload, plus the
// recomputed All/Published/Drafts counts so the tabs stay honest.
func (a *App) handleOSPostsBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action string   `json:"action"`
		Slugs  []string `json:"slugs"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-json", "Invalid request body", "")
		return
	}
	action := strings.TrimSpace(body.Action)
	if action != "published" && action != "draft" && action != "delete" {
		writeAPIError(w, r, http.StatusBadRequest, "bad-input", "action must be published, draft or delete", "")
		return
	}
	if len(body.Slugs) == 0 || len(body.Slugs) > osBulkMaxSlugs {
		writeAPIError(w, r, http.StatusBadRequest, "bad-input",
			"slugs must contain between 1 and "+strconv.Itoa(osBulkMaxSlugs)+" slugs", "")
		return
	}
	seen := make(map[string]struct{}, len(body.Slugs))
	slugs := make([]string, 0, len(body.Slugs))
	for _, s := range body.Slugs {
		s = strings.TrimSpace(s)
		if !api.IsValidSlug(s) {
			writeAPIError(w, r, http.StatusBadRequest, "bad-input", "every slug must be a valid post slug", "")
			return
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		slugs = append(slugs, s)
	}

	results := make([]bulkPostResult, 0, len(slugs))
	okN := 0
	for _, slug := range slugs {
		res := bulkPostResult{Slug: slug}
		var err error
		if action == "delete" {
			err = a.deletePostBySlug(r.Context(), r, slug)
		} else {
			err = a.applyPostStatus(r.Context(), slug, action)
		}
		if err != nil {
			res.Error = err.Error()
		} else {
			res.OK = true
			okN++
			if action != "delete" {
				res.Status = action
				res.Pill = osPostStatusPill(action)
				res.Button = osPostStatusButton(htmlpkg.EscapeString(slug), action)
			}
		}
		results = append(results, res)
	}

	resp := struct {
		OK      int              `json:"ok"`
		Failed  int              `json:"failed"`
		Results []bulkPostResult `json:"results"`
		Counts  map[string]int   `json:"counts,omitempty"`
	}{OK: okN, Failed: len(slugs) - okN, Results: results}
	if action != "delete" {
		// The tabs must describe the catalogue AS IT NOW IS, not as it was when
		// the page loaded — otherwise the numbers lie the moment the batch lands.
		if counts, err := postStatusCounts(r.Context()); err == nil {
			resp.Counts = counts
		}
	}
	writeJSON(w, r, http.StatusOK, resp)
}

// postStatusCounts recomputes the All/Published/Drafts tab counts. status is
// NOT NULL DEFAULT 'published' (migration 030), so the query groups by the bare
// column — COALESCE would defeat idx_articles_status and force a full scan (the
// same reasoning as the posts page's count query).
func postStatusCounts(ctx context.Context) (map[string]int, error) {
	counts := map[string]int{"all": 0, "published": 0, "draft": 0}
	rows, err := dbpkg.Reader().QueryContext(ctx, `SELECT status, COUNT(1) FROM articles GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		var c int
		if err := rows.Scan(&s, &c); err != nil {
			return nil, err
		}
		counts["all"] += c
		if s == "draft" {
			counts["draft"] += c
		} else {
			counts["published"] += c
		}
	}
	return counts, rows.Err()
}

// splitCSVTags splits a stored comma-separated tag string into a slice.
func splitCSVTags(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// uniqueArticleSlug derives a URL slug from title and ensures it does not collide
// with an existing article, appending -2, -3, … as needed. Shared by the native
// editor create path and quick-create.
func (a *App) uniqueArticleSlug(ctx context.Context, title string) string {
	slug := migrateSlugify(title)
	if slug == "" {
		slug = "untitled-" + strconv.FormatInt(time.Now().Unix(), 36)
	}
	base := slug
	for i := 2; i <= 99; i++ {
		if _, err := a.articles.Get(ctx, slug); err != nil {
			break // available
		}
		slug = base + "-" + strconv.Itoa(i)
	}
	return slug
}

// handleOSEditorConvert imports a legacy article's HTML into a block document
// (ADR-0069 Stage 1). It is deliberately non-destructive: it writes only the
// blocks_json side-car and never touches the rendered article content. The
// operator reviews the imported blocks in the editor and the original content
// stays authoritative until they explicitly Save. This keeps legacy posts
// lossless — a poor import can be abandoned by navigating away.
func (a *App) handleOSEditorConvert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-json", "Invalid request body", "")
		return
	}
	slug := strings.TrimSpace(body.Slug)
	if slug == "" {
		writeAPIError(w, r, http.StatusBadRequest, "missing-slug", "slug is required", "")
		return
	}

	art, err := a.articles.Get(r.Context(), slug)
	if err != nil {
		writeAPIError(w, r, http.StatusNotFound, "not-found", "No article with that slug", "")
		return
	}

	blocks := blockrender.ImportHTML(art.Content)
	raw, err := json.Marshal(blocks)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "marshal-error", err.Error(), "")
		return
	}
	if err := persistBlocksJSON(r.Context(), slug, string(raw)); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "persist-error", err.Error(), "")
		return
	}

	writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"status": "converted",
		"slug":   slug,
		"blocks": len(blocks),
	})
}

// handleOSEditorImport converts an editor-supplied HTML string into a block
// document and returns it, without persisting anything. It backs the editor's
// one-click HTML source mode: the operator edits raw HTML and, on switching back
// to the visual canvas, that HTML is parsed into blocks here. The conversion is
// the same conservative importer used for legacy posts and now preserves inline
// formatting (bold / italic / code / strike / links) as Markdown, so a
// visual → HTML → visual round-trip is lossless for common formatting.
func (a *App) handleOSEditorImport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		HTML string `json:"html"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-json", "Invalid request body", "")
		return
	}
	blocks := blockrender.ImportHTML(body.HTML)
	writeJSON(w, r, http.StatusOK, map[string]interface{}{"blocks": blocks})
}

// handleOSEditorPreview renders a block document to sanitised HTML without
// persisting anything — used by the editor's live preview pane.
func (a *App) handleOSEditorPreview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Blocks []json.RawMessage `json:"blocks"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-json", "Invalid request body", "")
		return
	}
	blocksJSON := "[]"
	if len(body.Blocks) > 0 {
		if raw, err := json.Marshal(body.Blocks); err == nil {
			blocksJSON = string(raw)
		}
	}
	contentHTML, excerpt, err := blockrender.Render(blocksJSON)
	if err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "render-error", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"html": contentHTML, "excerpt": excerpt})
}

// handleOSEditorAI proxies an AI writing-assist request for os session-cookie
// operators. The backing model is opt-in (VAYU_AI_URL); when absent the handler
// returns 503 so the editor UI can degrade gracefully.
func (a *App) handleOSEditorAI(w http.ResponseWriter, r *http.Request) {
	if a.aiAssist == nil || !a.aiAssist.Enabled() {
		writeAPIError(w, r, http.StatusServiceUnavailable, "ai-disabled", "AI assistant not configured (set VAYU_AI_URL)", "")
		return
	}
	var body struct {
		Op   string `json:"op"`
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-json", "Invalid request body", "")
		return
	}
	result, err := a.aiAssist.Assist(r.Context(), body.Op, body.Text)
	if err != nil {
		writeAPIError(w, r, http.StatusBadGateway, "ai-error", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]interface{}{"op": body.Op, "result": result})
}

// handleOSEditorVersionList returns the version list for a slug, session-gated.
func (a *App) handleOSEditorVersionList(w http.ResponseWriter, r *http.Request) {
	if a.versionStore == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "versions-disabled", "Version store not initialised", "")
		return
	}
	slug := chi.URLParam(r, "slug")
	var articleID string
	if err := dbpkg.Reader().QueryRowContext(r.Context(), `SELECT id FROM articles WHERE slug=?`, slug).Scan(&articleID); err != nil {
		writeAPIError(w, r, http.StatusNotFound, "article-not-found", "No article with that slug", "")
		return
	}
	vs, err := a.versionStore.List(r.Context(), articleID, 30)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "db-error", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]interface{}{"versions": vs})
}

// handleOSEditorVersionGet returns a single version by ID, session-gated.
func (a *App) handleOSEditorVersionGet(w http.ResponseWriter, r *http.Request) {
	if a.versionStore == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "versions-disabled", "Version store not initialised", "")
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-id", "Version id must be an integer", "")
		return
	}
	v, err := a.versionStore.Get(r.Context(), id)
	if err != nil {
		writeAPIError(w, r, http.StatusNotFound, "not-found", "Version not found", "")
		return
	}
	writeJSON(w, r, http.StatusOK, v)
}

// handleOSEditorVersionRestore rewinds an article to a stored snapshot
// (dashboard-upgrade Wave 1): history that can only be read is documentation,
// not a safety net. The article's title/content/tags return to the snapshot and
// the block document is rebuilt from the restored HTML so the editor rehydrates
// what was actually restored (ImportHTML is conservative; anything it cannot
// express becomes markdown/raw-HTML blocks rather than being dropped).
func (a *App) handleOSEditorVersionRestore(w http.ResponseWriter, r *http.Request) {
	if a.versionStore == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "versions-disabled", "Version store not initialised", "")
		return
	}
	if a.articles == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "article service not initialised", "")
		return
	}
	slug := strings.TrimSpace(chi.URLParam(r, "slug"))
	if !api.IsValidSlug(slug) {
		writeAPIError(w, r, http.StatusBadRequest, "bad-input", "A valid slug is required", "")
		return
	}
	// Same ownership gate as every other destructive write on this surface.
	if a.refuseArticleWrite(w, r, slug) {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-id", "Version id must be an integer", "")
		return
	}
	v, err := a.versionStore.Get(r.Context(), id)
	if err != nil || v == nil {
		writeAPIError(w, r, http.StatusNotFound, "not-found", "Version not found", "")
		return
	}
	if v.Slug != slug {
		writeAPIError(w, r, http.StatusBadRequest, "version-mismatch", "That version belongs to a different post", "")
		return
	}
	restoredTags := v.Tags
	if restoredTags == nil {
		restoredTags = []string{}
	}
	if _, err := a.articles.Update(r.Context(), slug, &v.Title, &v.Content, restoredTags); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "restore-error", err.Error(), "")
		return
	}
	// Best-effort hydration document: the canonical article content above is the
	// source of truth for readers; this keeps the editor's canvas faithful.
	blocks := blockrender.ImportHTML(v.Content)
	blocksJSON := "[]"
	if len(blocks) > 0 {
		if raw, mErr := json.Marshal(blocks); mErr == nil {
			blocksJSON = string(raw)
		}
	}
	if err := persistBlocksJSON(r.Context(), slug, blocksJSON); err != nil {
		logging.LogError("os-editor", "restore blocks_json persist failed", err.Error())
	}
	render.CachePurge(slug, restoredTags, generateSitemap, generateRSS, generateRobots)
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "restored", "slug": slug})
}

// osEditorBody builds the block-editor shell. The editor hydrates from the
// <script type="application/json" id="vp-editor-data"> document on first paint;
// an empty value starts a fresh document.
// osEditorHeadTmpl renders the interpolated head of the editor shell through
// html/template so every value passes a recognised escaping barrier:
//   - .Blocks is emitted in the <script type="application/json"> context, where
//     html/template turns HTML-significant bytes (<, >, &, U+2028/9) into \uXXXX
//     escapes that JSON.parse reverses — so </script> can never break out, yet
//     the document round-trips losslessly.
//   - .Slug and .Title are attribute-escaped (double quotes become &#34;).
//
// The static remainder of the shell carries no interpolation and is appended
// as a literal.
var osEditorHeadTmpl = htmpl.Must(htmpl.New("oseditorhead").Parse(
	`<script type="application/json" id="vp-editor-data">{{.Blocks}}</script>
<div class="editor-shell" data-editor data-slug="{{.Slug}}">
  <div class="editor-topbar">
    <span class="editor-topbar-status" data-editor-topbar-status></span>
    <div class="editor-topbar-actions">
      <span class="editor-wordcount" data-editor-wordcount aria-live="polite"></span>
      <button type="button" class="btn btn--ghost btn--sm" data-editor-focus-btn title="Focus mode (Ctrl/Cmd+.)">Focus</button>
      <button type="button" class="btn btn--ghost btn--sm" data-editor-split-btn title="Toggle live preview">Split</button>
      <button type="button" class="btn btn--ghost btn--sm" data-editor-md-btn title="Edit the whole post as Markdown (Ctrl/Cmd+Shift+M)" aria-pressed="false">Markdown</button>
      <button type="button" class="btn btn--ghost btn--sm" data-editor-html-btn title="Edit HTML source (Ctrl/Cmd+Shift+H)" aria-pressed="false">HTML</button>
      <button type="button" class="btn btn--ghost btn--sm" data-editor-preview-btn>Preview</button>
      <button type="button" class="btn btn--ghost btn--sm" data-editor-share-btn title="Copy a 48-hour preview link for this draft — it stays a draft">🔗 Share draft</button>
      <button type="button" class="btn btn--ghost btn--sm" data-editor-image-btn title="Upload an image and insert it here">🖼 Image</button>
      <button type="button" class="btn btn--ghost btn--sm" data-editor-ai-btn title="Write a draft from a prompt with AI">✨ AI</button>
      <button type="button" class="btn btn--ghost btn--sm" data-editor-settings-btn title="Post settings (Ctrl/Cmd+Shift+P)" aria-pressed="false">⚙ Settings</button>
      <button type="button" class="btn btn--ghost btn--sm" data-editor-newpage title="Create a new standalone page">＋ Page</button>
      <span class="editor-pubstate" data-editor-pubstate hidden></span>
      <button type="button" class="btn btn--accent btn--sm" data-editor-publish-btn hidden title="Publish to the live site"></button>
      <button type="button" class="btn btn--primary btn--sm" data-editor-save>Save</button>
    </div>
  </div>
  <div class="editor-main">
    <input class="editor-title" data-editor-title type="text" placeholder="Post title…" value="{{.Title}}" aria-label="Post title">
    <div class="editor-workspace">
      <div class="editor-canvas" data-editor-canvas aria-label="Editor canvas"></div>
      <aside class="editor-live" data-editor-live hidden aria-label="Live preview">
        <div class="editor-live-head">Live preview</div>
        <article class="editor-live-body article" data-editor-live-body></article>
      </aside>
      <section class="editor-html" data-editor-html-panel hidden aria-label="HTML source editor">
        <div class="editor-html-head">
          <span class="editor-html-title">HTML source</span>
          <span class="text-xs muted">Edit raw HTML — switch back to apply it to your blocks.</span>
        </div>
        <textarea class="editor-html-area" data-editor-html-area spellcheck="false" autocomplete="off" autocapitalize="off" wrap="soft" aria-label="HTML source"></textarea>
      </section>
      <section class="editor-html" data-editor-md-panel hidden aria-label="Markdown source editor">
        <div class="editor-html-head">
          <span class="editor-html-title">Markdown</span>
          <span class="text-xs muted">Write the whole post in Markdown — switch back to apply it to your blocks.</span>
        </div>
        <textarea class="editor-html-area" data-editor-md-area spellcheck="false" autocomplete="off" autocapitalize="off" wrap="soft" aria-label="Markdown source"></textarea>
      </section>
    </div>
  </div>`))

// osEditorMetaTmpl emits the publishing-options hydration document in the same
// JSON-in-script context the block document uses: html/template escapes the
// HTML-significant bytes so the values cannot break out of <script>, while
// JSON.parse reverses the escaping client-side.
var osEditorMetaTmpl = htmpl.Must(htmpl.New("oseditormeta").Parse(
	`<script type="application/json" id="vp-editor-meta">{{.Meta}}</script>`))

// osEditorMetaScript serialises a post's settings (tags, publish date, status,
// and the PostMeta side-car) for the editor's Post-settings panel to hydrate.
func osEditorMetaScript(slug, status string, createdAt time.Time, tags []string, m PostMeta) string {
	if tags == nil {
		tags = []string{}
	}
	pub := ""
	if !createdAt.IsZero() {
		pub = config.FormatSite(createdAt, "2006-01-02T15:04")
	}
	payload := struct {
		Slug        string   `json:"slug"`
		Status      string   `json:"status"`
		Tags        []string `json:"tags"`
		PublishDate string   `json:"publishDate"`
		PostMeta
	}{Slug: slug, Status: status, Tags: tags, PublishDate: pub, PostMeta: m}
	raw, err := json.Marshal(payload)
	if err != nil {
		raw = []byte("{}")
	}
	var sb strings.Builder
	_ = osEditorMetaTmpl.Execute(&sb, struct{ Meta json.RawMessage }{json.RawMessage(raw)})
	return sb.String()
}

func osEditorBody(slug, title, blocksJSON, authorOptions string) string {
	if strings.TrimSpace(blocksJSON) == "" {
		blocksJSON = "[]"
	}
	var head strings.Builder
	// Execute cannot fail for these scalar fields and a constant template.
	_ = osEditorHeadTmpl.Execute(&head, struct {
		Blocks json.RawMessage
		Slug   string
		Title  string
	}{json.RawMessage(blocksJSON), slug, title})
	return head.String() + `
  <aside class="editor-sidebar" aria-label="Editor tools">
    <div class="editor-status" data-editor-status>Ready</div>
    <div class="editor-stats" aria-label="Document statistics">
      <div class="editor-stat"><span class="editor-stat__num" data-editor-stats-words>0</span><span class="editor-stat__label">words</span></div>
      <div class="editor-stat"><span class="editor-stat__num" data-editor-stats-chars>0</span><span class="editor-stat__label">characters</span></div>
      <div class="editor-stat"><span class="editor-stat__num" data-editor-stats-read>—</span><span class="editor-stat__label">reading</span></div>
    </div>
    <nav class="editor-outline" data-editor-outline-wrap aria-label="Document outline" hidden>
      <div class="editor-outline__title">Outline</div>
      <div class="editor-outline__list" data-editor-outline></div>
    </nav>
    <div class="editor-actions">
      <button type="button" class="btn btn--ghost btn--sm" data-editor-undo title="Undo (Ctrl/Cmd+Z outside a field)" disabled>Undo</button>
      <button type="button" class="btn btn--ghost btn--sm" data-editor-redo title="Redo (Ctrl/Cmd+Shift+Z)" disabled>Redo</button>
      <button type="button" class="btn btn--ghost btn--sm" data-editor-history-btn>History</button>
    </div>
    <div class="text-xs muted">Press <kbd>/</kbd> on an empty block for commands, or <kbd>⌘K</kbd>/<kbd>Ctrl+K</kbd> anywhere. <kbd>/ai</kbd> for AI assist.</div>
    <div class="text-xs muted mt-2">Type Markdown to format: <kbd>## </kbd> heading, <kbd>- </kbd> list, <kbd>- [ ] </kbd> task, <kbd>1. </kbd> numbered, <kbd>&gt; </kbd> quote, <kbd>&#96;&#96;&#96;</kbd> code, <kbd>---</kbd> divider.</div>
    <div class="text-xs muted mt-2">Select text for <strong>bold</strong>/<em>italic</em>/link, or use <kbd>**bold**</kbd>, <kbd>*italic*</kbd>, <kbd>[text](url)</kbd>. Drag or paste an image to upload.</div>
    <div class="text-xs muted mt-2">Reorder blocks by dragging <kbd>⋮⋮</kbd> or with the <kbd>↑</kbd>/<kbd>↓</kbd> buttons. <kbd>⌘.</kbd> toggles focus mode.</div>
    <div class="text-xs muted mt-2"><kbd>Enter</kbd> new block · <kbd>Shift+Enter</kbd> line break · <kbd>⌘S</kbd> / <kbd>Ctrl+S</kbd> to save.</div>
    <div class="text-xs muted mt-2"><kbd>Markdown</kbd> (<kbd>⌘⇧M</kbd>) edits the whole post as Markdown; <kbd>HTML</kbd> (<kbd>⌘⇧H</kbd>) as raw HTML — both round-trip back to blocks losslessly.</div>
    <div class="text-xs muted mt-2"><kbd>⚙ Settings</kbd> (<kbd>⌘⇧P</kbd>) opens post settings: feature image, URL, publish date, excerpt, tags, SEO &amp; social cards.</div>
  </aside>
  <div class="editor-preview-modal" data-editor-preview hidden role="dialog" aria-modal="true" aria-label="Preview">
    <div class="editor-preview-panel">
      <div class="editor-preview-head">
        <span>Preview</span>
        <button type="button" class="btn--icon" data-editor-preview-close aria-label="Close preview">✕</button>
      </div>
      <article class="editor-preview-body article" data-editor-preview-body></article>
    </div>
  </div>
  <div class="editor-history-modal" data-editor-history hidden role="dialog" aria-modal="true" aria-label="Version history">
    <div class="editor-history-panel">
      <div class="editor-history-head">
        <span>Version history</span>
        <button type="button" class="btn--icon" data-editor-history-close aria-label="Close history">✕</button>
      </div>
      <div class="editor-history-body">
        <div class="editor-history-list" data-editor-history-list></div>
        <div class="editor-history-diff" data-editor-history-diff></div>
      </div>
    </div>
  </div>
  <div class="editor-history-modal" data-editor-ai-modal hidden role="dialog" aria-modal="true" aria-label="Write with AI">
    <div class="editor-history-panel">
      <div class="editor-history-head">
        <span>✨ Write with AI</span>
        <button type="button" class="btn--icon" data-ai-close aria-label="Close">✕</button>
      </div>
      <div class="editor-settings-body ai-panel">
        <div class="pm-field">
          <label class="pm-label" for="ai-prompt">What should this post be about?</label>
          <textarea class="pm-input" id="ai-prompt" data-ai-prompt rows="4" placeholder="e.g. A beginner's guide to self-hosting email — friendly tone, ~800 words, with a short FAQ."></textarea>
        </div>

        <!-- Shape: the controls most authors change per draft, open by default. -->
        <details class="mon-acc" open>
          <summary class="mon-acc__sum">
            <span class="mon-acc__ic" aria-hidden="true">&#9998;</span>
            <span class="mon-acc__head"><span class="mon-acc__title">Shape the draft</span><span class="mon-acc__sub">Format, tone, length and who it is for</span></span>
            <span class="mon-chip mon-chip--off" data-ai-shape-chip>○ defaults</span>
            <svg class="mon-acc__chev" viewBox="0 0 20 20" width="16" height="16" fill="none" aria-hidden="true"><path d="M6 8l4 4 4-4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </summary>
          <div class="mon-acc__body">
            <div class="ai-grid">
              <div class="pm-field">
                <label class="pm-label" for="ai-shape">Format</label>
                <select class="pm-input" id="ai-shape" data-ai-shape>
                  <option value="post">Full blog post</option>
                  <option value="outline">Outline only</option>
                  <option value="howto">Step-by-step how-to</option>
                  <option value="listicle">Numbered list article</option>
                  <option value="faq">Question &amp; answer</option>
                </select>
              </div>
              <div class="pm-field">
                <label class="pm-label" for="ai-tone">Tone</label>
                <select class="pm-input" id="ai-tone" data-ai-tone>
                  <option value="">Model default</option>
                  <option value="neutral">Neutral</option>
                  <option value="friendly">Friendly</option>
                  <option value="conversational">Conversational</option>
                  <option value="professional">Professional</option>
                  <option value="technical">Technical</option>
                  <option value="persuasive">Persuasive</option>
                </select>
              </div>
              <div class="pm-field">
                <label class="pm-label" for="ai-length">Length</label>
                <select class="pm-input" id="ai-length" data-ai-length>
                  <option value="">Model default</option>
                  <option value="short">Short — 300–500 words</option>
                  <option value="medium">Medium — 700–900 words</option>
                  <option value="long">Long — 1200–1600 words</option>
                  <option value="exact">Exact word count…</option>
                </select>
              </div>
              <div class="pm-field" data-ai-words-field hidden>
                <label class="pm-label" for="ai-words">Target words</label>
                <input class="pm-input" id="ai-words" type="number" min="100" max="4000" step="50" value="800" data-ai-words>
              </div>
              <div class="pm-field">
                <label class="pm-label" for="ai-audience">Written for <span class="muted">(optional)</span></label>
                <input class="pm-input" id="ai-audience" type="text" maxlength="80" placeholder="e.g. small-business owners, new self-hosters" data-ai-audience>
              </div>
              <div class="pm-field">
                <label class="pm-label" for="ai-language">Language <span class="muted">(optional)</span></label>
                <input class="pm-input" id="ai-language" type="text" maxlength="80" placeholder="Model default" data-ai-language>
              </div>
              <div class="pm-field">
                <label class="pm-label" for="ai-keyword">Search phrase to rank for <span class="muted">(optional)</span></label>
                <input class="pm-input" id="ai-keyword" type="text" maxlength="80" placeholder="e.g. self-hosted email server" data-ai-keyword>
                <p class="pm-help">Used naturally in the title, the opening answer and one section heading — not stuffed.</p>
              </div>
            </div>
          </div>
        </details>

        <!-- Engine: set once and rarely touched, so it starts collapsed. -->
        <details class="mon-acc">
          <summary class="mon-acc__sum">
            <span class="mon-acc__ic" aria-hidden="true">&#9881;</span>
            <span class="mon-acc__head"><span class="mon-acc__title">Model &amp; provider</span><span class="mon-acc__sub" data-ai-engine-sub>Which model writes it</span></span>
            <span class="mon-chip mon-chip--off" data-ai-engine-chip>○ checking</span>
            <svg class="mon-acc__chev" viewBox="0 0 20 20" width="16" height="16" fill="none" aria-hidden="true"><path d="M6 8l4 4 4-4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </summary>
          <div class="mon-acc__body">
            <div class="ai-grid">
              <div class="pm-field">
                <label class="pm-label" for="ai-provider">Provider</label>
                <select class="pm-input" id="ai-provider" data-ai-provider></select>
              </div>
              <div class="pm-field">
                <label class="pm-label" for="ai-model-select">Model</label>
                <select class="pm-input" id="ai-model-select" data-ai-model-select></select>
              </div>
              <div class="pm-field">
                <label class="pm-label" for="ai-model">Or type a model name</label>
                <input class="pm-input" id="ai-model" type="text" data-ai-model placeholder="Provider default">
              </div>
              <div class="pm-field">
                <label class="pm-label" for="ai-temp">Creativity <span class="muted" data-ai-temp-out>model default</span></label>
                <input class="pm-input" id="ai-temp" type="range" min="0" max="20" step="1" value="0" data-ai-temp>
                <p class="pm-help">Left is predictable and factual, right is more inventive. Leave at the far left to use the model's own setting.</p>
              </div>
            </div>
            <p class="pm-help">Providers and keys are configured in VayuOS &rarr; API Keys. Only providers you have set up appear here.</p>
          </div>
        </details>

        <p class="pm-help">Every draft is written as structured HTML — one H1, scannable sections, key
          takeaways and an FAQ — so it reads well and can be quoted by search and answer engines.</p>
        <div class="ai-status" data-ai-msg role="status" aria-live="polite">The draft is inserted as editable blocks — always review before you publish.</div>
        <div class="pm-row">
          <button type="button" class="btn btn--primary btn--sm" data-ai-run>Generate draft</button>
          <button type="button" class="btn btn--ghost btn--sm" data-ai-cancel>Cancel</button>
        </div>
      </div>
    </div>
  </div>
  <div class="editor-settings-backdrop" data-editor-settings-backdrop hidden></div>
  <aside class="editor-settings" data-editor-settings hidden role="dialog" aria-modal="true" aria-label="Post settings">
    <div class="editor-settings-head">
      <span class="editor-settings-title">Post settings</span>
      <button type="button" class="btn--icon" data-editor-settings-close aria-label="Close post settings">✕</button>
    </div>
    <div class="editor-settings-body">
      <div class="pm-field">
        <label class="pm-label">Feature image</label>
        <div class="pm-feature" data-pm-feature>
          <img class="pm-feature-preview" data-pm-feature-preview alt="" hidden>
          <div class="pm-feature-empty" data-pm-feature-empty>No feature image</div>
        </div>
        <div class="pm-row">
          <input class="pm-input" type="text" data-pm-feature-image placeholder="Image URL or upload…">
          <button type="button" class="btn btn--ghost btn--xs" data-pm-feature-upload>Upload</button>
          <button type="button" class="btn btn--ghost btn--xs" data-pm-feature-remove>Remove</button>
        </div>
        <input type="file" accept="image/*" data-pm-feature-file hidden>
      </div>

      <div class="pm-field">
        <label class="pm-label" for="pm-slug">Post URL</label>
        <div class="pm-row">
          <span class="pm-prefix" data-pm-slug-prefix>/</span>
          <input class="pm-input" id="pm-slug" type="text" data-pm-slug placeholder="post-url-slug">
          <button type="button" class="btn btn--ghost btn--xs" data-pm-slug-apply>Update</button>
        </div>
        <div class="pm-hint text-xs muted" data-pm-slug-status>The slug is set automatically from the title on first save.</div>
      </div>

      <div class="pm-field">
        <label class="pm-label" for="pm-publish-date">Publish date</label>
        <input class="pm-input" id="pm-publish-date" type="datetime-local" data-pm-publish-date>
      </div>

      <div class="pm-field">
        <label class="pm-label" for="pm-author">Author</label>
        <select class="pm-input" id="pm-author" data-pm-author>` + authorOptions + `</select>
        <div class="pm-hint text-xs muted">Attributed automatically to whoever creates the post; change it here to credit a different author.</div>
      </div>

      <div class="pm-field">
        <label class="pm-label" for="pm-excerpt">Excerpt</label>
        <textarea class="pm-input pm-textarea" id="pm-excerpt" rows="3" maxlength="300" data-pm-excerpt placeholder="A short summary used on cards, feeds, and search results…"></textarea>
        <div class="pm-hint text-xs muted"><span data-pm-excerpt-count>0</span>/300 · falls back to the first lines of the post when left blank.</div>
      </div>

      <div class="pm-field">
        <label class="pm-label">Tags</label>
        <div class="pm-tags" data-pm-tags-list></div>
        <input class="pm-input" type="text" data-pm-tags-input placeholder="Type a tag and press Enter…">
      </div>

      <div class="pm-field pm-toggles">
        <label class="pm-check"><input type="checkbox" data-pm-featured> <span>Feature this post</span></label>
        <label class="pm-check"><input type="checkbox" data-pm-is-page> <span>Turn this post into a page</span></label>
        <div class="pm-hint text-xs muted">Pages are standalone (no date, tags, or author) and are kept out of the home feed, RSS, and sitemap.</div>
      </div>

      <details class="pm-group" open>
        <summary class="pm-group-title">Meta data &amp; SEO</summary>
        <div class="pm-field">
          <label class="pm-label" for="pm-meta-title">SEO title</label>
          <input class="pm-input" id="pm-meta-title" type="text" maxlength="120" data-pm-meta-title placeholder="Custom title for search engines…">
          <div class="pm-hint text-xs muted"><span data-pm-meta-title-count>0</span>/120 · defaults to the post title.</div>
        </div>
        <div class="pm-field">
          <label class="pm-label" for="pm-meta-description">SEO description</label>
          <textarea class="pm-input pm-textarea" id="pm-meta-description" rows="3" maxlength="300" data-pm-meta-description placeholder="Custom description for search engines…"></textarea>
          <div class="pm-hint text-xs muted"><span data-pm-meta-description-count>0</span>/300 · defaults to the excerpt.</div>
        </div>
        <div class="pm-field">
          <label class="pm-label">Search preview</label>
          <div class="seo-snippet" data-seo-snippet aria-label="Google search result preview">
            <div class="seo-snippet__url" data-seo-snippet-url></div>
            <div class="seo-snippet__title" data-seo-snippet-title></div>
            <div class="seo-snippet__desc" data-seo-snippet-desc></div>
          </div>
          <div class="pm-hint text-xs muted">Approximate Google result. Titles over ~60 and descriptions over ~160 characters may be truncated.</div>
        </div>
        <div class="pm-field">
          <label class="pm-label" for="pm-canonical">Canonical URL</label>
          <input class="pm-input" id="pm-canonical" type="url" data-pm-canonical placeholder="https://example.com/original-post">
          <div class="pm-hint text-xs muted">Set when this content was first published elsewhere.</div>
        </div>
      </details>

      <details class="pm-group">
        <summary class="pm-group-title">Social sharing cards</summary>
        <div class="pm-subhead">Facebook / Open Graph</div>
        <div class="pm-field"><label class="pm-label" for="pm-og-title">Title</label><input class="pm-input" id="pm-og-title" type="text" data-pm-og-title placeholder="Defaults to the SEO title…"></div>
        <div class="pm-field"><label class="pm-label" for="pm-og-description">Description</label><textarea class="pm-input pm-textarea" id="pm-og-description" rows="2" data-pm-og-description placeholder="Defaults to the SEO description…"></textarea></div>
        <div class="pm-field"><label class="pm-label" for="pm-og-image">Image URL</label><input class="pm-input" id="pm-og-image" type="text" data-pm-og-image placeholder="Defaults to the feature image…"></div>
        <div class="pm-subhead">Twitter / X</div>
        <div class="pm-field"><label class="pm-label" for="pm-twitter-title">Title</label><input class="pm-input" id="pm-twitter-title" type="text" data-pm-twitter-title placeholder="Defaults to the Open Graph title…"></div>
        <div class="pm-field"><label class="pm-label" for="pm-twitter-description">Description</label><textarea class="pm-input pm-textarea" id="pm-twitter-description" rows="2" data-pm-twitter-description placeholder="Defaults to the Open Graph description…"></textarea></div>
        <div class="pm-field"><label class="pm-label" for="pm-twitter-image">Image URL</label><input class="pm-input" id="pm-twitter-image" type="text" data-pm-twitter-image placeholder="Defaults to the Open Graph image…"></div>
      </details>
    </div>
  </aside>
</div>`
}
