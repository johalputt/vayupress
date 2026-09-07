// SPDX-License-Identifier: Apache-2.0

package main

// admin_os_scoped_content.go — one site's own posts and pages (ADR-0154 D4).
//
// This is the tool the report was actually about: "I want to control their
// website or their blog." Before this, a hosted domain's only content control
// anywhere in the console was a single box reading "move a published post to
// this site by its slug" — no list, no drafts, no way to write one for it.
// `articles.domain_id` has existed since migration 060 and the public site has
// routed on it the whole time; nothing surfaced it.
//
// It deliberately does NOT fork the editor. A second content pipeline would be a
// second place for every future content change to be forgotten, which is the
// mistake ADR-0154 D1 exists to stop repeating. Writing opens the one editor,
// with this site pre-selected; the console owns the listing and the ownership
// moves.

import (
	"encoding/json"
	"html"
	htmpl "html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/domain"
	"github.com/johalputt/vayupress/internal/render"
	"github.com/johalputt/vayupress/internal/seo"
)

// scopedContentLimit bounds the listing. A console page is for operating a site,
// not for paging through an archive, and an unbounded list on a busy domain is a
// slow page nobody scrolls to the end of.
const scopedContentLimit = 200

// handleOSScopedContent lists everything this site owns.
func (a *App) handleOSScopedContent(w http.ResponseWriter, r *http.Request) {
	nonce := render.CSPNonce(r)
	cfg := a.getOSSettings(r.Context())
	d, ok := osScopedDomain(r)
	if !ok {
		http.Redirect(w, r, "/os/domains", http.StatusSeeOther)
		return
	}
	csrfTokenFor(w, r)

	var items []dbpkg.Article
	if a.articles != nil {
		items, _ = a.articles.ListOwnedBy(r.Context(), d.ID, scopedContentLimit)
	}

	body := scopedContentPage(d, items) + scopedContentScript(nonce)
	writeOSHTML(w, r, adminOSLayout(nonce, "Content · "+d.Host, "optimize", cfg, htmpl.HTML(body)))
}

func scopedContentPage(d domain.Domain, items []dbpkg.Article) string {
	esc := html.EscapeString
	var b strings.Builder

	posts, pages, drafts := 0, 0, 0
	for _, it := range items {
		if it.IsPage {
			pages++
		} else {
			posts++
		}
		if it.Status == "draft" {
			drafts++
		}
	}

	b.WriteString(`<div id="scoped-ctx" data-id="` + esc(d.ID) + `" hidden></div>`)
	b.WriteString(`<div class="page-header"><h1>Posts &amp; pages</h1>` +
		`<div class="page-actions">` +
		`<button type="button" class="btn btn--primary btn--sm" data-scoped-new>Write for this site</button>` +
		`<a class="btn btn--ghost btn--sm" href="/os/d/` + esc(d.ID) + `">← ` + esc(d.Host) + `</a>` +
		`<span id="scoped-content-status" class="text-sm muted" role="status" aria-live="polite"></span>` +
		`</div></div>`)
	b.WriteString(`<p class="page-sub">Everything owned by <b>` + esc(d.Host) + `</b>. Drafts are included — an ` +
		`unpublished post is the one that needs attention, and the public listing hides them by design.</p>`)

	b.WriteString(`<div class="stat-grid">`)
	b.WriteString(osStatTile("Posts", strconv.Itoa(posts), ""))
	b.WriteString(osStatTile("Pages", strconv.Itoa(pages), ""))
	draftTone := ""
	if drafts > 0 {
		draftTone = "warn"
	}
	b.WriteString(osStatTile("Drafts", strconv.Itoa(drafts), draftTone))
	b.WriteString(osStatTile("Total", strconv.Itoa(len(items)), ""))
	b.WriteString(`</div>`)

	// ── The bands, as collapsible details (house style §11) ──────────────────
	b.WriteString(`<div class="section-head"><span class="section-head__title">This site's content</span>` +
		`<span class="section-head__hint">Ownership decides which site serves a post</span></div>`)
	b.WriteString(`<div class="mon-stack">`)

	var owned strings.Builder
	if len(items) >= scopedContentLimit {
		// Never truncate in silence. A list that stops at 200 and says nothing
		// reads as "this site has 200 items", which is a number the page made up.
		owned.WriteString(`<div class="card"><p class="text-sm muted">Showing the ` +
			strconv.Itoa(scopedContentLimit) + ` most recently updated items. This site has more; the ` +
			`full archive is on the site itself.</p></div>`)
	}

	if len(items) == 0 {
		owned.WriteString(`<div class="card"><p class="text-sm muted">Nothing is published on this site yet. ` +
			`<b>Write for this site</b> opens the editor with ` + esc(d.Host) + ` already selected, so what you ` +
			`write is born here rather than being moved afterwards. You can also move an existing post across ` +
			`with the box below.</p></div>`)
	} else {
		owned.WriteString(`<div class="card"><div class="table-wrap"><table class="table"><thead><tr>` +
			`<th>Title</th><th>Kind</th><th>Status</th><th>Updated</th><th>Actions</th></tr></thead><tbody>`)
		for _, it := range items {
			kind := "Post"
			if it.IsPage {
				kind = "Page"
			}
			state := `<span class="badge badge--ok">published</span>`
			if it.Status == "draft" {
				state = `<span class="badge badge--warn">draft</span>`
			}
			live := ""
			if it.Status != "draft" {
				live = ` · <a href="` + esc(seo.Origin(d.Host)) + `/blog/` + esc(url.PathEscape(it.Slug)) +
					`" target="_blank" rel="noopener noreferrer">View ↗</a>`
			}
			owned.WriteString(`<tr><td><a href="/os/editor/` + esc(url.PathEscape(it.Slug)) + `">` +
				esc(it.Title) + `</a><div class="text-xs muted mono">` + esc(it.Slug) + `</div></td>` +
				`<td>` + kind + `</td><td>` + state + `</td>` +
				`<td class="text-xs muted">` + esc(it.UpdatedAt.Format("2006-01-02")) + `</td>` +
				`<td class="text-xs"><a href="/os/editor/` + esc(url.PathEscape(it.Slug)) + `">Edit</a>` + live +
				` · <button type="button" class="btn btn--ghost btn--sm" data-scoped-release data-slug="` +
				esc(it.Slug) + `">Move to primary</button></td></tr>`)
		}
		owned.WriteString(`</tbody></table></div></div>`)
	}

	ownedChip := `<span class="mon-chip mon-chip--off">nothing yet</span>`
	if len(items) > 0 {
		ownedChip = `<span class="mon-chip mon-chip--on">` + strconv.Itoa(len(items)) + ` items</span>`
	}
	b.WriteString(monAcc("📚", "Owned by this site", "Newest first", ownedChip, true, owned.String()))

	// Moving a post IN. The counterpart ("move to primary") is per-row above.
	moveBody := `<div class="card">
  <p class="text-sm muted">A post belongs to exactly one site. Moving it here removes it from wherever it was —
    its old site stops serving it the moment this saves, and its address changes to this domain's.</p>
  <div class="form-grid">
    <label class="field"><span class="field-label">Post slug</span>
      <input type="text" id="scoped-assign-slug" class="input" placeholder="my-post-slug" autocomplete="off" spellcheck="false">
      <span class="field-hint">The slug as it appears in the post's address, not its title.</span></label>
  </div>
  <div class="vm-row"><button type="button" class="btn btn--primary btn--sm" data-scoped-assign>Move to ` + esc(d.Host) + `</button></div>
</div>`
	b.WriteString(monAcc("↔️", "Move a post to this site", "Ownership decides which site serves it",
		`<span class="mon-chip mon-chip--on">by slug</span>`, false, moveBody))

	b.WriteString(`</div>`) // mon-stack
	return b.String()
}

func scopedContentScript(nonce string) string {
	return `<script nonce="` + nonce + `">
(function(){'use strict';
function csrf(){var m=document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);return m?decodeURIComponent(m[1]):'';}
var node=document.getElementById('scoped-ctx');
var ID=node?node.getAttribute('data-id'):'';
if(!ID)return;
var st=document.getElementById('scoped-content-status');
function say(t){if(st)st.textContent=t;}
function move(slug,target,btn){
  if(btn)btn.disabled=true; say('Moving…');
  fetch('/os/d/'+encodeURIComponent(ID)+'/api/content/move',{method:'POST',
    headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},
    body:JSON.stringify({slug:slug,to:target})})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
    .then(function(res){
      if(res.ok){say('Moved ✓ — reloading');window.location.reload();return;}
      if(btn)btn.disabled=false; say((res.j&&res.j.message)||'Could not move that post');})
    .catch(function(e){if(btn)btn.disabled=false; say('Error: '+e);});
}
var mk=document.querySelector('[data-scoped-new]');
if(mk)mk.addEventListener('click',function(){
  mk.disabled=true; say('Creating a draft on this site…');
  fetch('/os/d/'+encodeURIComponent(ID)+'/api/content/new',{method:'POST',
    headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:'{}'})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
    .then(function(res){
      if(res.ok&&res.j&&res.j.slug){window.location='/os/editor/'+encodeURIComponent(res.j.slug);return;}
      mk.disabled=false; say((res.j&&res.j.message)||'Could not create a draft');})
    .catch(function(e){mk.disabled=false; say('Error: '+e);});
});
var add=document.querySelector('[data-scoped-assign]');
if(add)add.addEventListener('click',function(){
  var el=document.getElementById('scoped-assign-slug');
  var slug=el?el.value.trim():'';
  if(!slug){say('Enter the post slug.');return;}
  move(slug,'site',add);
});
document.querySelectorAll('[data-scoped-release]').forEach(function(b){
  b.addEventListener('click',function(){
    var slug=b.getAttribute('data-slug');
    vpConfirm({title:'Release to primary',message:'Move '+slug+' to the primary site? This site stops serving it.',confirm:'Release'},function(){
      move(slug,'primary',b);
    });
  });
});
})();
</script>`
}

// handleOSScopedContentNew creates an empty draft that is BORN on this site,
// then hands back its slug so the browser can open the one editor on it.
//
// The alternative was `/os/editor?domain={id}`, and a test caught it: the editor
// does not read that parameter, so the link would have created the post on the
// PRIMARY from a page titled with the client's domain — the reported bug, in the
// code written to fix the reported bug. Creating here instead means the owning
// domain comes from the PATH and the editor needs to know nothing about domains
// at all, which is also why there is still exactly one editor.
//
// It creates a DRAFT: an empty post appearing live on a client's site because
// the operator clicked "write" and then closed the tab is not a thing anyone
// would choose.
func (a *App) handleOSScopedContentNew(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "admin role required", "")
		return
	}
	if a.articles == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "article service not initialised", "")
		return
	}
	d, ok := osScopedDomain(r)
	if !ok {
		writeAPIError(w, r, http.StatusNotFound, "unknown-domain", "no such site", "")
		return
	}

	title := "Untitled"
	slug := a.uniqueArticleSlug(r.Context(), title)
	// Article validation rejects empty content, so seed a single space: it
	// renders to nothing and the author replaces it immediately.
	// Draft-first (Wave 1): the status travels inside the queued insert itself,
	// so the post is never briefly live between enqueue and the old follow-up
	// UPDATE — and a failed follow-up can no longer leave it published.
	if _, err := a.articles.CreateDraft(r.Context(), title, slug, " ", nil); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "create-failed", err.Error(), "")
		return
	}
	if err := a.articles.SetDomain(r.Context(), slug, d.ID); err != nil {
		// The post exists but landed on the primary. Say so rather than
		// returning a slug that would open an editor for somebody else's site.
		writeAPIError(w, r, http.StatusInternalServerError, "assign-failed",
			"the draft was created but could not be assigned to this site: "+err.Error(), "")
		return
	}
	render.CachePurgeAll()
	dbpkg.AuditLog("vayudomains.content.new", dbpkg.AuditActor(r), d.Host, slug)
	writeJSON(w, r, http.StatusOK, map[string]any{"status": "ok", "slug": slug, "host": d.Host})
}

// handleOSScopedContentMove changes which site owns one post.
//
// The destination is expressed as "site" or "primary" and resolved HERE against
// the domain in the PATH — never as a domain id from the body. A caller cannot
// name a third site, so this endpoint cannot be used to move a post between two
// domains neither of which is the one whose page the operator is on.
func (a *App) handleOSScopedContentMove(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "admin role required", "")
		return
	}
	if a.articles == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "article service not initialised", "")
		return
	}
	d, ok := osScopedDomain(r)
	if !ok {
		writeAPIError(w, r, http.StatusNotFound, "unknown-domain", "no such site", "")
		return
	}
	var body struct {
		Slug string `json:"slug"`
		To   string `json:"to"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024)).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request", "invalid JSON", "")
		return
	}
	slug := strings.TrimSpace(body.Slug)
	if slug == "" {
		writeAPIError(w, r, http.StatusBadRequest, "validation_error", "a post slug is required", "")
		return
	}

	// Two destinations, both derived from the path. "" is the primary's sentinel
	// throughout this codebase; the request never supplies a domain id.
	var target, label string
	switch body.To {
	case "site", "":
		target, label = d.ID, d.Host
	case "primary":
		target, label = "", "the primary site"
	default:
		writeAPIError(w, r, http.StatusBadRequest, "validation_error",
			"a post can only be moved to this site or to the primary", "")
		return
	}

	if err := a.articles.SetDomain(r.Context(), slug, target); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "move-failed", err.Error(), "")
		return
	}
	// The post just changed owner, so both sites' cached pages are now wrong.
	// Same purge the older assign endpoint does: reassignment touches no
	// search-indexed field, so the engine snapshot is unchanged and only the
	// per-domain client-index memo needs clearing for search to re-scope.
	render.CachePurgeAll()
	purgeDomainSearchIndex()
	dbpkg.AuditLog("vayudomains.content.move", dbpkg.AuditActor(r), d.Host, slug+" → "+label)
	writeJSON(w, r, http.StatusOK, map[string]any{"status": "ok", "slug": slug, "owner": label})
}
