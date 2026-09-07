// SPDX-License-Identifier: Apache-2.0

package main

// admin_os_domains.go — VayuOS "Domains" surface: the VayuDomains registry
// (Stage 1). It lists every hostname this binary serves, lets the operator add
// or remove secondary domains and choose what each one serves, and records a
// per-domain TLS state that later stages will provision automatically.
//
// Stage 1 scope is deliberately narrow: the registry is authoritative for host
// resolution, but content/mail/member scoping per domain ships in later stages.
// The page says so plainly so an operator is never surprised by what a
// newly-added domain does (and does not yet) serve.
//
// CSP posture matches the rest of VayuOS: no inline styles, the single inline
// <script> carries the per-request nonce, every dynamic string is escaped.

import (
	"encoding/json"
	"html"
	htmpl "html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/johalputt/vayupress/internal/config"
	"github.com/johalputt/vayupress/internal/domain"
	"github.com/johalputt/vayupress/internal/render"
	"github.com/johalputt/vayupress/internal/users"
)

// isPendingTorSite reports whether a host is a just-added Tor site still waiting
// for the parent to mint and assign its .onion (ADR-0141). Such rows are shown as
// "Minting .onion…" and drive the page's auto-refresh-while-pending.
func isPendingTorSite(host string) bool {
	return strings.HasPrefix(host, torSitePending) && strings.HasSuffix(host, ".local")
}

// siteTypeOptions is the operator-facing catalogue of what "/" can serve for a
// domain, with a short description of the current support level.
var siteTypeOptions = []struct{ Value, Label, Note string }{
	{domain.SiteBlog, "Blog", "Serves the blog at / (the classic VayuPress site)."},
	{domain.SiteBusiness, "Business site", "Business site at /, blog at blog.<host>."},
	{domain.SiteBusinessSubpath, "Business + /blog", "Business site at /, blog at /blog."},
	{domain.SiteStatic, "Static bundle", "Reserved — served in a later stage."},
	{domain.SiteMailOnly, "Mail only", "No public site; branded mail only (later stage)."},
}

func siteTypeLabel(v string) string {
	for _, o := range siteTypeOptions {
		if o.Value == v {
			return o.Label
		}
	}
	return v
}

// toggleLabelFor / toggleStatusFor describe the enable/disable action for a
// secondary domain row: an active row offers Disable, a disabled row Enable.
func toggleLabelFor(d domain.Domain) string {
	if d.Status != domain.StatusActive {
		return "Enable"
	}
	return "Disable"
}

func toggleStatusFor(d domain.Domain) string {
	if d.Status != domain.StatusActive {
		return domain.StatusActive
	}
	return domain.StatusDisabled
}

// handleOSDomains renders the domain registry management page.
func (a *App) handleOSDomains(w http.ResponseWriter, r *http.Request) {
	nonce := render.CSPNonce(r)
	cfg := a.getOSSettings(r.Context())

	csrfTokenFor(w, r)

	var domains []domain.Domain
	if a.domains != nil {
		if list, err := a.domains.List(r.Context()); err == nil {
			domains = list
		}
	}

	// Per-domain article counts (VayuDomains Stage 2 — content ownership).
	counts := map[string]int{}
	if a.articles != nil {
		if c, err := a.articles.CountsByDomain(r.Context()); err == nil {
			counts = c
		}
	}

	// Per-domain mailbox counts (VayuDomains Stage 3a — mail-domain foundation).
	// Read-only reporting: mailboxes are keyed by full address, so the host is
	// derived. Delivery/auth stays untouched until Stage 3b.
	mailCounts := map[string]int{}
	mailOn := false
	if a.vayuMail != nil {
		mailOn = a.vayuMail.Config().Enabled
		if a.vayuMail.Accounts() != nil {
			if c, err := a.vayuMail.Accounts().CountsByHost(r.Context()); err == nil {
				mailCounts = c
			}
		}
	}

	// Per-domain member counts (VayuDomains Stage 4 — member attribution). Keyed by
	// the registry domain id ("" = primary), like the article counts.
	memberCounts := map[string]int{}
	if a.members != nil {
		if c, err := a.members.CountsByDomain(r.Context()); err == nil {
			memberCounts = c
		}
	}

	// The host the operator is currently browsing from — surfaced so it is
	// obvious which registered domain served this very page.
	viewingHost := ""
	if d, ok := activeDomain(r); ok {
		viewingHost = d.Host
	}

	// In the Tor world (OnionMode) a domain is a ".onion" the operator can't type —
	// it is minted for them. So swap the clearnet "Add a domain" host form for the
	// one-click "Add Tor site" picker, and auto-refresh while any site is still
	// waiting for its onion to land.
	onion := config.Cfg.OnionMode
	addForm := domainsAddForm()
	pending := false
	if onion {
		addForm = torSitesAddForm()
		for _, d := range domains {
			if !d.IsPrimary && isPendingTorSite(d.Host) {
				pending = true
				break
			}
		}
	}

	// The list is a premium, animated card grid; per-domain branding/content
	// editing moved to each site's own console (/os/d/{id}), surfaced from
	// the Optimize hub, so this page stays a clean add / list / remove surface.
	body := domainsHeader(domains, viewingHost) +
		domainsCards(domains, counts, mailCounts, memberCounts, mailOn) +
		addForm +
		domainsScript(nonce) +
		torSitesScript(nonce, onion, pending)

	writeOSHTML(w, r, adminOSLayout(nonce, "Domains", "domains", cfg, htmpl.HTML(body)))
}

// domainsHeader renders the list header in the Monetization house style
// (ADR-0154 D5): four tiles answering "what is the state of my sites", one lede,
// and the staging detail folded into an accordion.
//
// It replaced a header carrying a single 150-word `card--info` paragraph about
// rollout stages, manual holds and provisioning helpers. Every sentence in it was
// true and none of it answered the question an operator opens this page with,
// which is "are my sites up". Reference material an operator reads once does not
// belong permanently above the thing they came for.
func domainsHeader(domains []domain.Domain, viewingHost string) string {
	total, live, held, uncertified := len(domains), 0, 0, 0
	for _, d := range domains {
		if d.Status == domain.StatusActive {
			live++
		}
		if !d.IsPrimary && !d.IsSyncApproved() {
			held++
		}
		if !d.IsPrimary && d.IsSyncApproved() &&
			d.TLSState != domain.TLSActive && d.TLSState != domain.TLSPrimary {
			uncertified++
		}
	}

	sub := "Every site this install serves. Open one to operate it — its content, settings, theme, SEO and visitors are its own."
	if viewingHost != "" {
		sub += ` You are reading this from <strong>` + html.EscapeString(viewingHost) + `</strong>.`
	}

	var b strings.Builder
	b.WriteString(`<div class="page-header"><h1>Sites</h1>` +
		`<div class="page-actions"><a class="btn btn--ghost btn--sm" href="/os/dns">Domains &amp; DNS</a>` +
		`<span id="dom-status" class="text-sm muted" role="status" aria-live="polite"></span></div></div>`)
	b.WriteString(`<p class="page-sub">` + sub + `</p>`)

	// A configuration fault that decides which server block answers for a
	// hostname belongs above the site list, not in a warn-level log line. Empty
	// on a healthy install, so this costs nothing on the overwhelming majority
	// of page views (ADR-0157).
	b.WriteString(nginxConfigHealthCard(inspectNginxSitesEnabled(nginxSitesEnabled)))

	b.WriteString(`<div class="vm-stats">`)
	b.WriteString(vmStatTile(strconv.Itoa(total), "Sites", ""))
	b.WriteString(vmStatTile(strconv.Itoa(live), "Enabled", ""))
	heldTone := ""
	if held > 0 {
		heldTone = "warn"
	}
	b.WriteString(vmStatTile(strconv.Itoa(held), "On hold", heldTone))
	certTone := ""
	if uncertified > 0 {
		certTone = "warn"
	}
	b.WriteString(vmStatTile(strconv.Itoa(uncertified), "No certificate", certTone))
	b.WriteString(`</div>`)

	// The reference material, available and not shouting.
	b.WriteString(`<div class="mon-stack">`)
	b.WriteString(monAcc("📘", "How adding a site works", "Register, point DNS, approve, provision",
		`<span class="mon-chip mon-chip--off">read once</span>`, false,
		`<div class="card"><p class="text-sm muted">Adding a site only <strong>registers</strong> it — nothing is
    provisioned automatically, and a registered site serves nothing until it has a certificate. The order is:
    add it here, point its DNS at this server, approve it (<strong>Sync now</strong>, or the switch on the site's
    own console), then run <strong>Provision subdomains</strong> on <a href="/os/dns">Domains &amp; DNS</a>. That
    last step is a root-side helper — this service runs unprivileged and cannot obtain a certificate or reload
    nginx itself. It also runs daily, so a record you point later is picked up without you doing anything.</p>
  <p class="text-sm muted"><strong>Nothing restarts and nothing goes down.</strong> Provisioning obtains the
    certificate, writes the vhost and reloads nginx; the running server then picks the new domain up from its own
    registry <strong>within 30 seconds</strong>. It used to restart the service at the end of every run, which
    meant a full outage — nginx has no queue in front of the app, so every second of that restart was a 502 for
    every visitor on every site. If a freshly certified domain does not answer immediately, that half-minute is
    why; it is not a fault to chase.</p>
  <p class="text-sm muted">A site on <strong>manual hold</strong> is skipped by every provisioning helper. That is
    what the hold is for, and it is why a held site never gets a certificate.</p></div>`))
	b.WriteString(`</div>`)
	return b.String()
}

// domainsCards renders the registry as a premium, animated card grid (replacing
// the Stage-1 table): each hostname is a card carrying its identity, live
// content/member/mail counts, sync/TLS/status pills and lifecycle actions. Each
// secondary card links to its own console (/os/d/{id}), which is
// also surfaced from the Optimize hub, so the operator controls every part of a
// site from one place. Shared by both worlds — in the Tor world the hosts are
// .onion addresses and the same cards render unchanged.
func domainsCards(domains []domain.Domain, counts, mailCounts, memberCounts map[string]int, mailOn bool) string {
	if len(domains) == 0 {
		return `<div class="card"><div class="empty-title">No domains registered yet</div>
<div class="empty-sub">The primary domain is seeded automatically once DOMAIN is configured. Add a secondary domain below.</div></div>`
	}
	var cards strings.Builder
	held := 0 // secondary domains parked on manual hold (for the bulk action)
	for _, d := range domains {
		if !d.IsPrimary && !d.IsSyncApproved() {
			held++
		}
		// Content/member counts are keyed by domain id; the primary owns "".
		key := d.ID
		if d.IsPrimary {
			key = ""
		}

		cardCls := "domain-card"
		badge := ""
		if d.IsPrimary {
			cardCls += " domain-card--primary"
			badge = ` <span class="pill pill--accent">Primary</span>`
		}

		// A just-added Tor site has a placeholder host until the parent mints its
		// .onion; show that plainly rather than the internal placeholder hostname.
		hostText := `<span class="domain-card__host">` + html.EscapeString(d.Host) + badge + `</span>`
		if !d.IsPrimary && isPendingTorSite(d.Host) {
			hostText = `<span class="domain-card__host"><span class="pill pill--muted">Minting .onion…</span></span>`
		}

		statusPill := `<span class="pill pill--ok">Active</span>`
		if d.Status != domain.StatusActive {
			statusPill = `<span class="pill pill--muted">Disabled</span>`
		}
		tlsPill := `<span class="pill pill--muted">` + html.EscapeString(tlsLabel(d.TLSState)) + `</span>`
		// Sync (P5 manual gate): the primary is provisioned outside the registry.
		syncPill := ""
		if !d.IsPrimary {
			if d.IsSyncApproved() {
				syncPill = `<span class="pill pill--ok">Synced</span>`
			} else {
				syncPill = `<span class="pill pill--muted">Manual hold</span>`
			}
		}

		// Stat chips: content, members and mail (all derived read-only).
		stats := `<span class="domain-stat"><b>` + strconv.Itoa(counts[key]) + `</b> posts</span>` +
			`<span class="domain-stat"><b>` + strconv.Itoa(memberCounts[key]) + `</b> members</span>` +
			domainMailStat(d, mailCounts[strings.ToLower(d.Host)], mailOn)

		// Actions: the primary is managed from Website settings; secondary sites get
		// Manage (per-site editor), Sync, enable/disable and Remove.
		var actions string
		if d.IsPrimary {
			actions = `<a class="btn btn--ghost btn--sm" href="/os/website">Manage in Website</a>`
		} else {
			syncLabel, syncTarget := "Sync now", domain.SyncApproved
			if d.IsSyncApproved() {
				syncLabel, syncTarget = "Pause sync", domain.SyncHold
			}
			actions = `<a class="btn btn--primary btn--sm" href="/os/d/` + html.EscapeString(d.ID) + `">Open site</a>` +
				`<button type="button" class="btn btn--ghost btn--sm" data-dom-sync data-id="` + html.EscapeString(d.ID) + `" data-sync="` + syncTarget + `">` + syncLabel + `</button>` +
				`<button type="button" class="btn btn--ghost btn--sm" data-dom-toggle data-id="` + html.EscapeString(d.ID) + `" data-status="` + toggleStatusFor(d) + `">` + toggleLabelFor(d) + `</button>` +
				`<button type="button" class="btn btn--danger btn--sm" data-dom-delete data-id="` + html.EscapeString(d.ID) + `" data-host="` + html.EscapeString(d.Host) + `">Remove</button>`
		}

		cards.WriteString(`<div class="` + cardCls + `" data-dom-row>
  <div class="domain-card__head">
    <span class="domain-card__icon">` + iconDomains + `</span>
    <span class="domain-card__id">` + hostText + `
      <span class="domain-card__serves">` + html.EscapeString(siteTypeLabel(d.EffectiveSiteType())) + `</span>
    </span>
    ` + statusPill + `
  </div>
  <div class="domain-card__stats">` + stats + `</div>
  <div class="domain-card__meta">` + syncPill + tlsPill + `</div>
  <div class="domain-card__actions">` + actions + `</div>
</div>`)
	}
	// Bulk action: when one or more secondaries sit on manual hold, offer a single
	// "Sync all pending" that approves them together — the batch counterpart to
	// each card's "Sync now" (the helper still provisions out-of-process).
	bulk := ""
	if held > 0 {
		unit := "domains"
		if held == 1 {
			unit = "domain"
		}
		bulk = `<div class="vm-row mb-6">
  <button type="button" class="btn btn--primary btn--sm" data-dom-sync-all>Sync all pending (` + strconv.Itoa(held) + ` ` + unit + `)</button>
  <span id="dom-sync-all-status" class="text-sm muted" role="status" aria-live="polite"></span>
</div>`
	}
	return bulk + `<div class="domain-grid">` + cards.String() + `</div>`
}

// domainMailStat renders the mail chip for a domain card — the compact,
// card-friendly counterpart to mailCell. The primary carries the install's mail
// when the engine is on; a secondary opts in via mail_enabled; otherwise the
// chip reads "no mail". The mailbox count is derived read-only from the account
// store (VayuDomains Stage 3a).
func domainMailStat(d domain.Domain, n int, mailOn bool) string {
	switch {
	case d.IsPrimary:
		if !mailOn {
			return `<span class="domain-stat">no mail</span>`
		}
		return `<span class="domain-stat"><b>` + strconv.Itoa(n) + `</b> mailboxes</span>`
	case d.MailEnabled:
		return `<span class="domain-stat"><b>` + strconv.Itoa(n) + `</b> mailboxes</span>`
	default:
		return `<span class="domain-stat">no mail</span>`
	}
}

// handleOSDomainManage renders the per-site manager for one secondary domain —
// the "control every part of this site" surface reached from its card and from
// the Optimize hub's "Your websites" row. It carries the site's identity and
// live counts, a scoped branding editor (its own name / tagline / colours), a
// post-assignment box, lifecycle controls (sync / enable / remove) and shortcuts
// into Theme Studio and Website. Shared by both worlds. The primary site's
// identity is the global Website settings, so it is redirected there; an unknown
// id falls back to the registry list.
// handleOSDomainManage is the old per-site page, now a redirect.
//
// ADR-0154 D1: one address per site. This page and /os/d/{id} were two consoles
// for the same thing, and an operator had to learn which of them held which
// control. Worse, this one carried a row of buttons into the INSTALL-WIDE tools —
// Theme Studio, Website settings, Analytics, SEO — on a page titled "Manage
// site" for somebody's client, which is exactly how "my subdomain's controls
// show the main domain" happened. A permanent redirect rather than a deletion:
// the URL is in operators' bookmarks and in this console's own history.
func (a *App) handleOSDomainManage(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var found *domain.Domain
	if a.domains != nil {
		if list, err := a.domains.List(r.Context()); err == nil {
			for i := range list {
				if list[i].ID == id {
					d := list[i]
					found = &d
					break
				}
			}
		}
	}
	if found == nil {
		http.Redirect(w, r, "/os/domains", http.StatusSeeOther)
		return
	}
	if found.IsPrimary {
		http.Redirect(w, r, "/os/website", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/os/d/"+url.PathEscape(found.ID), http.StatusMovedPermanently)
}

func domainClientAccessCard(d domain.Domain, clients []users.User) string {
	esc := html.EscapeString

	existing := `<p class="text-sm muted">No client login yet. Until you issue one, nobody outside your
    team can see this site's settings, mailboxes or traffic.</p>`
	if len(clients) > 0 {
		rows := ""
		for _, c := range clients {
			seen := "never signed in"
			if c.LastLogin != nil {
				seen = "last seen " + c.LastLogin.Format("2006-01-02")
			}
			name := c.Name
			if strings.TrimSpace(name) == "" {
				name = "—"
			}
			rows += `<tr><td class="mono text-sm">` + esc(c.Email) + `</td><td class="text-sm">` +
				esc(name) + `</td><td class="text-sm muted">` + esc(seen) + `</td></tr>`
		}
		existing = `<table class="table"><thead><tr><th>Sign-in</th><th>Name</th><th>Activity</th></tr></thead><tbody>` +
			rows + `</tbody></table>`
	}

	return `<div class="card">
  <h2 class="card-title">Client access</h2>
  <p class="text-sm muted">A login for the person who owns <b>` + esc(d.Host) + `</b>. It reaches their site
    settings, their mailboxes and their own traffic — and nothing else on this install. It is not an
    editor and cannot see another client, your posts, or any technical page.</p>
  ` + existing + `
  <div class="form-grid">
    <label class="field"><span class="field-label">Their email</span>
      <input type="email" id="client-email" class="input" placeholder="owner@` + esc(d.Host) + `" autocomplete="off" spellcheck="false"></label>
    <label class="field"><span class="field-label">Their name</span>
      <input type="text" id="client-name" class="input" placeholder="Optional" autocomplete="off"></label>
    <label class="field"><span class="field-label">Starting password</span>
      <input type="text" id="client-password" class="input" placeholder="At least 8 characters" autocomplete="off" spellcheck="false">
      <span class="field-hint">Hand this over in person or by phone, never in the same email as the link.
        They are required to change it at first sign-in, so it stops being a password you know.</span></label>
  </div>
  <div class="vm-row">
    <button type="button" class="btn btn--primary" data-client-create>Issue login</button>
    <span id="client-status" class="text-sm muted" role="status" aria-live="polite"></span>
  </div>
</div>`
}

// domainAllowanceCard is the operator's control for how many branded mailboxes
// this hosted domain may have.
//
// It exists because the enforcement shipped without it. `POST
// /os/api/domains/{id}/allowance` refused mailbox creation at the cap from the
// day it landed, and nothing rendered an input for it — so the only way to grant
// a client their mailboxes was a hand-written API call. An enforced limit no
// operator can set is a limit that is always 0, which reads to the operator as
// "mailbox creation is broken".
//
// The used/granted pair is shown together deliberately. An operator setting this
// number is answering "how many more can they have?", and that question cannot
// be answered by the allowance alone.
func domainAllowanceCard(d domain.Domain, used int, mailOn bool) string {
	granted := d.Limits().Mailboxes

	// State in words before the input, because 0 is ambiguous on sight and the
	// wrong reading of it is the expensive one: an operator who assumes 0 means
	// "no limit set yet, so unlimited" will not understand why creation refuses.
	var state string
	switch {
	case !mailOn:
		state = `Mail is switched off for this install, so no mailbox can exist on this domain yet.`
	case granted == 0:
		state = `<b>No mailboxes granted.</b> Creation on this domain is refused until you grant some — ` +
			`0 means none, never unlimited.`
	case used >= granted:
		state = `<b>` + strconv.Itoa(used) + ` of ` + strconv.Itoa(granted) + ` used — the allowance is full.</b> ` +
			`The next mailbox on this domain will be refused until you raise it.`
	default:
		state = `<b>` + strconv.Itoa(used) + ` of ` + strconv.Itoa(granted) + ` used</b>, ` +
			strconv.Itoa(granted-used) + ` still available.`
	}

	return `<div class="card">
  <h2 class="card-title">Mailbox allowance</h2>
  <p class="text-sm muted">` + state + `</p>
  <p class="text-sm muted">Mailboxes are created by you, on request, from VayuMail — this only sets the ceiling.
    Lowering it below what is already in use does not delete anything; it stops the next one being made.</p>
  <div class="form-grid">
    <label class="field"><span class="field-label">Mailboxes granted</span>
      <input type="number" id="site-allowance" class="input" min="0" step="1" value="` +
		strconv.Itoa(granted) + `" autocomplete="off"></label>
  </div>
  <div class="vm-row">
    <button type="button" class="btn btn--primary" data-site-allowance-save>Save allowance</button>
    <span id="site-allowance-status" class="text-sm muted" role="status" aria-live="polite"></span>
  </div>
</div>`
}

// domainManageScript wires every control on a site's console.
//
// REWRITTEN, because the previous version did not parse.
//
// Three handlers were removed from it by text surgery when their markup was
// retired (ADR-0154 D3), and each deletion stopped at the first `});` after its
// marker — which, in a handler containing `.then(function(res){…});`, is an
// INNER closer. Every deletion therefore left its tail behind, and the script
// ended with orphan `});` lines that made the whole IIFE a syntax error.
//
// The consequence is the worst kind: a parse error binds NOTHING. Provision now,
// Issue login, Save allowance, sync, disable and remove were all inert on every
// site console — buttons that looked live, reported nothing, and did nothing.
// An operator pressing them saw exactly what they would see if the server were
// ignoring them, which is what sent a certificate investigation through five
// releases looking at systemd.
//
// A syntax gate now runs over every inline script in the codebase, because
// nothing else here can catch it: Go compiles a broken script perfectly, every
// test that asserted on this markup passed, and the CSP nonce was correct.
func domainManageScript(nonce string) string {
	return `<script nonce="` + nonce + `">
(function(){'use strict';
function csrf(){var m=document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);return m?decodeURIComponent(m[1]):'';}
var node=document.getElementById('dom-manage');
var ID=node?node.getAttribute('data-id'):'';
if(!ID)return;
function val(id){var e=document.getElementById(id);return e?e.value.trim():'';}
function set(id,t){var e=document.getElementById(id);if(e)e.textContent=t;}
function post(path,body,opts){
  var h={'X-CSRF-Token':csrf()};
  if(body!==null&&body!==undefined)h['Content-Type']='application/json';
  return fetch('/os/api/domains/'+encodeURIComponent(ID)+path,
    {method:'POST',headers:h,body:body===null||body===undefined?undefined:JSON.stringify(body)});
}

// Mailbox allowance. The field is a number input, but a browser hands back a
// string and an empty one parses to NaN — sending that would clear the
// allowance to 0 and silently revoke every mailbox the operator granted.
var aSave=document.querySelector('[data-site-allowance-save]');
if(aSave)aSave.addEventListener('click',function(){
  var raw=val('site-allowance');
  var n=parseInt(raw,10);
  if(raw===''||isNaN(n)||n<0){set('site-allowance-status','Enter a whole number, 0 or more');return;}
  aSave.disabled=true;set('site-allowance-status','Saving…');
  post('/allowance',{mailboxes:n})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
    .then(function(res){aSave.disabled=false;
      if(res.ok){set('site-allowance-status','Saved ✓ — reloading');window.location.reload();}
      else{set('site-allowance-status',(res.j&&res.j.message)||'Could not save the allowance');}})
    .catch(function(e){aSave.disabled=false;set('site-allowance-status','Error: '+e);});
});

// Client login. The password is typed by the operator, sent once, and the
// account is forced to change it at first sign-in.
var cNew=document.querySelector('[data-client-create]');
if(cNew)cNew.addEventListener('click',function(){
  var email=val('client-email'),name=val('client-name'),pw=val('client-password');
  if(!email){set('client-status','Enter the email they will sign in with');return;}
  if(pw.length<8){set('client-status','The starting password must be at least 8 characters');return;}
  cNew.disabled=true;set('client-status','Creating…');
  post('/client',{email:email,name:name,password:pw})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
    .then(function(res){cNew.disabled=false;
      if(res.ok){set('client-status','Created ✓ — reloading');window.location.reload();}
      else{set('client-status',(res.j&&res.j.message)||'Could not create the login');}})
    .catch(function(e){cNew.disabled=false;set('client-status','Error: '+e);});
});

// Provision now — the certificate control, on the page that reports the
// certificate. It reports the OUTCOME, not merely that it was asked for.
var pv=document.querySelector('[data-site-provision]');
if(pv)pv.addEventListener('click',function(){
  pv.disabled=true;set('site-cert-status','Requesting…');
  fetch('/os/api/provision/run',{method:'POST',headers:{'X-CSRF-Token':csrf()}})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
    .then(function(res){
      if(!res.ok){pv.disabled=false;set('site-cert-status',(res.j&&res.j.message)||'Could not request a run');return;}
      set('site-cert-status','Running…');
      watch(0);})
    .catch(function(e){pv.disabled=false;set('site-cert-status','Error: '+e);});
});
function watch(n){
  if(n>20){set('site-cert-status','Still running — reload in a moment, or see Domains & DNS for the log.');return;}
  setTimeout(function(){
    fetch('/os/api/provision/status',{headers:{'Accept':'application/json'}})
      .then(function(r){if(!r.ok)throw new Error('status '+r.status);return r.json();})
      .then(function(j){
        if(j&&j.pending){set('site-cert-status','Running…');watch(n+1);return;}
        var res=(j&&j.result)||{},d=res.details||'';
        if(d.indexOf('nginx-config-broken')>=0){pv.disabled=false;
          set('site-cert-status','nginx config was already invalid, so nothing ran.');return;}
        if(res.failed>0){pv.disabled=false;set('site-cert-status','Finished with '+res.failed+' problem(s): '+d);return;}
        if(res.ran===0){pv.disabled=false;set('site-cert-status','Finished, but provisioned nothing: '+d);return;}
        set('site-cert-status','Provisioned ✓ — reloading');
        window.location.reload();})
      .catch(function(e){pv.disabled=false;
        set('site-cert-status','Requested. Could not read the result ('+e.message+') — the run may still be going; reload the page for the log.');});
  },3000);
}

// Repair the certificate helpers, from the page that diagnosed the problem.
//
// It posts to the SAME endpoint the VayuShield row uses, rather than a second
// implementation: one control, one validation, one audit trail. The 409 is the
// one answer worth handling specially — it means the installed agent predates
// this capability, and the operator needs to upgrade the helper first. Reporting
// that as a generic failure would send them looking for a fault that is not one.
var rBtn=document.querySelector('[data-site-repair]');
if(rBtn)rBtn.addEventListener('click',function(){
  rBtn.disabled=true;set('site-cert-status','Requesting the repair…');
  fetch('/os/api/shield/fix',{method:'POST',
    headers:{'X-CSRF-Token':csrf(),'Content-Type':'application/x-www-form-urlencoded'},
    body:'fix=provisionhelpers'})
    .then(function(res){
      rBtn.disabled=false;
      if(res.status===409){set('site-cert-status',
        'The running helper is older than this repair. Open VayuShield, press Upgrade the helper, then try this again.');return;}
      if(!res.ok){set('site-cert-status','The repair could not be requested (status '+res.status+').');return;}
      set('site-cert-status','Repair requested. It installs the current helpers and reloads nginx; reload this page in a moment.');
    })
    .catch(function(e){rBtn.disabled=false;set('site-cert-status','Could not reach the panel: '+e.message);});
});

// Lifecycle: approve/pause provisioning, enable/disable, remove.
var sBtn=document.querySelector('[data-site-sync]');
if(sBtn)sBtn.addEventListener('click',function(){
  sBtn.disabled=true;set('site-life-status','Saving…');
  post('/sync',{sync_state:sBtn.getAttribute('data-sync')})
    .then(function(r){if(r.ok){location.reload();}else{sBtn.disabled=false;set('site-life-status','Could not update');}})
    .catch(function(e){sBtn.disabled=false;set('site-life-status','Error: '+e);});
});
var tBtn=document.querySelector('[data-site-toggle]');
if(tBtn)tBtn.addEventListener('click',function(){
  tBtn.disabled=true;set('site-life-status','Saving…');
  post('/status',{status:tBtn.getAttribute('data-status')})
    .then(function(r){if(r.ok){location.reload();}else{tBtn.disabled=false;set('site-life-status','Could not update');}})
    .catch(function(e){tBtn.disabled=false;set('site-life-status','Error: '+e);});
});
var dBtn=document.querySelector('[data-site-delete]');
if(dBtn)dBtn.addEventListener('click',function(){
  vpConfirm({title:'Remove domain',message:'Remove '+dBtn.getAttribute('data-host')+' from the registry? This cannot be undone.',confirm:'Remove'},function(){
  dBtn.disabled=true;set('site-life-status','Removing…');
  fetch('/os/api/domains/'+encodeURIComponent(ID),{method:'DELETE',headers:{'X-CSRF-Token':csrf()}})
    .then(function(r){if(r.ok){location.href='/os/domains';}else{dBtn.disabled=false;set('site-life-status','Could not remove');}})
    .catch(function(e){dBtn.disabled=false;set('site-life-status','Error: '+e);});
  });
});
})();
</script>`
}

func tlsLabel(state string) string {
	switch state {
	case domain.TLSPrimary:
		return "Primary cert"
	case domain.TLSActive:
		return "Active"
	case domain.TLSFailed:
		return "Failed"
	default:
		return "Pending"
	}
}

func domainsAddForm() string {
	var opts strings.Builder
	for _, o := range siteTypeOptions {
		// Same outcome language as the per-site card. An operator choosing here
		// and an operator changing it later are answering one question, and two
		// vocabularies for it is how "Business + /blog" reads as jargon in one
		// place and as an answer in the other.
		opts.WriteString(`<option value="` + o.Value + `">` +
			html.EscapeString(o.Label+" — "+servesOutcome(o.Value)) + `</option>`)
	}
	return `<div class="card">
  <h2 class="card-title">Add a domain</h2>
  <p class="text-sm muted">Register another hostname this install should answer on. New domains start on <strong>manual hold</strong>: nothing is provisioned until you point DNS here and press <strong>Sync now</strong> on the domain's row.</p>
  <div class="form-grid">
    <label class="field"><span class="field-label">Host</span>
      <input type="text" id="dom-host" class="input" placeholder="example.com" autocomplete="off" spellcheck="false"></label>
    <label class="field"><span class="field-label">Serves</span>
      <select id="dom-type" class="input">` + opts.String() + `</select></label>
    <label class="field field--check"><input type="checkbox" id="dom-mail"> <span class="field-label">Branded mail on this domain</span></label>
  </div>
  <div class="vm-row" style="gap:.5rem;align-items:center">
    <button type="button" class="btn btn--primary" data-dom-add>Add domain</button>
    <span id="dom-status" class="text-sm muted" role="status" aria-live="polite"></span>
  </div>
</div>`
}

// torSitesAddForm is the one-click "Add Tor site" card, shown only in the Tor
// world (ADR-0141). There is no host to type — the operator picks what the site
// serves and the parent mints a fresh dedicated .onion for it. Anonymous mail
// (VayuMail·Tor) can be switched on so the new site also carries mailboxes.
func torSitesAddForm() string {
	var opts strings.Builder
	for _, o := range siteTypeOptions {
		opts.WriteString(`<option value="` + o.Value + `">` + html.EscapeString(o.Label) + `</option>`)
	}
	return `<div class="card">
  <h2 class="card-title">Add a Tor site</h2>
  <p class="text-sm muted">Spin up another anonymous site in one click. You don't pick a name — VayuPress mints a fresh <code>.onion</code> for it automatically. Choose what it serves, optionally turn on anonymous mail, and its <code>.onion</code> address appears in the table above within about a minute.</p>
  <div class="form-grid">
    <label class="field"><span class="field-label">Serves</span>
      <select id="tor-site-type" class="input">` + opts.String() + `</select></label>
    <label class="field field--check"><input type="checkbox" id="tor-site-mail"> <span class="field-label">Enable anonymous mail (VayuMail·Tor)</span></label>
  </div>
  <div class="vm-row" style="gap:.5rem;align-items:center">
    <button type="button" class="btn btn--primary" data-tor-site-add>Add Tor site</button>
    <span id="tor-site-status" class="text-sm muted" role="status" aria-live="polite"></span>
  </div>
</div>`
}

// torSitesScript wires the "Add Tor site" button and, while any site is still
// waiting on its onion, auto-refreshes so the freshly-assigned .onion appears
// without a manual reload. Emitted only in the Tor world; the empty string
// otherwise keeps the clearnet console byte-identical.
func torSitesScript(nonce string, onion, pending bool) string {
	if !onion {
		return ""
	}
	// A pending site is waiting on the parent's tor engine (it reconciles about
	// once a minute); re-check periodically until every onion has landed.
	poll := ""
	if pending {
		poll = `setTimeout(function(){location.reload();},15000);`
	}
	return `<script nonce="` + nonce + `">
(function(){'use strict';
function csrf(){var m=document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);return m?decodeURIComponent(m[1]):'';}
var st=document.getElementById('tor-site-status');
function show(t){if(st)st.textContent=t;}
var b=document.querySelector('[data-tor-site-add]');
if(b)b.addEventListener('click',function(){
  var typeEl=document.getElementById('tor-site-type');
  var mailEl=document.getElementById('tor-site-mail');
  var type=typeEl?typeEl.value:'blog';
  var mail=mailEl?mailEl.checked:false;
  b.disabled=true;show('Creating your Tor site…');
  fetch('/os/api/torworld/add-site',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:JSON.stringify({site_type:type,mail_enabled:mail})})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};}).catch(function(){return {ok:r.ok,j:null};});})
    .then(function(res){if(res.ok){show('Site created — minting its .onion…');setTimeout(function(){location.reload();},900);}else{b.disabled=false;show((res.j&&res.j.error&&res.j.error.message)||'Could not add site');}})
    .catch(function(e){b.disabled=false;show('Error: '+e);});
});
` + poll + `
})();
</script>`
}

// domainsScript wires the registry list page: add a domain, per-card sync /
// enable / remove, and the bulk "Sync all pending" action. Per-domain branding
// and post assignment moved to each site's manager (domainManageScript), so this
// script is now just the list-page CRUD. Every handler is null-guarded so a page
// without a given control (e.g. no pending domains → no bulk button) is safe.
func domainsScript(nonce string) string {
	return `<script nonce="` + nonce + `">
(function(){'use strict';
function csrf(){var m=document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);return m?decodeURIComponent(m[1]):'';}
var st=document.getElementById('dom-status');
function show(t){if(st)st.textContent=t;}
var addBtn=document.querySelector('[data-dom-add]');
if(addBtn)addBtn.addEventListener('click',function(){
  var host=(document.getElementById('dom-host').value||'').trim();
  if(!host){show('Enter a host.');return;}
  var type=document.getElementById('dom-type').value;
  var mail=document.getElementById('dom-mail').checked;
  addBtn.disabled=true;show('Adding…');
  fetch('/os/api/domains',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:JSON.stringify({host:host,site_type:type,mail_enabled:mail})})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
    .then(function(res){if(res.ok){location.reload();}else{addBtn.disabled=false;show((res.j&&res.j.message)||'Could not add domain');}})
    .catch(function(e){addBtn.disabled=false;show('Error: '+e);});
});
document.querySelectorAll('[data-dom-sync]').forEach(function(b){
  b.addEventListener('click',function(){
    b.disabled=true;show('Saving…');
    fetch('/os/api/domains/'+encodeURIComponent(b.getAttribute('data-id'))+'/sync',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:JSON.stringify({sync_state:b.getAttribute('data-sync')})})
      .then(function(r){if(r.ok){location.reload();}else{b.disabled=false;show('Could not update sync state');}})
      .catch(function(e){b.disabled=false;show('Error: '+e);});
  });
});
var syncAllBtn=document.querySelector('[data-dom-sync-all]');
if(syncAllBtn)syncAllBtn.addEventListener('click',function(){
  var s=document.getElementById('dom-sync-all-status');
  syncAllBtn.disabled=true;if(s)s.textContent='Approving…';
  fetch('/os/api/domains/sync-all',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:JSON.stringify({sync_state:'approved'})})
    .then(function(r){if(r.ok){location.reload();}else{syncAllBtn.disabled=false;if(s)s.textContent='Could not approve pending domains';}})
    .catch(function(e){syncAllBtn.disabled=false;if(s)s.textContent='Error: '+e;});
});
document.querySelectorAll('[data-dom-toggle]').forEach(function(b){
  b.addEventListener('click',function(){
    b.disabled=true;show('Saving…');
    fetch('/os/api/domains/'+encodeURIComponent(b.getAttribute('data-id'))+'/status',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:JSON.stringify({status:b.getAttribute('data-status')})})
      .then(function(r){if(r.ok){location.reload();}else{b.disabled=false;show('Could not update');}})
      .catch(function(e){b.disabled=false;show('Error: '+e);});
  });
});
document.querySelectorAll('[data-dom-delete]').forEach(function(b){
  b.addEventListener('click',function(){
    vpConfirm({title:'Remove domain',message:'Remove '+b.getAttribute('data-host')+' from the registry? This cannot be undone.',confirm:'Remove'},function(){
    b.disabled=true;show('Removing…');
    fetch('/os/api/domains/'+encodeURIComponent(b.getAttribute('data-id')),{method:'DELETE',headers:{'X-CSRF-Token':csrf()}})
      .then(function(r){if(r.ok){location.reload();}else{b.disabled=false;show('Could not remove');}})
      .catch(function(e){b.disabled=false;show('Error: '+e);});
    });
  });
});
})();
</script>`
}

// handleOSDomainAssign moves a post to a domain (Stage 2 content ownership).
func (a *App) handleOSDomainAssign(w http.ResponseWriter, r *http.Request) {
	if a.articles == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "article service not initialised", "")
		return
	}
	var body struct {
		Slug     string `json:"slug"`
		DomainID string `json:"domain_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request", "invalid JSON", "")
		return
	}
	body.Slug = strings.TrimSpace(body.Slug)
	body.DomainID = strings.TrimSpace(body.DomainID)
	// A non-empty target must be a real, registered secondary domain.
	if body.DomainID != "" && a.domains != nil {
		found := false
		if list, err := a.domains.List(r.Context()); err == nil {
			for _, d := range list {
				if d.ID == body.DomainID && !d.IsPrimary {
					found = true
					break
				}
			}
		}
		if !found {
			writeAPIError(w, r, http.StatusBadRequest, "unknown-domain", "target is not a registered secondary domain", "")
			return
		}
	}
	if err := a.articles.SetDomain(r.Context(), body.Slug, body.DomainID); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "assign-failed", err.Error(), "")
		return
	}
	// The post just moved between domains — lazily invalidate the public caches
	// so every domain's homepage re-renders on next request (Stage 2b). Reassigning
	// touches no search-indexed field, so the engine snapshot version is unchanged;
	// clear the per-domain client-index memo explicitly so search re-scopes too
	// (Stage 2c). The per-domain sitemap/feed self-heal within their freshness
	// window, so they need no explicit purge.
	render.CachePurgeAll()
	purgeDomainSearchIndex()
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Session-friendly write APIs (CSRF-protected; operators hold a cookie) ---

// handleOSDomainCreate registers a new secondary domain.
func (a *App) handleOSDomainCreate(w http.ResponseWriter, r *http.Request) {
	if a.domains == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "domain registry not initialised", "")
		return
	}
	var body struct {
		Host        string `json:"host"`
		SiteType    string `json:"site_type"`
		MailEnabled bool   `json:"mail_enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request", "invalid JSON", "")
		return
	}
	body.Host = strings.TrimSpace(body.Host)
	if body.SiteType == "" {
		body.SiteType = domain.SiteBlog
	}
	d, err := a.domains.Create(r.Context(), body.Host, body.SiteType, body.MailEnabled)
	if err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "create-failed", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, d)
}

// handleOSDomainSync approves or holds a secondary domain for out-of-process
// TLS+nginx provisioning (P5 manual sync gate). Approving does not provision
// anything by itself — it only adds the domain to the work list the privileged
// helper (scripts/setup-vayudomain.sh) reads on its next run; the page copy
// says so, keeping the surface truthful.
func (a *App) handleOSDomainSync(w http.ResponseWriter, r *http.Request) {
	if a.domains == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "domain registry not initialised", "")
		return
	}
	id := chi.URLParam(r, "id")
	var body struct {
		SyncState string `json:"sync_state"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512)).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request", "invalid JSON", "")
		return
	}
	if err := a.domains.SetSyncState(r.Context(), id, strings.TrimSpace(body.SyncState)); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "sync-failed", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

// handleOSDomainSyncAll flips every secondary domain's sync state in one call —
// the bulk counterpart to handleOSDomainSync behind the "Sync all pending"
// button. Like the per-row action it only records approval; provisioning still
// happens out-of-process on the helper's next run. Returns how many rows
// changed so the UI can report the batch result.
func (a *App) handleOSDomainSyncAll(w http.ResponseWriter, r *http.Request) {
	if a.domains == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "domain registry not initialised", "")
		return
	}
	var body struct {
		SyncState string `json:"sync_state"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512)).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request", "invalid JSON", "")
		return
	}
	n, err := a.domains.SetAllSyncState(r.Context(), strings.TrimSpace(body.SyncState))
	if err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "sync-failed", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"status": "ok", "changed": n})
}

// handleOSDomainStatus enables or disables a secondary domain.
func (a *App) handleOSDomainStatus(w http.ResponseWriter, r *http.Request) {
	if a.domains == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "domain registry not initialised", "")
		return
	}
	id := chi.URLParam(r, "id")
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512)).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request", "invalid JSON", "")
		return
	}
	if err := a.domains.SetStatus(r.Context(), id, strings.TrimSpace(body.Status)); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "status-failed", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

// handleOSDomainAllowance sets how many branded mailboxes a hosted domain may
// have. Operator-only: it is registered under /os/api/domains, which the client
// surface does not declare, and the client console offers no path to it.
//
// This is the number that makes the studio's capacity claim true. Without it
// STORAGE_QUOTA_GB is global and MailQuotaMB is per membership tier, so nothing
// stops one client's mail filling the disk that thirty clients share.
func (a *App) handleOSDomainAllowance(w http.ResponseWriter, r *http.Request) {
	if a.domains == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "domain registry not initialised", "")
		return
	}
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "admin role required", "")
		return
	}
	id := chi.URLParam(r, "id")
	var body struct {
		Mailboxes int `json:"mailboxes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512)).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request", "invalid JSON", "")
		return
	}
	// A negative allowance is a typo, not an intent. Refuse rather than clamp: a
	// clamped -1 becomes 0, which silently REVOKES every mailbox the operator
	// meant to grant, and the operator sees a success message either way.
	if body.Mailboxes < 0 {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request",
			"an allowance cannot be negative", "")
		return
	}
	if err := a.domains.SetLimits(r.Context(), id, domain.Limits{Mailboxes: body.Mailboxes}); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "allowance-failed", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"status": "ok", "mailboxes": body.Mailboxes})
}

// handleOSDomainClient issues the login an agency client uses to reach their own
// site, mail and traffic — and nothing else (ADR-0152 D2).
//
// It lives on the domain, not on the team page, because the binding is the whole
// identity: a client account is meaningless without the domain it is scoped to,
// and a role picker that offers "client" as a fourth option invites an operator
// to create one from a screen that has no domain to bind it to. The store
// refuses that path outright; this is the path that carries the binding.
func (a *App) handleOSDomainClient(w http.ResponseWriter, r *http.Request) {
	if a.domains == nil || a.userStore == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "not initialised", "")
		return
	}
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "admin role required", "")
		return
	}
	id := chi.URLParam(r, "id")
	// The domain must exist and must NOT be the primary. Binding a client to the
	// primary domain would hand a paying customer a login scoped to the agency's
	// own install — the exact outcome the empty-binding refusal exists to prevent,
	// arrived at from the other direction.
	var target *domain.Domain
	if list, err := a.domains.List(r.Context()); err == nil {
		for i := range list {
			if list[i].ID == id {
				d := list[i]
				target = &d
				break
			}
		}
	}
	if target == nil {
		writeAPIError(w, r, http.StatusNotFound, "no-domain", "no such domain", "")
		return
	}
	if target.IsPrimary {
		writeAPIError(w, r, http.StatusBadRequest, "primary-domain",
			"the primary domain is your own install; a client cannot be bound to it", "")
		return
	}
	var body struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request", "invalid JSON", "")
		return
	}
	u, err := a.userStore.CreateClient(r.Context(), body.Email, body.Name, body.Password, id)
	if err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "client-failed", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"status": "ok", "email": u.Email})
}

// handleOSDomainBrand stores a secondary domain's public branding overrides
// (VayuDomains per-domain branding). Colour fields are hex-validated before they
// can reach the domain's /theme.css or its <meta theme-color>, so no CSS or
// attribute injection is possible through the accent variables; text fields are
// length-capped. An empty payload clears the brand back to inheriting the
// primary site. Only secondary domains are brandable — the registry refuses the
// primary, whose identity is the global Website settings.
func (a *App) handleOSDomainBrand(w http.ResponseWriter, r *http.Request) {
	if a.domains == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "domain registry not initialised", "")
		return
	}
	id := chi.URLParam(r, "id")
	var body struct {
		SiteName    string `json:"site_name"`
		Tagline     string `json:"tagline"`
		Description string `json:"description"`
		AccentLight string `json:"accent_light"`
		AccentDark  string `json:"accent_dark"`
		ThemeColor  string `json:"theme_color"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request", "invalid JSON", "")
		return
	}
	// Clipping, the hex check and the write-through all live in saveBrand, which
	// the client's own /os/api/mysite/brand also calls. They used to live here
	// only — so the client-facing endpoint stored unvalidated colours, and
	// neither endpoint reached the store the public site reads.
	brand, err := a.saveBrand(r.Context(), id, domain.Brand{
		SiteName:    body.SiteName,
		Tagline:     body.Tagline,
		Description: body.Description,
		AccentLight: body.AccentLight,
		AccentDark:  body.AccentDark,
		ThemeColor:  body.ThemeColor,
	})
	if err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "brand-failed", err.Error(), "")
		return
	}
	// The domain's public identity changed: purge the public HTML caches so its
	// homepage and articles re-render with the new brand on the next request (the
	// same lazy purge the assign path uses). /theme.css is served live per request,
	// so its accent update needs no purge and takes effect immediately.
	render.CachePurgeAll()
	writeJSON(w, r, http.StatusOK, map[string]any{"status": "ok", "brand": brand})
}

// handleOSDomainDelete removes a secondary domain from the registry.
func (a *App) handleOSDomainDelete(w http.ResponseWriter, r *http.Request) {
	if a.domains == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "domain registry not initialised", "")
		return
	}
	id := chi.URLParam(r, "id")
	if err := a.domains.Delete(r.Context(), id); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "delete-failed", err.Error(), "")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
}
