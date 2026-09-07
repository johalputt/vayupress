// SPDX-License-Identifier: Apache-2.0

package main

// admin_os_scoped_website.go — what one hosted domain SERVES, and its website
// content (ADR-0154 D9).
//
// The serving side has been per-domain since ADR-0132 Stage 2b: siteSourceFor
// resolves the active domain and returns that site's own mode, template and
// content, with a deliberate rule that a secondary with no override serves its
// OWN blog rather than inheriting the primary's website — inheriting is what
// once made every client domain serve the studio's bundle.
//
// What was missing is the admin side. /os/website reads bizSettings(r), which
// resolves by REQUEST HOST, and an operator's admin request carries no secondary
// host — so it always edited the primary. A hosted domain's mode and content
// were reachable only by the CLI or by hand. Same shape as the content gap: the
// scoping existed underneath and nothing surfaced it.

import (
	"encoding/json"
	"html"
	htmpl "html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/johalputt/vayupress/internal/bizsite"
	"github.com/johalputt/vayupress/internal/customsite"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/domain"
	"github.com/johalputt/vayupress/internal/render"
	"github.com/johalputt/vayupress/internal/seo"
)

// scopedSiteModes is what a hosted domain can serve at "/".
//
// "custom" is deliberately absent: a custom bundle is an upload, not a choice,
// and offering it as a radio button an operator can select with nothing
// uploaded would put a domain into a mode that serves a 404.
var scopedSiteModes = []struct{ Value, Label, Note string }{
	{"blog", "Blog", "The classic VayuPress blog at /. This is what a site serves if you choose nothing."},
	{"business", "Website", "A business website at /, with the blog moved to blog.<host>."},
	{"business_subpath", "Website + /blog", "A business website at /, with the blog at /blog on the same host."},
}

// scopedSiteMode reports the mode a domain is actually serving, resolving the
// blank override to what it MEANS rather than leaving the page to guess.
//
// A blank mode is not "unset" to a visitor — it serves the blog. Rendering the
// radio group with nothing selected would tell an operator their site serves
// nothing, which is the kind of gap between what a page shows and what the
// server does that this whole ADR exists to close.
func scopedSiteMode(d domain.Domain) string {
	if s, ok := d.Site(); ok && s.Mode != "" {
		return s.Mode
	}
	return "blog"
}

func (a *App) handleOSScopedWebsite(w http.ResponseWriter, r *http.Request) {
	nonce := render.CSPNonce(r)
	cfg := a.getOSSettings(r.Context())
	d, ok := osScopedDomain(r)
	if !ok {
		http.Redirect(w, r, "/os/domains", http.StatusSeeOther)
		return
	}
	csrfTokenFor(w, r)

	site, _ := d.Site()
	content := bizsite.ParseContent(site.Content)
	tpl := bizsite.ByKey(site.Template)
	if content.Name == "" && content.Tagline == "" {
		content = tpl.Defaults
	}
	man := customsite.ReadManifest(scopedBundleDir(d))
	body := scopedWebsitePage(d, tpl.Key, content, customsite.Deployed(scopedBundleDir(d)), man) +
		scopedWebsiteScript(nonce)
	writeOSHTML(w, r, adminOSLayout(nonce, "Website · "+d.Host, "optimize", cfg, htmpl.HTML(body)))
}

func scopedWebsitePage(d domain.Domain, tplKey string, c bizsite.Content, bundled bool, man customsite.Manifest) string {
	esc := html.EscapeString
	mode := scopedSiteMode(d)
	var b strings.Builder

	b.WriteString(`<div id="scoped-ctx" data-id="` + esc(d.ID) + `" hidden></div>`)
	b.WriteString(`<div class="page-header"><h1>Website</h1><div class="page-actions">` +
		`<a class="btn btn--ghost btn--sm" href="` + esc(seo.Origin(d.Host)) +
		`" target="_blank" rel="noopener noreferrer">View site ↗</a>` +
		`<a class="btn btn--ghost btn--sm" href="/os/d/` + esc(d.ID) + `">← ` + esc(d.Host) + `</a>` +
		`<button type="button" class="btn btn--primary btn--sm" data-site-web-save>Save &amp; publish</button>` +
		`<span id="scoped-web-status" class="text-sm muted" role="status" aria-live="polite"></span>` +
		`</div></div>`)
	b.WriteString(`<p class="page-sub">What <b>` + esc(d.Host) + `</b> serves at its root, and the content of ` +
		`that site. This domain only — the primary's website is edited from your own Website settings.</p>`)

	// ── Four tiles ────────────────────────────────────────────────────────────
	//
	// The house style opens a page with the numbers that answer "what is the
	// state of this?" before any control. This page had none, so an operator had
	// to open sections to learn what the domain was even serving — which is how a
	// site sat on a stale uploaded bundle for a day with the file count visible
	// only inside a collapsed radio hint.
	servesLabel := "Blog"
	for _, m := range scopedSiteModes {
		if m.Value == mode {
			servesLabel = m.Label
		}
	}
	if mode == "custom" {
		servesLabel = "Uploaded"
	}
	filesLabel, filesTone := "—", ""
	if bundled {
		filesLabel = itoaSafe(man.Files) + " files"
	} else if mode == "custom" {
		filesLabel, filesTone = "none", " stat-card--warn"
	}
	evalLabel, evalTone := "—", ""
	if bundled {
		evalLabel = "Off"
		if site, ok := d.Site(); ok && site.AllowEval {
			evalLabel, evalTone = "On", " stat-card--warn"
		}
	}
	certLabel, certTone := scopedCertTile(d)
	certCls := ""
	if certTone != "" {
		certCls = " stat-card--" + certTone
	}
	b.WriteString(`<div class="stat-grid">
  <div class="stat-card"><div class="stat-card__label">Serving at /</div><div class="stat-card__value">` +
		esc(servesLabel) + `</div></div>
  <div class="stat-card` + filesTone + `"><div class="stat-card__label">Uploaded site</div><div class="stat-card__value">` +
		esc(filesLabel) + `</div></div>
  <div class="stat-card` + evalTone + `"><div class="stat-card__label">Runtime code</div><div class="stat-card__value">` +
		esc(evalLabel) + `</div></div>
  <div class="stat-card` + certCls + `"><div class="stat-card__label">Certificate</div><div class="stat-card__value">` +
		esc(certLabel) + `</div></div>
</div>`)

	// ── The bands, as accordions (house style §11) ───────────────────────────
	//
	// A mon-stack of pure-CSS <details>, each with a chip so its state reads
	// while collapsed. This page was ten flat sections to scroll past.
	b.WriteString(`<div class="section-head"><span class="section-head__title">This site</span>` +
		`<span class="section-head__hint">Changes take effect within seconds</span></div>`)
	b.WriteString(`<div class="mon-stack">`)

	var srv strings.Builder
	srv.WriteString(`<div class="card"><div class="form-grid">`)
	for _, m := range scopedSiteModes {
		checked := ""
		if m.Value == mode {
			checked = " checked"
		}
		srv.WriteString(`<label class="field field--check"><input type="radio" name="scoped-site-mode" ` +
			`value="` + esc(m.Value) + `"` + checked + `> <span class="field-label">` + esc(m.Label) + `</span>` +
			`<span class="field-hint">` + esc(m.Note) + `</span></label>`)
	}
	if bundled {
		checked := ""
		if mode == "custom" {
			checked = " checked"
		}
		srv.WriteString(`<label class="field field--check"><input type="radio" name="scoped-site-mode" ` +
			`value="custom"` + checked + `> <span class="field-label">Uploaded website</span>` +
			`<span class="field-hint">The site you uploaded or had built — served exactly as authored, at /. ` +
			`` + esc(itoaSafe(man.Files)) + ` file(s), deployed ` + esc(man.DeployedAt.Format("2006-01-02 15:04")) +
			`.</span></label>`)
	}
	srv.WriteString(`</div></div>`)
	b.WriteString(monAcc("🌐", "What this domain serves", "Blog, website, or the site you uploaded",
		`<span class="mon-chip mon-chip--on">`+esc(servesLabel)+`</span>`, true, srv.String()))

	// ── A whole site of your own ─────────────────────────────────────────────
	uploadBody := `<div class="card">
  <div class="settings-block-title">Upload a website</div>
  <p class="text-sm muted">A <code>.zip</code> of a complete static site — <code>index.html</code> at its root,
    with whatever CSS, JavaScript, images and fonts it needs beside it. It is served exactly as authored, so a
    hand-built page looks like a hand-built page. Up to 50&nbsp;MiB unpacked, 3000 files.</p>
  <p class="text-sm muted">Each deploy is atomic and keeps the one before it, so a bad publish is one click from
    being undone.</p>
  <div class="vm-row">
    <input type="file" id="scoped-bundle-file" class="input" accept=".zip,application/zip">
    <button type="button" class="btn btn--primary btn--sm" data-bundle-upload>Upload &amp; deploy</button>` +
		func() string {
			if !bundled || !man.HasPrev {
				return ""
			}
			return `<button type="button" class="btn btn--ghost btn--sm" data-bundle-rollback>Restore previous</button>`
		}() + `
    <span id="scoped-bundle-status" class="text-sm muted" role="status" aria-live="polite"></span>
  </div>
  <p id="scoped-bundle-outcome" class="text-sm" role="alert"></p>
  <p class="text-sm muted">Or have one written for you: ask an assistant through <a href="/os/vayumcp">VayuMCP</a>
    to <em>build a site for ` + esc(d.Host) + `</em>. It authors the HTML and CSS itself and publishes it here —
    the same deploy path as an upload, with the same limits.</p>
</div>`
	uploadChip := `<span class="mon-chip mon-chip--off">nothing uploaded</span>`
	if bundled {
		uploadChip = `<span class="mon-chip mon-chip--on">` + esc(itoaSafe(man.Files)) + ` files</span>`
	}
	b.WriteString(monAcc("📦", "A whole site of your own", "Upload a .zip, or have one built for you",
		uploadChip, !bundled, uploadBody))

	// ── What this domain actually serves ─────────────────────────────────────
	//
	// Everything that goes wrong with an uploaded site goes wrong silently: a
	// stylesheet the policy refuses and a stylesheet that is not there both
	// render as a page with no styling, no error and a clean server log. The
	// operator is left comparing two browser windows by eye. The server can
	// simply answer the question — it holds the bundle and it writes the policy —
	// and until now it never offered to.
	checkBody := `<div class="card">
  <div class="settings-block-title">Fetch a page and check it</div>
  <p class="text-sm muted">Fetches the page from this server the way a visitor would, then reports every
    stylesheet, script and image it asks for — and what happens to each one. A file that is missing and a file
    this site refuses to load look identical on screen; this tells them apart.</p>
  <div class="vm-row">
    <input type="text" id="preview-path" class="input" value="/" placeholder="/" aria-label="Page to check">
    <button type="button" class="btn btn--primary btn--sm" data-site-preview>Check this page</button>
    <span id="preview-status" class="text-sm muted" role="status" aria-live="polite"></span>
  </div>
  <div id="preview-out" class="text-sm"></div>
</div>`
	b.WriteString(monAcc("🔎", "Check what this domain serves", "Asks this server, not your browser",
		`<span class="mon-chip mon-chip--on">on demand</span>`, false, checkBody))

	// ── The eval opt-in ───────────────────────────────────────────────────────
	//
	// This setting existed in the config and in the connector for three releases
	// with no control anywhere on the panel, so the only way to turn it on was to
	// ask an assistant to call a tool. That is the failure this project keeps
	// removing from everywhere else, and it stayed here because the setting was
	// added to serve one particular upload rather than to be operated.
	//
	// Shown only when a bundle is deployed: it changes nothing for a template
	// site, and a control that does nothing is worse than an absent one.
	if bundled {
		checked := ""
		if site, ok := d.Site(); ok && site.AllowEval {
			checked = " checked"
		}
		evalBody := `<div class="card">
  <div class="settings-block-title">Scripts that build their own code</div>
  <p class="text-sm muted">Some page frameworks keep their behaviour in HTML attributes
    (<code>x-show="open"</code> and the like) and turn those strings into functions in the browser. That needs
    <code>eval</code>, which this server refuses by default because it is the single most useful thing for an
    attacker who gets a script onto your page.</p>
  <p class="text-sm muted">Turn it on only for a site whose code you control and trust. It applies to
    <b>` + esc(d.Host) + `</b> alone — never to your panel, your API, or any other domain — and only while an
    uploaded website is being served. Leave it off and such a page still lays out and reads correctly; what stops
    is the animation and anything driven by those attributes.</p>
  <label class="field field--check"><input type="checkbox" id="web-alloweval"` + checked + `>
    <span class="field-label">Allow this site to build code at runtime</span>
    <span class="field-hint">Applies on Save &amp; publish. Off is the safe default and the one to keep unless a
      page you uploaded needs it.</span></label>
</div>`
		evalChip := `<span class="mon-chip mon-chip--off">off</span>`
		if checked != "" {
			evalChip = `<span class="mon-chip mon-chip--on">on</span>`
		}
		b.WriteString(monAcc("⚡", "Scripts that build their own code",
			"Needed by some page frameworks; off by default", evalChip, false, evalBody))
	}

	// ── Design ────────────────────────────────────────────────────────────────
	var dsn strings.Builder
	dsn.WriteString(`<div class="card"><label class="field"><span class="field-label">Template</span>` +
		`<select class="input" id="scoped-web-template">`)
	for _, t := range bizsite.All() {
		sel := ""
		if t.Key == tplKey {
			sel = " selected"
		}
		dsn.WriteString(`<option value="` + esc(t.Key) + `"` + sel + `>` + esc(t.Name) + ` — ` + esc(t.Category) + `</option>`)
	}
	dsn.WriteString(`</select><span class="field-hint">Each template is a complete design. Switching one keeps ` +
		`your content.</span></label></div>`)
	b.WriteString(monAcc("🎨", "Design", "Used when this domain serves a website",
		`<span class="mon-chip mon-chip--on">`+esc(bizsite.ByKey(tplKey).Name)+`</span>`, false, dsn.String()))

	// ── Content ───────────────────────────────────────────────────────────────
	var con strings.Builder
	field := func(id, label, hint, val string) string {
		return `<label class="field"><span class="field-label">` + esc(label) + `</span>` +
			`<input type="text" class="input" id="` + id + `" value="` + esc(val) + `" autocomplete="off">` +
			`<span class="field-hint">` + esc(hint) + `</span></label>`
	}
	// areaField renders one of the MULTI-LINE content fields.
	//
	// WHY A TEXTAREA AND NEVER AN <input type=text>: a browser applies the HTML
	// "value sanitization algorithm" to every single-line input, which STRIPS
	// line breaks from its value. Hours stored as "Tue–Sun 18:00–23:00\nClosed
	// Mondays" therefore reached this form already collapsed to
	// "...23:00Closed Mondays", and the next Save & publish persisted that
	// mangled string over the good one — exactly how vayupress.johal.in lost the
	// second line of its hours while .vb-hours (white-space:pre-line) was still
	// rendering from a newline nobody's editor could hold. Hours, address and
	// about are line-oriented fields BY DESIGN; they must only ever be edited
	// through an element whose value can carry "\n". Keep them textareas even if
	// this page is restyled; the ordinary single-line fields below stay inputs,
	// where nothing multi-line can be lost.
	areaField := func(id, label, hint, val string, rows int) string {
		return `<label class="field"><span class="field-label">` + esc(label) + `</span>` +
			`<textarea class="input" id="` + id + `" rows="` + itoaSafe(rows) + `">` + esc(val) + `</textarea>` +
			`<span class="field-hint">` + esc(hint) + `</span></label>`
	}
	con.WriteString(`<div class="card"><div class="form-grid">`)
	con.WriteString(field("web-name", "Business name", "The name across the top of the site.", c.Name))
	con.WriteString(field("web-tagline", "Tagline", "One line under the name.", c.Tagline))
	con.WriteString(areaField("web-about", "About", "A paragraph or two — one per line. Line breaks are kept.", c.About, 4))
	con.WriteString(field("web-phone", "Phone", "Optional.", c.Phone))
	con.WriteString(field("web-email", "Email", "Optional.", c.Email))
	con.WriteString(areaField("web-address", "Address", "Optional — one line per row. Line breaks are kept.", c.Address, 2))
	con.WriteString(areaField("web-hours", "Opening hours", "One range per line, e.g. Tue–Sun 18:00–23:00. Line breaks are kept.", c.Hours, 3))
	con.WriteString(field("web-cta", "Button label", "The hero button, e.g. “Book a table”.", c.CTA))
	con.WriteString(field("web-ctalink", "Button link", "Where the hero button goes.", c.CTALink))
	con.WriteString(field("web-heroimg", "Hero image URL", "Optional. Left blank, the template's own art is used.", c.HeroImg))
	blogChecked := ""
	if c.ShowBlog {
		blogChecked = " checked"
	}
	con.WriteString(`<label class="field field--check"><input type="checkbox" id="web-showblog"` + blogChecked + `> ` +
		`<span class="field-label">Link the blog from this website</span>` +
		`<span class="field-hint">Adds the blog to the navigation and footer.</span></label>`)
	con.WriteString(`</div></div>`)

	// The honest note about what this page does not edit.
	con.WriteString(`<div class="card"><p class="text-sm muted">Services and gallery are not edited here yet — ` +
		`they are preserved exactly as they are when you save, so nothing you set elsewhere is lost. The ` +
		`fastest way to build a whole site is to ask an AI assistant through <a href="/os/vayumcp">VayuMCP</a>: ` +
		`it can read and write every field on this page for any site you host.</p></div>`)
	contentChip := `<span class="mon-chip mon-chip--off">not set</span>`
	if strings.TrimSpace(c.Name) != "" {
		contentChip = `<span class="mon-chip mon-chip--on">` + esc(c.Name) + `</span>`
	}
	b.WriteString(monAcc("✍️", "Content", "What the website says",
		contentChip, false, con.String()))

	b.WriteString(`</div>`) // mon-stack
	return b.String()
}

func scopedWebsiteScript(nonce string) string {
	return `<script nonce="` + nonce + `">
(function(){'use strict';
function csrf(){var m=document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);return m?decodeURIComponent(m[1]):'';}
var node=document.getElementById('scoped-ctx');
var ID=node?node.getAttribute('data-id'):'';
if(!ID)return;
var st=document.getElementById('scoped-web-status');
function v(id){var e=document.getElementById(id);return e?e.value.trim():'';}
var btn=document.querySelector('[data-site-web-save]');
if(!btn)return;
btn.addEventListener('click',function(){
  var m=document.querySelector('input[name="scoped-site-mode"]:checked');
  var sb=document.getElementById('web-showblog');
  var ae=document.getElementById('web-alloweval');
  var payload={mode:m?m.value:'blog',template:v('scoped-web-template'),
    allow_eval:!!(ae&&ae.checked),content:{
    name:v('web-name'),tagline:v('web-tagline'),about:v('web-about'),
    phone:v('web-phone'),email:v('web-email'),address:v('web-address'),hours:v('web-hours'),
    cta:v('web-cta'),ctaLink:v('web-ctalink'),heroImg:v('web-heroimg'),
    showBlog:!!(sb&&sb.checked)}};
  btn.disabled=true; if(st)st.textContent='Saving…';
  fetch('/os/d/'+encodeURIComponent(ID)+'/api/website',{method:'POST',
    headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},
    body:JSON.stringify(payload)})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
    .then(function(res){btn.disabled=false;
      if(st)st.textContent=res.ok?'Published ✓':((res.j&&res.j.message)||'Could not save');})
    .catch(function(e){btn.disabled=false; if(st)st.textContent='Error: '+e;});
});
var pv=document.querySelector('[data-site-preview]');
if(pv)pv.addEventListener('click',function(){
  var ps=document.getElementById('preview-status'), out=document.getElementById('preview-out');
  var pth=(document.getElementById('preview-path')||{}).value||'/';
  pv.disabled=true; if(ps)ps.textContent='Checking\u2026'; if(out)out.textContent='';
  fetch('/os/d/'+encodeURIComponent(ID)+'/api/website/preview?path='+encodeURIComponent(pth))
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
    .then(function(res){pv.disabled=false;
      var j=res.j;
      if(!res.ok){if(ps)ps.textContent=(j&&j.message)||'Could not check';return;}
      if(ps)ps.textContent='HTTP '+j.status+(j.eval_allowed?' \u00b7 runtime code allowed':'');
      if(!out)return;
      out.textContent='';
      function row(cls,txt){var d=document.createElement('div');d.className=cls;d.textContent=txt;out.appendChild(d);}
      if(j.title)row('text-sm muted','Title: '+j.title);
      row('text-sm muted','Sent '+j.bytes+' bytes'+(j.content_type?' as '+j.content_type:''));
      var probs=j.problems||[];
      if(!probs.length){row('text-sm','Nothing on this page is refused or missing.');}
      else{probs.forEach(function(p){row('text-sm','\u2022 '+p);});}
      var subs=j.subresources||[];
      if(subs.length){
        row('text-sm muted','\u2014');
        subs.forEach(function(s){
          var mark=s.verdict==='ok'?'\u2713':'\u2717';
          row('text-sm',mark+' '+s.tag+' '+s.url+' \u2014 '+s.verdict+(s.why?' ('+s.why+')':''));
        });
      }
    })
    .catch(function(e){pv.disabled=false; if(ps)ps.textContent='Error: '+e;});
});
var up=document.querySelector('[data-bundle-upload]');
if(up)up.addEventListener('click',function(){
  // The outcome belongs BESIDE THIS BUTTON. It used to be written to the status
  // span in the page header, which on a long page is off-screen from the upload
  // card entirely — so a refused upload looked exactly like the button doing
  // nothing, and the previously deployed site stayed live with no explanation.
  var bs=document.getElementById('scoped-bundle-status');
  var bo=document.getElementById('scoped-bundle-outcome');
  function say(msg,bad){ if(bs)bs.textContent=bad?'Not deployed':'';
    if(bo){bo.textContent=msg||''; bo.className='text-sm'+(bad?' upd-bad':' muted');} }
  var f=document.getElementById('scoped-bundle-file');
  if(!f||!f.files||!f.files.length){say('Choose a .zip first, then press Upload & deploy.',true);return;}
  up.disabled=true; if(bs)bs.textContent='Uploading\u2026'; if(bo)bo.textContent='';
  var fd=new FormData(); fd.append('bundle', f.files[0]);
  fetch('/os/d/'+encodeURIComponent(ID)+'/api/website/bundle',{method:'POST',
    headers:{'X-CSRF-Token':csrf()}, body:fd})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
    .then(function(res){up.disabled=false;
      if(res.ok){
        var n=res.j.files||0, sk=res.j.skipped||0;
        var msg='Deployed '+n+' file(s).';
        if(sk)msg+=' '+sk+' system file(s) ignored'+(res.j.skipped_names?' ('+res.j.skipped_names.join(', ')+')':'')+'.';
        if(bs)bs.textContent='Deployed \u2713';
        if(bo){bo.textContent=msg+' Reloading so the count above is current\u2026'; bo.className='text-sm muted';}
        window.setTimeout(function(){window.location.reload();},900);
        return;
      }
      say('This bundle was NOT deployed, and the site above is unchanged. '+
          ((res.j&&res.j.message)||'The server refused it without giving a reason.'),true);})
    .catch(function(e){up.disabled=false;
      say('This bundle was NOT deployed, and the site above is unchanged. '+e,true);});
});
var rb=document.querySelector('[data-bundle-rollback]');
if(rb)rb.addEventListener('click',function(){
  vpConfirm({title:'Roll back website',message:'Restore the previous uploaded website? The current bundle is replaced.',confirm:'Roll back'},function(){
  rb.disabled=true; if(st)st.textContent='Restoring\u2026';
  fetch('/os/d/'+encodeURIComponent(ID)+'/api/website/bundle/rollback',{method:'POST',
    headers:{'X-CSRF-Token':csrf()}})
    .then(function(r){if(r.ok){window.location.reload();return;}
      rb.disabled=false; if(st)st.textContent='Could not restore';})
    .catch(function(e){rb.disabled=false; if(st)st.textContent='Error: '+e;});
  });
});
})();
</script>`
}

// handleOSScopedWebsiteSave writes one domain's website configuration.
//
// The domain comes from the PATH. Services and gallery are READ BACK from the
// stored content and carried forward, because this page does not edit them: a
// save that silently dropped every field the form happens not to render is how
// an operator loses work they never touched.
func (a *App) handleOSScopedWebsiteSave(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "admin role required", "")
		return
	}
	if a.domains == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "domain registry not initialised", "")
		return
	}
	d, ok := osScopedDomain(r)
	if !ok {
		writeAPIError(w, r, http.StatusNotFound, "unknown-domain", "no such site", "")
		return
	}
	var body struct {
		Mode     string           `json:"mode"`
		Template string           `json:"template"`
		Content  bizsite.Content  `json:"content"`
		DomainID string           `json:"domain_id"`
		Raw      *json.RawMessage `json:"-"`
		// Pointer, so a client that omits it keeps the stored value. A plain bool
		// would read every save that did not mention the field as "turn it off",
		// which is the failure this page's own carry-forward exists to prevent.
		AllowEval *flexBool `json:"allow_eval"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024)).Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request", "invalid JSON", "")
		return
	}
	if !requireScopeMatchesPath(r, body.DomainID) {
		writeAPIError(w, r, http.StatusBadRequest, "scope-mismatch",
			"this request names a different site from the one in its address; nothing was saved", "")
		return
	}

	cfg, err := scopedWebsiteConfig(d, body.Mode, body.Template, body.Content)
	if err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "validation_error", err.Error(), "")
		return
	}
	// scopedWebsiteConfig has already carried the stored value forward; only an
	// explicit value from the operator overrides it.
	if body.AllowEval != nil {
		cfg.AllowEval = body.AllowEval.Bool()
	}
	if err := a.domains.SetSite(r.Context(), d.ID, cfg); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "save-failed", err.Error(), "")
		return
	}
	render.CachePurgeAll()
	dbpkg.AuditLog("vayudomains.website.save", dbpkg.AuditActor(r), d.Host,
		"mode="+cfg.Mode+" template="+cfg.Template+" allow_eval="+strconv.FormatBool(cfg.AllowEval))
	writeJSON(w, r, http.StatusOK, map[string]any{"status": "ok", "host": d.Host, "mode": cfg.Mode})
}

// scopedWebsiteConfig validates a submitted website configuration and merges it
// with what is already stored, so fields this surface does not edit survive.
//
// Shared by the console and the MCP tools rather than duplicated: two validators
// for one shape is how one of them ends up accepting a mode the renderer does
// not know, and a domain then serves nothing.
func scopedWebsiteConfig(d domain.Domain, mode, template string, c bizsite.Content) (domain.SiteConfig, error) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	valid := false
	for _, m := range scopedSiteModes {
		if m.Value == mode {
			valid = true
			break
		}
	}
	// "custom" is accepted only when a bundle is actually deployed for this site.
	//
	// Same rule the primary's Website settings enforce, and for the same reason:
	// selecting a mode with nothing behind it publishes a domain that serves a
	// 404 at its root, which looks like a broken site rather than an unfinished
	// choice. It is absent from scopedSiteModes on purpose — a bundle is an
	// upload, not a radio button — and appears there only once one exists.
	if mode == "custom" && customsite.Deployed(scopedBundleDir(d)) {
		valid = true
	}
	if !valid {
		if mode == "custom" {
			return domain.SiteConfig{}, errNoBundleDeployed
		}
		return domain.SiteConfig{}, errUnknownSiteMode(mode)
	}
	// An unknown template key resolves to the default rather than being stored:
	// a stored key nothing matches renders an unstyled page later, far from the
	// save that caused it.
	template = bizsite.ByKey(strings.TrimSpace(template)).Key

	// Carry forward what this surface does not edit.
	allowEval := false
	if prev, ok := d.Site(); ok {
		old := bizsite.ParseContent(prev.Content)
		if len(c.Services) == 0 {
			c.Services = old.Services
		}
		if len(c.Gallery) == 0 {
			c.Gallery = old.Gallery
		}
		if c.SectionA == "" {
			c.SectionA = old.SectionA
		}
		// The eval opt-in is a property of the SITE, not of the content, and it
		// is carried HERE — in the one function both the console and the
		// connector go through — rather than at each call site. The connector
		// restored it after calling this; the console did not, so an operator who
		// turned it on and then pressed "Save & publish" for an unrelated reason
		// silently lost every animation on their site, with the setting still
		// reading as something they had chosen. This file already carries a note
		// about losing work nobody touched; that was the same defect wearing a
		// different field's name.
		allowEval = prev.AllowEval
	}

	raw, err := json.Marshal(c)
	if err != nil {
		return domain.SiteConfig{}, err
	}
	return domain.SiteConfig{Mode: mode, Template: template, Content: string(raw), AllowEval: allowEval}, nil
}

// scopedWebsiteConfigPreserving switches a domain's MODE while keeping every
// content field exactly as stored.
//
// Publishing a hand-built site is a decision about what the domain SERVES, not
// an instruction to forget the business details. The first version routed
// through scopedWebsiteConfig with an empty Content, whose carry-forward only
// rescues Services, Gallery and SectionA — so name, tagline, about, phone,
// email, address, hours and both button fields were blanked. An operator who
// later switched back to the template found them gone, with nothing having
// warned them. Losing work nobody touched is the defect this whole file already
// guards against on the form; it was reintroduced from the other side.
func scopedWebsiteConfigPreserving(d domain.Domain, mode, template string) (domain.SiteConfig, error) {
	prev, _ := d.Site()
	if template == "" {
		template = prev.Template
	}
	return scopedWebsiteConfig(d, mode, template, bizsite.ParseContent(prev.Content))
}

type siteModeError string

func (e siteModeError) Error() string {
	return "unknown site mode " + string(e) + " — use blog, business or business_subpath"
}

func errUnknownSiteMode(m string) error { return siteModeError(m) }

// errNoBundleDeployed distinguishes "that mode does not exist" from "that mode
// exists and you have not uploaded anything to serve in it". Collapsing the two
// would tell an operator their upload feature is unsupported.
var errNoBundleDeployed = bundleError(
	"no uploaded website exists for this domain yet — upload one first, or ask an assistant to build one")
