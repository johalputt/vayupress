// SPDX-License-Identifier: Apache-2.0

package main

// admin_os_power.go — VayuOS "Power & Maintenance".
//
// A single, safe control room for taking the public site offline and for
// restarting the app:
//
//   - Maintenance mode (on/off): the reversible "power switch". While on, every
//     PUBLIC request gets a clean, premium "under maintenance" page (503); the
//     VayuOS console (/os), the health probes and the operator's own browsing
//     stay live, so the site can always be brought back from the web.
//   - Restart: gracefully restarts the app (systemd's Restart=always brings it
//     straight back), for a quick refresh or after an update.
//   - Shut down: turns maintenance on and then restarts, so the app comes back
//     up with the public site OFF and stays that way until maintenance is turned
//     off again — a "stay offline" that never locks the operator out of /os.
//
// The self-signal path reuses the process's existing SIGTERM graceful-shutdown
// (plugins, Tor space, HTTP server all drain) — we never hard-kill.

import (
	"html"
	htmpl "html/template"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/johalputt/vayupress/internal/config"
	"github.com/johalputt/vayupress/internal/logging"
	"github.com/johalputt/vayupress/internal/render"
	"github.com/johalputt/vayupress/internal/settings"
)

// maintenanceExemptPrefixes are path prefixes that stay reachable while the site
// is in maintenance — the admin console and the operational/well-known surfaces,
// so the operator can always turn maintenance back off and uptime probes keep
// working. Mirrors (a subset of) the shield's bypass list.
var maintenanceExemptPrefixes = []string{
	"/os", "/__vayushield", "/__vayuanalytics", "/.well-known", "/mcp", "/oauth", "/health",
}

// maintenancePathExempt reports whether a path stays reachable while the site is
// in maintenance. Critically this includes the WHOLE /os console — so the login
// page (/os/login), its assets (/os/static) and the Power page (/os/power) all
// keep working and the operator can always turn maintenance back off from the
// web. The prefix match is segment-aware ("/os" matches "/os" and "/os/…" but
// never a public page like "/osborne").
func maintenancePathExempt(p string) bool {
	if p == "/favicon.ico" {
		return true
	}
	for _, pre := range maintenanceExemptPrefixes {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

// maintenanceModeOn reports whether the operator has taken the public site down.
func (a *App) maintenanceModeOn(r *http.Request) bool {
	return a.siteSettings != nil && a.siteSettings.Get(r.Context(), settings.ForPrimary(), settings.KeyMaintenanceMode) == "on"
}

// maintenanceMiddleware serves the premium maintenance page for public requests
// while maintenance mode is on. It is a near-free pass-through otherwise. The
// admin console, operational endpoints and the operator's own authenticated
// browsing are always let through so the site can be recovered from the web.
func (a *App) maintenanceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.siteSettings == nil || !a.maintenanceModeOn(r) {
			next.ServeHTTP(w, r)
			return
		}
		// The admin console (/os, incl. /os/login and /os/static), the health
		// probes and the well-known/shield/MCP surfaces are always reachable — so
		// the operator can ALWAYS sign in and lift maintenance from the web, and
		// uptime checks keep working. This is the guarantee that VayuOS never goes
		// offline with the public site.
		if maintenancePathExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		// A signed-in operator keeps seeing the real site so they can verify a
		// change before lifting maintenance.
		if a.isAdminRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		a.serveMaintenance(w, r)
	})
}

// serveMaintenance writes the premium maintenance page as a 503 with a
// Retry-After, so crawlers treat it as a transient outage (not a dead site).
func (a *App) serveMaintenance(w http.ResponseWriter, r *http.Request) {
	msg := ""
	if a.siteSettings != nil {
		msg = a.siteSettings.Get(r.Context(), settings.ForPrimary(), settings.KeyMaintenanceMessage)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "120")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(maintenancePageHTML(msg)))
}

// maintenancePageHTML is the self-contained (no external CSS/JS — those are
// blocked in maintenance) premium "under maintenance" page shown to visitors.
func maintenancePageHTML(message string) string {
	brand := html.EscapeString(config.Cfg.Domain)
	msg := "We’re making things better behind the scenes and will be back online shortly. Thanks for your patience."
	if m := strings.TrimSpace(message); m != "" {
		msg = html.EscapeString(m)
	}
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>` + brand + ` — under maintenance</title>
<meta name="robots" content="noindex">
</head><body style="margin:0;min-height:100vh;display:flex;background:#05070d;color:#e5e7eb;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif">
<main style="margin:auto;max-width:34rem;padding:2.5rem 1.5rem;text-align:center">
  <div style="position:relative;width:96px;height:96px;margin:0 auto 1.75rem">
    <div style="position:absolute;inset:0;border-radius:9999px;background:radial-gradient(circle,rgba(45,212,191,.35),transparent 70%);filter:blur(8px);animation:vp-pulse 2.6s ease-in-out infinite"></div>
    <div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:3rem" aria-hidden="true">🛠️</div>
  </div>
  <h1 style="font-family:'Space Grotesk',system-ui,sans-serif;font-size:1.9rem;font-weight:700;letter-spacing:-.02em;margin:0 0 .6rem;background:linear-gradient(108deg,#5eead4,#2dd4bf 40%,#818cf8 110%);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent">We’ll be right back</h1>
  <p style="color:#94a3b8;font-size:1.02rem;line-height:1.6;margin:0 auto 1.75rem;max-width:28rem">` + msg + `</p>
  <div style="display:inline-flex;align-items:center;gap:.6rem;padding:.55rem 1.1rem;border:1px solid rgba(255,255,255,.09);border-radius:9999px;background:rgba(255,255,255,.03);color:#cbd5e1;font-size:.85rem">
    <span style="width:.55rem;height:.55rem;border-radius:9999px;background:#2dd4bf;box-shadow:0 0 0 0 rgba(45,212,191,.6);animation:vp-dot 1.8s ease-out infinite"></span>
    Upgrading the system — this page refreshes itself
  </div>
  <p style="color:#475569;font-size:.75rem;margin-top:2rem"><strong style="color:#64748b">` + brand + `</strong> · powered by VayuPress</p>
</main>
<style>
@keyframes vp-pulse{0%,100%{transform:scale(1);opacity:.75}50%{transform:scale(1.12);opacity:1}}
@keyframes vp-dot{0%{box-shadow:0 0 0 0 rgba(45,212,191,.55)}70%{box-shadow:0 0 0 9px rgba(45,212,191,0)}100%{box-shadow:0 0 0 0 rgba(45,212,191,0)}}
@media (prefers-reduced-motion:reduce){*{animation:none!important}}
</style>
</body></html>`
}

// ── Admin page + actions ─────────────────────────────────────────────────────

// handleOSPower renders the Power & Maintenance control page.
func (a *App) handleOSPower(w http.ResponseWriter, r *http.Request) {
	nonce := render.CSPNonce(r)
	cfg := a.getOSSettings(r.Context())
	on := a.maintenanceModeOn(r)
	msg := ""
	if a.siteSettings != nil {
		msg = a.siteSettings.Get(r.Context(), settings.ForPrimary(), settings.KeyMaintenanceMessage)
	}
	crawlersOff := a.crawlersBlocked(r.Context())
	feedbackAddr := a.feedbackEmail(r.Context())
	writeOSHTML(w, r, adminOSLayout(nonce, "Power & Maintenance", "operations", cfg,
		htmpl.HTML(osPowerBody(nonce, on, msg, crawlersOff, feedbackAddr))))
}

// handleOSPowerPreview renders the public maintenance page inside the console so
// the operator can see exactly what visitors get, without taking the site down.
func (a *App) handleOSPowerPreview(w http.ResponseWriter, r *http.Request) {
	msg := ""
	if a.siteSettings != nil {
		msg = a.siteSettings.Get(r.Context(), settings.ForPrimary(), settings.KeyMaintenanceMessage)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(maintenancePageHTML(msg)))
}

// osPowerBody builds the control page. The inline script (nonce'd) drives the
// toggle and the restart/shutdown buttons; all three POST to the CSRF-protected
// /os/api/power/* endpoints.
func osPowerBody(nonce string, on bool, message string, crawlersOff bool, feedbackAddr string) string {
	esc := html.EscapeString
	onAttr := "0"
	if on {
		onAttr = "1"
	}
	crawlAttr := "0"
	crawlBadge := `<span class="badge badge--ok">Allowed</span>`
	crawlToggleLabel := "Block all crawlers"
	crawlToggleClass := "btn btn--danger btn--sm"
	crawlHint := "Search engines and AI crawlers <strong>can</strong> index your public site. Turn this on to shut them out."
	if crawlersOff {
		crawlAttr = "1"
		crawlBadge = `<span class="badge badge--warn">Blocked</span>`
		crawlToggleLabel = "Allow crawlers"
		crawlToggleClass = "btn btn--primary btn--sm"
		crawlHint = "Search engines and AI crawlers are <strong>blocked</strong> — robots.txt disallows everything, known crawler bots get a 403, and every public page is marked <code>noindex</code>."
	}
	statusBadge := `<span class="badge badge--ok">Live</span>`
	toggleLabel := "Turn maintenance ON"
	toggleClass := "btn btn--danger"
	stateHint := "Your public site is <strong>live</strong>. Visitors reach it normally."
	if on {
		statusBadge = `<span class="badge badge--warn">In maintenance</span>`
		toggleLabel = "Turn maintenance OFF (go live)"
		toggleClass = "btn btn--primary"
		stateHint = "Your public site is <strong>offline</strong> — visitors see the maintenance page. Your admin console stays open."
	}
	return `<div class="page-header"><h1>Power &amp; Maintenance ` + statusBadge + `</h1>
<p class="page-sub">Take the public site offline behind a premium maintenance page, or restart the app. Your VayuOS console always stays reachable.</p></div>

<div class="card" data-power-card>
  <div class="settings-row">
    <div class="settings-row-info">
      <div class="settings-row-label">Maintenance mode</div>
      <div class="settings-row-hint" data-state-hint>` + stateHint + `</div>
    </div>
    <button type="button" class="` + toggleClass + `" data-power-toggle data-on="` + onAttr + `">` + toggleLabel + `</button>
  </div>
  <div class="section-divider"></div>
  <div class="field">
    <label class="field-label" for="mnt-msg">Message shown to visitors (optional)</label>
    <textarea id="mnt-msg" class="input" rows="2" maxlength="280" placeholder="We’re upgrading the system and will be back shortly.">` + esc(message) + `</textarea>
    <div class="mt-2" style="display:flex;gap:.5rem;flex-wrap:wrap">
      <button type="button" class="btn btn--sm" data-power-savemsg>Save message</button>
      <a class="btn btn--sm btn--ghost" href="/os/power/preview" target="_blank" rel="noopener">Preview the page ↗</a>
    </div>
  </div>
</div>

<div class="card" data-crawlers-card>
  <div class="settings-row">
    <div class="settings-row-info">
      <div class="settings-row-label">Search engine &amp; AI crawler access ` + crawlBadge + `</div>
      <div class="settings-row-hint" data-crawlers-hint>` + crawlHint + `</div>
    </div>
    <button type="button" class="` + crawlToggleClass + `" data-crawlers-toggle data-on="` + crawlAttr + `">` + crawlToggleLabel + `</button>
  </div>
  <div class="settings-row-hint mt-2 text-xs muted">Blocks Google, Bing, GPTBot, ClaudeBot, PerplexityBot and other AI/search bots. Your visitors, the VayuOS console and VayuMCP are never affected.</div>
</div>

<div class="card">
  <div class="settings-block-title">Feedback &amp; bug reports</div>
  <p class="text-sm muted">The 💡 button in the top bar lets you and your team report a bug, request an improvement or suggest a feature — it opens a PGP-encrypted email to the inbox below (screenshots and files supported). By default it reaches the <strong>VayuPress team at feedback@vayupress.com</strong>; change it here to collect reports in your own inbox instead.</p>
  <div class="field">
    <label class="field-label" for="fb-addr">Feedback inbox</label>
    <div style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">
      <input id="fb-addr" class="input" type="email" style="max-width:22rem" value="` + esc(feedbackAddr) + `" placeholder="feedback@vayupress.com">
      <button type="button" class="btn btn--sm" data-fb-save>Save</button>
      <a class="btn btn--ghost btn--sm" href="/os/vayumail/compose?feedback=1">Open a test report ↗</a>
    </div>
  </div>
</div>

<div class="card">
  <div class="settings-block-title">Restart &amp; shutdown</div>
  <p class="text-sm muted">The app drains in-flight requests, then restarts. It comes back automatically within a few seconds (your service runs with auto-restart).</p>
  <div class="settings-row">
    <div class="settings-row-info">
      <div class="settings-row-label">Restart the app</div>
      <div class="settings-row-hint">A quick refresh — the site comes back <strong>live</strong>. Use after an update or to clear transient state.</div>
    </div>
    <button type="button" class="btn btn--primary btn--sm" data-power-restart>Restart now</button>
  </div>
  <div class="settings-row">
    <div class="settings-row-info">
      <div class="settings-row-label">Shut the site down</div>
      <div class="settings-row-hint">Turns maintenance ON and restarts, so the app comes back with the public site <strong>OFF</strong> — and stays off until you turn maintenance off here.</div>
    </div>
    <button type="button" class="btn btn--danger btn--sm" data-power-shutdown>Shut down</button>
  </div>
</div>

<script nonce="` + nonce + `">
(function(){'use strict';
function csrf(){var m=document.cookie.match(/(?:^|;\s*)vp_csrf=([^;]+)/);return m?decodeURIComponent(m[1]):'';}
function toast(msg,kind){if(window.vpToast){window.vpToast(msg,kind);}}
function post(url,body){return fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:body?JSON.stringify(body):'{}'});}
var card=document.querySelector('[data-power-card]');
var tgl=document.querySelector('[data-power-toggle]');
if(tgl){tgl.addEventListener('click',function(){
  var turnOn=tgl.getAttribute('data-on')!=='1';
  var apply=function(){
  tgl.disabled=true;
  post('/os/api/power/maintenance',{on:turnOn}).then(function(r){return r.json();}).then(function(j){
    if(j&&j.ok){toast(turnOn?'Maintenance mode is ON — the public site is offline.':'Maintenance mode is OFF — your site is live.','ok');setTimeout(function(){location.reload();},700);}
    else{tgl.disabled=false;toast((j&&j.error&&j.error.message)||'Could not change maintenance mode','error');}
  }).catch(function(){tgl.disabled=false;toast('Network error','error');});
  };
  if(turnOn){vpConfirm({title:'Go offline?',message:'Take the public site offline now? Visitors will see the maintenance page. Your admin console stays open.',confirm:'Go offline'},apply);return;}
  apply();
});}
var saveBtn=document.querySelector('[data-power-savemsg]');
if(saveBtn){saveBtn.addEventListener('click',function(){
  var ta=document.getElementById('mnt-msg');
  post('/os/api/power/maintenance',{message:(ta&&ta.value)||''}).then(function(r){return r.json();}).then(function(j){
    toast(j&&j.ok?'Message saved.':'Could not save the message','ok');
  }).catch(function(){toast('Network error','error');});
});}
var fbBtn=document.querySelector('[data-fb-save]');
if(fbBtn){fbBtn.addEventListener('click',function(){
  var inp=document.getElementById('fb-addr');
  var v=((inp&&inp.value)||'').trim();
  fbBtn.disabled=true;
  post('/os/api/settings',{key:'vayupress.feedback_email',value:v}).then(function(r){return r.json();}).then(function(j){
    fbBtn.disabled=false;
    toast(j&&j.status==='ok'?'Feedback inbox saved.':'Could not save the address','ok');
  }).catch(function(){fbBtn.disabled=false;toast('Network error','error');});
});}
var crawlBtn=document.querySelector('[data-crawlers-toggle]');
if(crawlBtn){crawlBtn.addEventListener('click',function(){
  var block=crawlBtn.getAttribute('data-on')!=='1';
  var apply=function(){
  crawlBtn.disabled=true;
  post('/os/api/power/crawlers',{block:block}).then(function(r){return r.json();}).then(function(j){
    if(j&&j.ok){toast(block?'Search engines & AI crawlers are now blocked.':'Crawlers are allowed again — your site can be indexed.','ok');setTimeout(function(){location.reload();},700);}
    else{crawlBtn.disabled=false;toast((j&&j.error&&j.error.message)||'Could not change crawler access','error');}
  }).catch(function(){crawlBtn.disabled=false;toast('Network error','error');});
  };
  if(block){vpConfirm({title:'Block crawlers?',message:'Block all search engines and AI crawlers now? Your site stops being indexed until you allow crawlers again.',confirm:'Block'},apply);return;}
  apply();
});}
var reBtn=document.querySelector('[data-power-restart]');
if(reBtn){reBtn.addEventListener('click',function(){
  vpConfirm({title:'Restart the app?',message:'Restart the app now? The site is unavailable for a few seconds and comes back automatically.',confirm:'Restart'},function(){
  reBtn.disabled=true;
  post('/os/api/power/restart').then(function(r){return r.json();}).then(function(j){
    toast('Restarting… this page will reconnect in a few seconds.','ok');
    setTimeout(function(){location.reload();},9000);
  }).catch(function(){toast('Restart signal sent — reconnecting shortly.','ok');setTimeout(function(){location.reload();},9000);});
  });
});}
var offBtn=document.querySelector('[data-power-shutdown]');
if(offBtn){offBtn.addEventListener('click',function(){
  vpConfirm({title:'Shut the site down?',message:'Maintenance mode turns ON and the app restarts, coming back with the public site OFF. You can bring it back any time from this page.',confirm:'Shut down'},function(){
  offBtn.disabled=true;
  post('/os/api/power/shutdown').then(function(r){return r.json();}).then(function(j){
    toast('Shutting down to maintenance… reconnecting shortly.','ok');
    setTimeout(function(){location.reload();},9000);
  }).catch(function(){toast('Shutdown signal sent.','ok');setTimeout(function(){location.reload();},9000);});
  });
});}
})();
</script>`
}

// handleOSPowerMaintenance toggles maintenance mode and/or saves the message.
func (a *App) handleOSPowerMaintenance(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "administrator access required", "")
		return
	}
	if a.siteSettings == nil {
		writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "settings unavailable", "")
		return
	}
	var body struct {
		On      *bool   `json:"on"`
		Message *string `json:"message"`
	}
	if err := readCappedJSON(w, r, 4*1024, &body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "bad-json", "invalid request body", "")
		return
	}
	kv := map[string]string{}
	if body.On != nil {
		if *body.On {
			kv[settings.KeyMaintenanceMode] = "on"
		} else {
			kv[settings.KeyMaintenanceMode] = "off"
		}
	}
	if body.Message != nil {
		m := strings.TrimSpace(*body.Message)
		if len(m) > 280 {
			m = m[:280]
		}
		kv[settings.KeyMaintenanceMessage] = m
	}
	if len(kv) == 0 {
		writeJSON(w, r, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if err := a.siteSettings.SetMany(r.Context(), settings.ForPrimary(), kv); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "write_failed", "could not save the setting", "")
		return
	}
	if body.On != nil {
		logging.LogWarn("power", "maintenance mode set to "+kv[settings.KeyMaintenanceMode]+" by admin")
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "maintenance": a.maintenanceModeOn(r)})
}

// handleOSPowerRestart gracefully restarts the app (SIGTERM → the process's own
// graceful shutdown → the service manager restarts it live).
func (a *App) handleOSPowerRestart(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "administrator access required", "")
		return
	}
	logging.LogWarn("power", "app restart requested by admin")
	writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "action": "restart"})
	scheduleSelfShutdown()
}

// handleOSPowerShutdown turns maintenance ON, then restarts — so the app returns
// with the public site offline and stays that way until maintenance is lifted.
func (a *App) handleOSPowerShutdown(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "administrator access required", "")
		return
	}
	if a.siteSettings != nil {
		_ = a.siteSettings.SetMany(r.Context(), settings.ForPrimary(), map[string]string{settings.KeyMaintenanceMode: "on"})
	}
	logging.LogWarn("power", "app shutdown-to-maintenance requested by admin")
	writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "action": "shutdown"})
	scheduleSelfShutdown()
}

// scheduleSelfShutdown sends this process SIGTERM after a short grace period, so
// the HTTP response is flushed first. SIGTERM triggers the existing graceful
// shutdown in main() (plugins, Tor space and the HTTP server all drain); the
// service manager (systemd Restart=always) then brings the app back.
func scheduleSelfShutdown() {
	go func() {
		time.Sleep(700 * time.Millisecond)
		if p, err := os.FindProcess(os.Getpid()); err == nil {
			_ = p.Signal(syscall.SIGTERM)
		}
	}()
}
