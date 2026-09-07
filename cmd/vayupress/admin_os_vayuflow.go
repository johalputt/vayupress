// SPDX-License-Identifier: Apache-2.0

package main

// admin_os_vayuflow.go — /os/vayuflow, the automation console (ADR-0151).
//
// The page has one job beyond listing flows: make the blast radius of each one
// legible before it is armed. A flow's dangerous property is never its trigger
// or its name — it is what it may write, whose authority it borrows, and what
// it is allowed to spend. So those three are on the summary line of every
// accordion, visible while collapsed, rather than behind a click.
//
// Dry-run is the default and the page says what that means in the same words
// the engine uses: the whole flow executes, the effects are captured, and the
// capability boundary refuses them. An operator reading "test mode" here and
// "dry-run" in the trail would be reconciling two vocabularies for one state.

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/render"
	"github.com/johalputt/vayupress/internal/safefetch"
	"github.com/johalputt/vayupress/internal/vayuflow"
	"github.com/johalputt/vayupress/internal/vayuflow/flowaudit"
)

// handleOSVayuFlow renders the automation console.
func (a *App) handleOSVayuFlow(w http.ResponseWriter, r *http.Request) {
	nonce := render.CSPNonce(r)
	cfg := a.getOSSettings(r.Context())
	csrfTokenFor(w, r)

	var (
		flows    []vayuflow.Flow
		rejected map[string]error
		stats    vayuflow.Stats
		runs     []vayuflow.Run
	)
	if a.flowStore != nil {
		flows, rejected, _ = a.flowStore.LoadableFlows(r.Context())
		all, err := a.flowStore.List(r.Context())
		if err == nil {
			flows = all // show disabled flows too; the chip carries their state
		}
	}
	if a.flowRuns != nil {
		stats, _ = a.flowRuns.StatsSince(r.Context(), time.Now().Add(-24*time.Hour))
		runs, _ = a.flowRuns.Recent(r.Context(), "", 25)
	}

	pending := 0
	if a.flowInbox != nil {
		pending, _ = a.flowInbox.PendingCount(r.Context())
	}
	roles := map[string]string{}
	resolve := a.flowRoleResolver()
	for _, f := range flows {
		if _, seen := roles[f.Owner]; seen {
			continue
		}
		// An unresolvable owner is recorded as an EMPTY role rather than
		// skipped, so the report reads it as "could not check" and fails
		// closed — the same answer the runner gives.
		role, err := resolve(r.Context(), f.Owner)
		if err != nil {
			role = ""
		}
		roles[f.Owner] = role
	}
	checks := flowaudit.Run(flowaudit.Inputs{
		Wired:           a.flowStore != nil && a.flowRunner != nil,
		Flows:           flows,
		Rejected:        rejected,
		OwnerRoles:      roles,
		Stats:           stats,
		PendingInbox:    pending,
		OnionMode:       safefetch.ClearnetBlocked(),
		ModelConfigured: a.aiAssist != nil && a.aiAssist.Enabled(),
		ModelLocal:      flowModel{c: a.aiAssist}.Local(),
	})

	body := vayuFlowPage(flows, rejected, stats, runs, checks, a.flowStore != nil, flowModel{c: a.aiAssist}.Local())
	full := adminOSShellHead(nonce, "VayuFlow", "vayuflow", cfg) + body +
		adminOSShellFoot(nonce, vayuFlowScript, pageUsesAlpine(body))
	writeOSHTML(w, r, full)
}

// handleOSVayuFlowArm moves a flow between dry-run and live.
//
// Arming is its own endpoint rather than a field on a save, because it is the
// moment a flow stops being a description and starts being an actor. The audit
// entry records the actor AND the prior mode: "armed" without a from-state
// cannot distinguish a first arming from a re-arming, and the difference
// matters when reading back why something started happening.
func (a *App) handleOSVayuFlowArm(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "admin role required", "")
		return
	}
	if a.flowStore == nil {
		writeAPIError(w, r, http.StatusInternalServerError, "no-store", "automation store unavailable", "")
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeAPIError(w, r, http.StatusBadRequest, "bad-request", "no flow id", "")
		return
	}
	mode, ok := armModeFor(r.URL.Query().Get("mode"))
	if !ok {
		// An unrecognised value must not silently pick a mode. Defaulting to
		// dry-run would be the safe-looking choice and would still be the
		// endpoint answering a question the operator asked.
		writeAPIError(w, r, http.StatusBadRequest, "bad-request",
			`expected mode=live or mode=dry; nothing was changed`, "")
		return
	}
	prior, err := a.flowStore.SetMode(r.Context(), id, mode)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "save-failed", err.Error(), "")
		return
	}
	dbpkg.AuditLog("vayuflow.arm", dbpkg.AuditActor(r), id,
		fmt.Sprintf("%s -> %s", prior, mode))
	writeJSON(w, r, http.StatusOK, map[string]string{
		"status": "ok", "mode": mode.String(), "prior": prior.String(),
	})
}

// armModeFor maps the query value to a mode. It returns ok=false for anything
// it does not recognise rather than choosing.
func armModeFor(v string) (vayuflow.RunMode, bool) {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "live":
		return vayuflow.RunLive, true
	case "dry", "dry-run", "dryrun":
		return vayuflow.RunDryRun, true
	}
	return 0, false
}

// handleOSVayuFlowRun executes a flow once, now, on the operator's press.
func (a *App) handleOSVayuFlowRun(w http.ResponseWriter, r *http.Request) {
	if !a.isAdminRequest(r) {
		writeAPIError(w, r, http.StatusForbidden, "forbidden", "admin role required", "")
		return
	}
	if a.flowStore == nil || a.flowRunner == nil {
		writeAPIError(w, r, http.StatusInternalServerError, "no-store", "automation engine unavailable", "")
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	f, err := a.flowStore.Get(r.Context(), id)
	if err != nil {
		writeAPIError(w, r, http.StatusNotFound, "not-found", err.Error(), "")
		return
	}
	// Pressing Run twice IS two runs, so the identity is fresh each press.
	identity := "manual-" + newFlowArticleID()
	run, err := a.flowRunner.Execute(r.Context(), f, "manual · "+dbpkg.AuditActor(r), identity, vayuflow.Subject{})
	if err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "run-failed", err.Error(), "")
		return
	}
	dbpkg.AuditLog("vayuflow.run", dbpkg.AuditActor(r), id, string(run.Status))
	writeJSON(w, r, http.StatusOK, map[string]string{
		"status": "ok", "run": run.ID, "outcome": string(run.Status),
		"writes": fmt.Sprintf("%d / %d", run.Spend.Writes, run.Budget.MaxWritesPerRun),
	})
}

// flowCheckChip renders a posture verdict. Only Pass gets the "on" tone — a
// Context row is a fact, not a success, and toning it green would let the
// honest-ceiling row read as reassurance.
func flowCheckChip(s flowaudit.Status) string {
	switch s {
	case flowaudit.Pass:
		return `<span class="mon-chip mon-chip--on" title="` + s.String() + `">ok</span>`
	case flowaudit.Warn:
		return `<span class="mon-chip mon-chip--off" title="` + s.String() + `">look</span>`
	case flowaudit.Fail:
		return `<span class="mon-chip mon-chip--off" title="` + s.String() + `">act</span>`
	}
	return `<span class="mon-chip mon-chip--off" title="` + s.String() + `">note</span>`
}

func flowCheckIcon(s flowaudit.Status) string {
	switch s {
	case flowaudit.Pass:
		return "✓"
	case flowaudit.Fail:
		return "✕"
	case flowaudit.Warn:
		return "!"
	}
	return "·"
}

// flowModeChip renders a flow's arming state so it reads while collapsed.
func flowModeChip(f vayuflow.Flow) string {
	if !f.Enabled {
		return `<span class="mon-chip mon-chip--off">disabled</span>`
	}
	if f.Mode == vayuflow.RunLive {
		return `<span class="mon-chip mon-chip--on">live</span>`
	}
	return `<span class="mon-chip mon-chip--off">dry-run</span>`
}

// runStatusChip renders one run's outcome.
func runStatusChip(s vayuflow.RunStatus) string {
	switch s {
	case vayuflow.StatusSucceeded:
		return `<span class="mon-chip mon-chip--on">succeeded</span>`
	case vayuflow.StatusRefused:
		return `<span class="mon-chip mon-chip--off">refused</span>`
	case vayuflow.StatusInterrupted:
		return `<span class="mon-chip mon-chip--off">interrupted</span>`
	case vayuflow.StatusFailed:
		return `<span class="mon-chip mon-chip--off">failed</span>`
	}
	return `<span class="mon-chip mon-chip--off">` + html.EscapeString(string(s)) + `</span>`
}

// vayuFlowPage builds the console body. Pure, so it can be rendered and
// asserted on without a request or a database.
// modelLocal is passed rather than inferred because the flow document cannot
// know it: a model step is outbound only when the configured provider is
// remote, and only the install can say which it has. The banner below used to
// answer without asking, and got it wrong for every local provider.
func vayuFlowPage(flows []vayuflow.Flow, rejected map[string]error,
	stats vayuflow.Stats, runs []vayuflow.Run, checks []flowaudit.Check,
	wired, modelLocal bool) string {
	esc := html.EscapeString
	var b strings.Builder

	b.WriteString(`<div class="page-header"><h1>VayuFlow</h1><div class="page-actions">` +
		`<a class="btn btn--ghost btn--sm" href="/os/adr">ADR-0151</a>` +
		`<span id="flow-status" class="text-sm muted" role="status" aria-live="polite"></span>` +
		`</div></div>`)
	b.WriteString(`<p class="page-sub">Automations this install runs on its own: when something ` +
		`happens, if a condition holds, do a bounded piece of work. Every flow is armed by a named ` +
		`operator, spends against ceilings it declared before it could be saved, and records what it ` +
		`did. <b>A new flow starts in dry-run</b>: the whole flow executes and every effect is ` +
		`captured and refused at the capability boundary, so what you read is what a live run would ` +
		`do.</p>`)

	armed := 0
	for _, f := range flows {
		if f.Enabled && f.Mode == vayuflow.RunLive {
			armed++
		}
	}
	b.WriteString(`<div class="stat-grid">` +
		osStatTile("Armed live", strconv.Itoa(armed), tone(armed > 0)) +
		osStatTile("Runs · 24h", strconv.Itoa(stats.Runs), "") +
		osStatTile("Refusals · 24h", strconv.Itoa(stats.Refused), "") +
		osStatTile("At a ceiling · 24h", strconv.Itoa(stats.BudgetCapped), tone(stats.BudgetCapped > 0)) +
		`</div>`)

	if !wired {
		b.WriteString(`<div class="warn-box">The automation engine is not running in this build, so ` +
			`nothing on this page can fire. Flows are listed from storage for reference only.</div>`)
	}

	// ── Posture ──────────────────────────────────────────────────────────────
	pass, warn, fail, ctxRows := flowaudit.Summary(checks)
	b.WriteString(`<div class="section-head"><span class="section-head__title">Posture</span>` +
		`<span class="section-head__hint">Computed now, from live state — ` +
		strconv.Itoa(fail) + ` to act on, ` + strconv.Itoa(warn) + ` to look at, ` +
		strconv.Itoa(pass) + ` ok, ` + strconv.Itoa(ctxRows) + ` noted</span></div>`)
	b.WriteString(`<div class="mon-stack">`)
	for i, c := range checks {
		b.WriteString(monAcc(flowCheckIcon(c.Status), esc(c.Title), "", flowCheckChip(c.Status),
			i == 0 && c.Status != flowaudit.Pass,
			`<div class="card"><p class="text-sm muted">`+esc(c.Detail)+`</p></div>`))
	}
	b.WriteString(`</div>`)

	// ── What can be automated ────────────────────────────────────────────────
	b.WriteString(`<div class="section-head"><span class="section-head__title">What a flow may do</span>` +
		`<span class="section-head__hint">The capability registry, in full</span></div>`)
	b.WriteString(`<div class="card"><p class="text-sm muted">Every action an automation can take is ` +
		`registered with what it touches, the strongest write it may perform, what it does in a Tor ` +
		`Space, whether it can be undone, and the role its owner must still hold. An action with no ` +
		`registration cannot be invoked at all.</p>`)
	b.WriteString(`<table class="table"><thead><tr><th>Action</th><th>Writes</th><th>Tor</th>` +
		`<th>Undo</th><th>Owner must be</th></tr></thead><tbody>`)
	for _, c := range vayuflow.Capabilities() {
		b.WriteString(`<tr><td><span class="mono">` + esc(c.Action) + `</span></td>` +
			`<td>` + esc(c.Writes.String()) + `</td>` +
			`<td>` + esc(c.Onion.String()) + `</td>` +
			`<td>` + esc(c.Undo.String()) + `</td>` +
			`<td>` + esc(c.MinRole) + `</td></tr>`)
	}
	b.WriteString(`</tbody></table>`)
	b.WriteString(`<p class="text-sm muted">Settings, users, keys, domains, protection tiers and ` +
		`payment configuration are deliberately absent and cannot be automated in this version.</p>`)
	b.WriteString(`</div>`)

	// ── Flows ────────────────────────────────────────────────────────────────
	b.WriteString(`<div class="section-head"><span class="section-head__title">Flows</span>` +
		`<span class="section-head__hint">Create, arm, inspect &amp; run</span></div>`)
	if len(flows) == 0 {
		b.WriteString(`<div class="card"><p class="text-sm muted">No automations are defined yet. ` +
			`Build one below — it starts switched off and in dry-run, and stays that way until ` +
			`you decide otherwise.</p></div>`)
	}
	b.WriteString(`<div class="mon-stack">` +
		monAcc("✚", "Create a flow", "Starts switched off, in dry-run", "", len(flows) == 0,
			flowEditorCard()) + `</div>`)
	b.WriteString(`<div class="mon-stack">`)
	for i, f := range flows {
		var body strings.Builder
		body.WriteString(`<div class="card">`)
		body.WriteString(`<div class="settings-block-title">Blast radius</div>`)
		body.WriteString(`<p class="text-sm muted">Highest write <b>` + esc(f.HighestWrite().String()) +
			`</b> · owner <span class="mono">` + esc(f.Owner) + `</span> must hold <b>` +
			esc(f.MinOwnerRole()) + `</b> when it runs · ceilings: ` +
			strconv.Itoa(f.Budget.MaxStepsPerRun) + ` steps, ` +
			strconv.Itoa(f.Budget.MaxWritesPerRun) + ` writes, ` +
			strconv.Itoa(f.Budget.MaxEgressPerRun) + ` fetches, ` +
			strconv.Itoa(f.Budget.MaxRunsPerHour) + `/hour, ` +
			esc(f.Budget.Timeout.String()) + ` wall clock.</p>`)
		body.WriteString(`<div class="settings-block-title">Mode</div>`)
		body.WriteString(`<p class="text-sm muted">` + esc(vayuflow.DescribeMode(f.Mode)) + `</p>`)
		body.WriteString(`<div class="settings-block-title">Steps</div>`)
		body.WriteString(`<p class="text-sm"><span class="mono">` + esc(vayuflow.ActionSummary(f.Steps)) + `</span></p>`)
		if f.NeedsEgress() {
			body.WriteString(`<div class="warn-box">This flow reaches a remote host. It is inert while ` +
				`the install runs as a Tor Space.</div>`)
		}
		// Said separately, and only about what is true. A model step reaches out
		// when the provider is remote and does not when it runs here, so the
		// banner names which of the two this install has rather than assuming the
		// dangerous one and calling every local generation an outbound call.
		if f.NeedsModel() {
			if modelLocal {
				body.WriteString(`<div class="text-sm muted">This flow calls a model. The configured ` +
					`provider runs on this host, so the step is not an outbound call and stays ` +
					`active in a Tor Space.</div>`)
			} else {
				body.WriteString(`<div class="warn-box">This flow calls a model, and the configured ` +
					`provider is remote — that makes the step an outbound call, so it is inert ` +
					`while the install runs as a Tor Space.</div>`)
			}
		}
		enableLabel, enableTo := "Switch on", "true"
		if f.Enabled {
			enableLabel, enableTo = "Switch off", "false"
		}
		body.WriteString(`<div class="flex-between">` +
			`<button type="button" class="btn btn--primary btn--sm" data-flow-run="` + esc(f.ID) + `">Run once now</button>` +
			`<button type="button" class="btn btn--sm" data-flow-enable="` + esc(f.ID) + `" data-flow-on="` + enableTo + `">` + enableLabel + `</button>` +
			`<button type="button" class="btn btn--sm" data-flow-arm="` + esc(f.ID) + `" data-flow-mode="live">Arm live</button>` +
			`<button type="button" class="btn btn--ghost btn--sm" data-flow-arm="` + esc(f.ID) + `" data-flow-mode="dry">Return to dry-run</button>` +
			`<button type="button" class="btn btn--ghost btn--sm" data-flow-delete="` + esc(f.ID) + `" data-flow-name="` + esc(f.Name) + `">Delete</button>` +
			`</div>`)
		body.WriteString(`</div>`)

		sub := vayuflow.TriggerSummary(f.Trigger) + " · v" + strconv.Itoa(f.Version)
		b.WriteString(monAcc("⚙", esc(f.Name), esc(sub), flowModeChip(f), i == 0, body.String()))
	}
	b.WriteString(`</div>`)

	if len(rejected) > 0 {
		b.WriteString(`<div class="card"><div class="settings-block-title">Flows that cannot run</div>` +
			`<p class="text-sm muted">These are enabled but their stored definition no longer ` +
			`validates, so the engine will not fire them. They are listed rather than skipped, because ` +
			`an automation an operator believes is armed and which silently never runs is the worst ` +
			`state this page can hide.</p><ul class="reset-list">`)
		for id, err := range rejected {
			b.WriteString(`<li class="text-sm"><span class="mono">` + esc(id) + `</span> — ` + esc(err.Error()) + `</li>`)
		}
		b.WriteString(`</ul></div>`)
	}

	// ── The trail ────────────────────────────────────────────────────────────
	b.WriteString(`<div class="section-head"><span class="section-head__title">Recent runs</span>` +
		`<span class="section-head__hint">What actually happened, and what it spent</span></div>`)
	b.WriteString(`<div class="card">`)
	if len(runs) == 0 {
		b.WriteString(`<p class="text-sm muted">Nothing has run yet.</p>`)
	}
	for _, run := range runs {
		var body strings.Builder
		body.WriteString(`<div class="card"><p class="text-sm muted">` +
			`Flow version <b>v` + strconv.Itoa(run.FlowVersion) + `</b> · cause <span class="mono">` +
			esc(run.Cause) + `</span> · mode <b>` + esc(run.Mode.String()) + `</b> · owner ` +
			`<span class="mono">` + esc(run.Owner) + `</span> ran as <b>` + esc(run.OwnerRole) + `</b></p>`)
		// Spend beside its ceiling. A count without its limit means nothing, and
		// a limit without its count hides the flow living at the edge of it.
		body.WriteString(`<p class="text-sm">Spent — steps <b>` +
			strconv.Itoa(run.Spend.Steps) + ` / ` + strconv.Itoa(run.Budget.MaxStepsPerRun) + `</b>, writes <b>` +
			strconv.Itoa(run.Spend.Writes) + ` / ` + strconv.Itoa(run.Budget.MaxWritesPerRun) + `</b>, fetches <b>` +
			strconv.Itoa(run.Spend.Egress) + ` / ` + strconv.Itoa(run.Budget.MaxEgressPerRun) + `</b></p>`)
		if run.Error != "" {
			body.WriteString(`<div class="warn-box">` + esc(run.Error) + `</div>`)
		}
		for _, st := range run.Steps {
			body.WriteString(`<div class="settings-block-title"><span class="mono">` + esc(st.Action) + `</span></div>`)
			if st.Did != "" {
				// What the step actually performed. A model call belongs here
				// even in a dry run: §8 requires the generation to be real, and
				// a reader must be able to tell that it was.
				body.WriteString(`<p class="text-sm muted">` + esc(st.Did) + `</p>`)
			}
			if st.Refused != "" {
				// The dry-run diff: what this step WOULD have done.
				body.WriteString(`<pre class="code-block">` + esc(st.Refused) + `</pre>`)
			}
			if st.Output != "" {
				body.WriteString(`<p class="text-sm">` + esc(st.Output) + `</p>`)
			}
			if st.Error != "" {
				body.WriteString(`<p class="text-sm"><span class="mono">` + esc(st.Error) + `</span></p>`)
			}
		}
		body.WriteString(`</div>`)
		when := run.StartedAt.Format("2006-01-02 15:04")
		b.WriteString(monAcc("▷", esc(when), esc(run.FlowID), runStatusChip(run.Status), false, body.String()))
	}
	b.WriteString(`</div>`)

	return b.String()
}

// vayuFlowScript wires the arm and run buttons. One nonce'd script, no inline
// handlers, no Alpine.
const vayuFlowScript = `
(function(){'use strict';
var status=document.getElementById('flow-status');
function say(t){ if(status){ status.textContent=t; } }
function post(url,done){
  fetch(url,{method:'POST',headers:{'X-CSRF-Token':(document.cookie.match(/(?:^|; )vayu_csrf=([^;]*)/)||[])[1]||''}})
    .then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});})
    .then(function(res){ done(res); })
    .catch(function(){ say('Request failed.'); });
}
document.addEventListener('click',function(ev){
  var arm=ev.target.closest('[data-flow-arm]');
  if(arm){
    var id=arm.getAttribute('data-flow-arm'), mode=arm.getAttribute('data-flow-mode');
    say('Working…');
    post('/os/api/vayuflow/arm?id='+encodeURIComponent(id)+'&mode='+encodeURIComponent(mode),function(res){
      if(res.ok){ say('Mode: '+res.d.prior+' → '+res.d.mode+'. Reload to refresh.'); }
      else { say((res.d&&res.d.error&&(res.d.error.message||res.d.error))||'Could not change mode.'); }
    });
    return;
  }
  var run=ev.target.closest('[data-flow-run]');
  if(run){
    say('Running…');
    post('/os/api/vayuflow/run?id='+encodeURIComponent(run.getAttribute('data-flow-run')),function(res){
      if(res.ok){ say('Run '+res.d.outcome+' — writes '+res.d.writes+'. Reload to see the trail.'); }
      else { say((res.d&&res.d.error&&(res.d.error.message||res.d.error))||'Run failed.'); }
    });
    return;
  }
  var en=ev.target.closest('[data-flow-enable]');
  if(en){
    var eid=en.getAttribute('data-flow-enable'), on=en.getAttribute('data-flow-on');
    say('Working…');
    post('/os/api/vayuflow/enable?id='+encodeURIComponent(eid)+'&on='+encodeURIComponent(on),function(res){
      if(res.ok){ say(res.d.enabled?'Switched on. Reload to refresh.':'Switched off. Reload to refresh.'); }
      else { say((res.d&&res.d.error&&(res.d.error.message||res.d.error))||'Could not change it.'); }
    });
    return;
  }
  var del=ev.target.closest('[data-flow-delete]');
  if(del){
    var did=del.getAttribute('data-flow-delete');
    // Confirmed by NAME, not by id. An operator asked to confirm an opaque hex
    // string is being asked to agree to something they cannot read.
    vpConfirm({title:'Delete flow',message:'Delete "'+del.getAttribute('data-flow-name')+'"? Its runs stay in the trail.',confirm:'Delete'},function(){
    say('Deleting…');
    post('/os/api/vayuflow/delete?id='+encodeURIComponent(did),function(res){
      if(res.ok){ say('Deleted. Reload to refresh.'); }
      else { say((res.d&&res.d.error&&(res.d.error.message||res.d.error))||'Could not delete it.'); }
    });
    });
  }
});

function val(id){ var el=document.getElementById(id); return el?el.value.trim():''; }
function num(id){ var n=parseInt(val(id),10); return isNaN(n)?0:n; }
// Parameters are key=value per line. Split on the FIRST '=' only, so a value
// containing one — a URL with a query string, a prompt with an equation —
// survives intact.
function params(id){
  var out={}, lines=val(id).split('\n');
  for(var i=0;i<lines.length;i++){
    var line=lines[i].trim(); if(!line){ continue; }
    var at=line.indexOf('='); if(at<1){ continue; }
    out[line.slice(0,at).trim()]=line.slice(at+1).trim();
  }
  return out;
}
var saveBtn=document.getElementById('ff-save');
if(saveBtn){ saveBtn.addEventListener('click',function(){
  var steps=[];
  for(var i=1;i<=4;i++){
    var a=val('ff-act'+i); if(!a){ continue; }
    steps.push({action:a,params:params('ff-par'+i)});
  }
  var doc={
    id:val('ff-id'), name:val('ff-name'),
    trigger:{kind:val('ff-trigger'),cron:val('ff-cron'),event:val('ff-event')},
    condition:{kind:val('ff-cond'),value:val('ff-condval')},
    steps:steps,
    budget:{max_steps_per_run:num('ff-bsteps'),max_runs_per_hour:num('ff-bruns'),
      max_writes_per_run:num('ff-bwrites'),max_egress_per_run:num('ff-begress'),
      timeout_seconds:num('ff-btimeout')}
  };
  say('Saving…');
  fetch('/os/api/vayuflow/save',{method:'POST',
    headers:{'Content-Type':'application/json','X-CSRF-Token':(document.cookie.match(/(?:^|; )vayu_csrf=([^;]*)/)||[])[1]||''},
    body:JSON.stringify(doc)})
   .then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});})
   .then(function(res){
     if(res.ok){
       // The store is the authority on what was accepted, so the confirmation
       // quotes what came BACK rather than what was sent.
       say((res.d.created?'Created':'Saved')+' — v'+res.d.version+', writes at most '+res.d.highest_write+
           ', owner must hold '+res.d.min_owner+'. It is '+(res.d.enabled?'on':'off')+
           ' and in '+res.d.mode+'. Reload to see it listed.');
     } else {
       // The store's refusal is shown verbatim. It is written to be read by the
       // person who filled the form, and paraphrasing it here would lose the
       // one sentence that says which field is wrong.
       say((res.d&&res.d.error&&(res.d.error.message||res.d.error))||'Could not save it.');
     }
   })
   .catch(function(){ say('Request failed.'); });
}); }
var resetBtn=document.getElementById('ff-reset');
if(resetBtn){ resetBtn.addEventListener('click',function(){
  ['ff-id','ff-name','ff-cron','ff-condval','ff-par1','ff-par2','ff-par3','ff-par4'].forEach(function(id){
    var el=document.getElementById(id); if(el){ el.value=''; }
  });
  ['ff-act1','ff-act2','ff-act3','ff-act4','ff-event'].forEach(function(id){
    var el=document.getElementById(id); if(el){ el.selectedIndex=0; }
  });
  say('Form cleared.');
}); }
})();
`

// flowRoleResolver reads an owner's CURRENT role from the user store. It is the
// function that makes a demotion take effect: nothing about authority is cached
// on the flow.
func (a *App) flowRoleResolver() vayuflow.RoleResolver {
	return func(ctx context.Context, owner string) (string, error) {
		if a.userStore == nil {
			return "", fmt.Errorf("vayuflow: no user store; cannot resolve owner authority")
		}
		u, err := a.userStore.GetByID(ctx, owner)
		if err != nil {
			return "", err
		}
		return u.Role, nil
	}
}

// flowEditorCard renders the create/edit form.
//
// Every choice it offers is read from the ENGINE — the action list from the
// capability registry, the condition list from LeafConditionKinds, the events
// from KnownEvents. A form carrying its own copy of any of those is a second
// list that drifts from the first, and the operator finds out by saving
// something the store then refuses for a reason the page never mentioned.
//
// The budget fields have no "unlimited" and no blank default. ADR-0151 §3 makes
// unlimited inexpressible on purpose; a form that let the field stay empty would
// reintroduce it as a shrug.
func flowEditorCard() string {
	esc := html.EscapeString
	var b strings.Builder
	b.WriteString(`<div class="card">`)
	b.WriteString(`<div class="settings-block-title">What it is</div>`)
	b.WriteString(`<div class="field"><label class="field-label" for="ff-name">Name</label>` +
		`<input class="input" id="ff-name" type="text" placeholder="Monday digest"></div>`)
	b.WriteString(`<input id="ff-id" type="hidden" value="">`)

	b.WriteString(`<div class="settings-block-title">What starts it</div>`)
	b.WriteString(`<div class="field"><label class="field-label" for="ff-trigger">Trigger</label>` +
		`<select class="input" id="ff-trigger">` +
		`<option value="manual">manual — only when you press Run</option>` +
		`<option value="schedule">schedule — on a cron expression</option>` +
		`<option value="event">event — when something happens here</option>` +
		`</select></div>`)
	b.WriteString(`<div class="field"><label class="field-label" for="ff-cron">Cron (schedule only)</label>` +
		`<input class="input" id="ff-cron" type="text" placeholder="0 9 * * 1">` +
		`<div class="field-hint">Five fields, install timezone. Parsed when you save, not when it ` +
		`first fires — an expression that only fails at 9am on Monday is one you find out about on Tuesday.</div></div>`)
	b.WriteString(`<div class="field"><label class="field-label" for="ff-event">Event (event only)</label>` +
		`<select class="input" id="ff-event"><option value="">—</option>`)
	for _, e := range vayuflow.KnownEvents() {
		b.WriteString(`<option value="` + esc(e) + `">` + esc(e) + `</option>`)
	}
	b.WriteString(`</select></div>`)

	b.WriteString(`<div class="settings-block-title">Which subjects</div>`)
	b.WriteString(`<div class="field"><label class="field-label" for="ff-cond">Condition</label>` +
		`<select class="input" id="ff-cond">`)
	for _, n := range vayuflow.LeafConditionNames() {
		b.WriteString(`<option value="` + esc(n) + `">` + esc(n) + `</option>`)
	}
	b.WriteString(`</select><div class="field-hint">"always" is a real answer, not a missing one. ` +
		`Combining conditions with all/any/not is not expressible here yet.</div></div>`)
	b.WriteString(`<div class="field"><label class="field-label" for="ff-condval">Compare against</label>` +
		`<input class="input" id="ff-condval" type="text" placeholder="release-notes"></div>`)

	b.WriteString(`<div class="settings-block-title">What it does</div>`)
	b.WriteString(`<p class="text-sm muted">Up to four steps, in order. Each one names an action from ` +
		`the registry above; leave a row blank to stop there. Parameters are ` +
		`<span class="mono">key=value</span>, one per line. A parameter whose whole value is ` +
		`<span class="mono">$prev</span> receives the previous step's output.</p>`)
	for i := 1; i <= 4; i++ {
		n := strconv.Itoa(i)
		b.WriteString(`<div class="field"><label class="field-label" for="ff-act` + n + `">Step ` + n + `</label>` +
			`<select class="input" id="ff-act` + n + `"><option value="">—</option>`)
		for _, c := range vayuflow.Capabilities() {
			b.WriteString(`<option value="` + esc(c.Action) + `">` + esc(c.Action) +
				` — writes ` + esc(c.Writes.String()) + `, needs ` + esc(c.MinRole) + `</option>`)
		}
		b.WriteString(`</select>` +
			`<textarea class="input" id="ff-par` + n + `" rows="2" placeholder="title=Weekly digest"></textarea></div>`)
	}

	b.WriteString(`<div class="settings-block-title">What it may spend</div>`)
	b.WriteString(`<p class="text-sm muted">Every ceiling is required and there is no way to write ` +
		`"unlimited". The run trail shows what was spent against what was allowed.</p>`)
	for _, f := range []struct{ id, label, def string }{
		{"ff-bsteps", "Steps per run", "4"},
		{"ff-bruns", "Runs per hour", "2"},
		{"ff-bwrites", "Writes per run", "1"},
		{"ff-begress", "Fetches per run", "1"},
		{"ff-btimeout", "Wall clock (seconds)", "60"},
	} {
		b.WriteString(`<div class="field"><label class="field-label" for="` + f.id + `">` + f.label + `</label>` +
			`<input class="input" id="` + f.id + `" type="number" min="1" value="` + f.def + `"></div>`)
	}

	b.WriteString(`<div class="flex-between">` +
		`<button type="button" class="btn btn--primary btn--sm" id="ff-save">Save flow</button>` +
		`<button type="button" class="btn btn--ghost btn--sm" id="ff-reset">Clear the form</button>` +
		`</div>`)
	b.WriteString(`<p class="text-sm muted">A new flow is stored switched off and in dry-run. ` +
		`Neither this form nor an edit ever changes those — arming is its own button, with its own ` +
		`entry in the audit trail.</p>`)
	b.WriteString(`</div>`)
	return b.String()
}
