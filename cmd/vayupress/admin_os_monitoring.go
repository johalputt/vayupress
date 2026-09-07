// SPDX-License-Identifier: Apache-2.0

package main

// admin_os_monitoring.go — VayuOS "Monitoring" surface (VayuOS consolidation).
//
// This folds the at-a-glance half of the classic v1 SRE console into the single
// os admin: current system mode, live performance percentiles, storage/queue
// health, and the governance error-budget ledger — all rendered server-side
// from the same in-process sources the v1 console and JSON APIs use, then kept
// fresh by a small poll loop against the existing /api/v1/admin/{mode,budgets}
// endpoints. Deep interactive consoles (mode transitions, topology, fault
// simulation, replay, ADR registry) remain at their /admin/* routes and are
// linked from here, so nothing regresses while the surfaces converge.
//
// CSP posture matches the rest of VayuOS: no inline styles, the only inline
// <script> carries the per-request nonce, every dynamic string is escaped.

import (
	"html"
	htmpl "html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/johalputt/vayupress/internal/budget"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/mode"
	"github.com/johalputt/vayupress/internal/render"
)

// modeStateClass maps a system mode to the status-pill modifier used for colour.
func modeStateClass(m mode.Mode) string {
	switch m {
	case mode.ModeNormal:
		return "tool-status--on"
	case mode.ModeDegraded, mode.ModeRecovery, mode.ModeMaintenance:
		return "tool-status--idle"
	default: // read-only, quarantined
		return "tool-status--off"
	}
}

// budgetStateClass maps a budget state string to a status-pill modifier.
func budgetStateClass(state string) string {
	switch state {
	case "healthy":
		return "tool-status--on"
	case "at-risk":
		return "tool-status--idle"
	default: // exhausted
		return "tool-status--off"
	}
}

// monStat renders one performance stat card.
func monStat(label, value, sub string) string {
	return `<div class="stat-card">
  <div class="stat-card__top"><div class="stat-card__label">` + html.EscapeString(label) + `</div></div>
  <div class="stat-card__value">` + html.EscapeString(value) + `</div>
  <div class="stat-card__bottom"><span class="muted text-xs">` + html.EscapeString(sub) + `</span></div>
</div>`
}

func (a *App) handleOSMonitoring(w http.ResponseWriter, r *http.Request) {
	nonce := render.CSPNonce(r)
	cfg := a.getOSSettings(r.Context())
	snap := a.getAdminSnapshot()

	// ── System mode ──────────────────────────────────────────────────────────
	cur := mode.Global.Current()
	transitions := len(mode.Global.History())
	modeCard := `<div class="card mb-6">
  <div class="flex justify-between items-center">
    <div>
      <div class="card-title">System mode</div>
      <div class="text-sm muted">` + strconv.Itoa(transitions) + ` recorded transition(s)</div>
    </div>
    <span aria-live="polite">` + monModePill(cur, false) + `</span>
  </div>
</div>`

	// ── Performance ──────────────────────────────────────────────────────────
	uptime := time.Duration(snap.UptimeSeconds) * time.Second
	perf := `<div class="stat-grid mb-6">` +
		monStat("HTTP p95", strconv.FormatInt(snap.HTTPP95, 10)+" ms", "request latency · last 15 min") +
		monStat("Write p99", strconv.FormatInt(snap.WriteP99, 10)+" ms", "queue job latency") +
		monStat("Render p99", strconv.FormatInt(snap.RenderP99, 10)+" ms", "page render") +
		monStat("Cache hit", strconv.Itoa(int(snap.CacheHitRatio*100))+"%", "render cache") +
		monStat("Workers", strconv.FormatInt(snap.WorkersAlive, 10), "alive") +
		monStat("Uptime", uptime.Truncate(time.Second).String(), "since boot") +
		`</div>`

	// ── Storage & queue ──────────────────────────────────────────────────────
	pct := int(snap.StoragePct)
	storWidth := storageWidthClass(pct)
	storBar := "progress__bar progress__bar--ok"
	if pct >= 90 {
		storBar = "progress__bar progress__bar--danger"
	} else if pct >= 75 {
		storBar = "progress__bar progress__bar--warn"
	}
	storageJobs := `<div class="grid grid-2 mb-6">
  <div class="card">
    <div class="card-title">Storage</div>
    <div class="progress"><div class="` + storBar + ` ` + storWidth + `"></div></div>
    <div class="flex justify-between mt-3">
      <span class="text-xs muted">` + strconv.Itoa(pct) + `% used</span>
      <span class="text-xs muted">` + dbpkg.FormatBytes(snap.StorageBytes) + ` / ` + dbpkg.FormatBytes(snap.QuotaBytes) + `</span>
    </div>
  </div>
  <div class="card">
    <div class="card-title">Write queue</div>
    <div class="flex justify-between"><span class="text-sm muted">Pending</span><span>` + strconv.Itoa(snap.PendingJobs) + `</span></div>
    <div class="flex justify-between mt-2"><span class="text-sm muted">Failed</span><span>` + strconv.Itoa(snap.FailedJobs) + `</span></div>
    <div class="flex justify-between mt-2"><span class="text-sm muted">Completed</span><span>` + strconv.Itoa(snap.CompletedJobs) + `</span></div>
  </div>
</div>`

	// ── The write connection ─────────────────────────────────────────────────
	// The fault that had no page. SQLite has one writer; when it jams, every
	// write queues and the site 502s with nothing in the log and no restart to
	// point at. Neither the stall nor its cost was measured anywhere, so the
	// only available answer was a guess. Both are measured now, and this is
	// where an operator reads them (ADR-0156).
	stallState := dbpkg.WriteStall()
	recState := a.analytics.CollectorStats()
	writer := writeStallStats(stallState, recState) + writeStallCard(stallState, recState)

	// ── Governance budgets ───────────────────────────────────────────────────
	rows := ""
	for _, b := range budget.Global.Status(time.Now()) {
		rows += `<tr>
  <td class="row-title">` + html.EscapeString(b.Name) + `<div class="row-meta">tracks ` + html.EscapeString(b.Tracks) + `</div></td>
  <td class="muted text-sm">` + strconv.Itoa(b.Consumed) + ` / ` + strconv.Itoa(b.Limit) + `</td>
  <td>` + monBudgetStatePill(b.Name, b.State, false) + `</td>
</tr>`
	}
	budgetsCard := `<div class="card mb-6">
  <div class="card-title">Governance error budgets</div>
  <div class="table-wrap"><table class="table">
    <thead><tr><th>Budget</th><th>Consumed</th><th>State</th></tr></thead>
    <tbody aria-live="polite">` + rows + `</tbody>
  </table></div>
  <div class="text-xs muted mt-3">Accounting + recommendation — mode transitions are operator-gated, never auto-applied.</div>
</div>`

	// ── Deep operator consoles ───────────────────────────────────────────────
	link := func(href, label, desc string) string {
		return `<a class="tool-card" href="` + href + `">
  <div class="tool-card__head"><div class="tool-card__title">` + html.EscapeString(label) + `</div></div>
  <div class="tool-card__desc">` + html.EscapeString(desc) + `</div>
</a>`
	}
	consoles := `<div class="tools-cat">Deep operator consoles</div>
<div class="tools-grid">` +
		link("/os/modes", "Mode transitions", "Drive the system-mode state machine and review the transition journal.") +
		link("/os/topology", "Topology", "Subsystem dependency graph and live component health.") +
		link("/os/faults", "Fault simulation", "Inject controlled faults to exercise recovery (non-production).") +
		link("/os/replay", "Replay", "Dead-letter inspection and safe job replay.") +
		link("/os/adr", "ADR registry", "Browse the architecture decision record index.") +
		`</div>`

	// The page renders a complete server-side snapshot above. This invisible
	// HTMX poller keeps an open dashboard fresh: every 5s it GETs the live
	// endpoint, which returns out-of-band fragments that swap the mode pill,
	// each budget state pill, and the "updated" stamp in place — no client JS.
	poller := `<div hx-get="/os/monitoring/live" hx-trigger="every 5s" hx-swap="none" aria-hidden="true"></div>`

	body := `<div class="page-header">
  <h1>Monitoring</h1>
  <div class="page-actions">` + monUpdatedStamp(time.Now(), a.nowSnapAge(), false) + `</div>
</div>
<p class="page-sub">A live view of your running install — performance, background jobs, storage and budgets, refreshed as you watch.</p>` + poller + modeCard + perf + storageJobs + writer + budgetsCard + consoles

	writeOSHTML(w, r, adminOSLayout(nonce, "Monitoring", "monitoring", cfg, htmpl.HTML(body)))
}
