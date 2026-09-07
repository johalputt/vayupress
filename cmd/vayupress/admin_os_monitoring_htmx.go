// SPDX-License-Identifier: Apache-2.0

package main

// admin_os_monitoring_htmx.go — HTMX live-refresh for the VayuOS "Monitoring"
// surface, replacing the former static/js/admin-os-monitoring.js poll loop.
//
// The full page (handleOSMonitoring) still renders a complete, correct
// server-side snapshot on load. A single invisible HTMX poller element then
// GETs /os/monitoring/live every 5s and the handler returns a tiny set of
// out-of-band (hx-swap-oob) fragments — the system-mode pill, each governance
// budget's state pill, and the "updated" stamp — which HTMX swaps in place by
// id. This mirrors, byte-for-byte in behaviour, what the old JS did (refresh
// mode + budget states + stamp; nothing else), but with zero client JavaScript.
//
// CSP posture is unchanged: no inline scripts, no inline styles, every dynamic
// string HTML-escaped. Read-only GET, so no CSRF token is required.

import (
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/johalputt/vayupress/internal/budget"
	"github.com/johalputt/vayupress/internal/mode"
)

// oobAttr returns the hx-swap-oob attribute when the fragment is being served as
// part of a live-poll response, and the empty string when it is rendered inline
// in the full page (where it is a plain swap target, not itself an OOB update).
func oobAttr(oob bool) string {
	if oob {
		return ` hx-swap-oob="true"`
	}
	return ""
}

// monBudgetID derives a stable, HTML-id-safe key for a governance budget's live
// state pill from its name, so the poller can target it out-of-band. Governance
// budget names are a small fixed set of distinct labels, so the lower-cased
// alphanumeric slug is collision-free in practice and — crucially — identical
// between the full-page render and every subsequent poll.
func monBudgetID(name string) string {
	var b strings.Builder
	b.Grow(len("mon-b-") + len(name))
	b.WriteString("mon-b-")
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// monModePill renders the system-mode status pill. Rendered inline (oob=false)
// in the full page as the swap target, and again (oob=true) in the live-poll
// response so HTMX replaces it by id.
func monModePill(cur mode.Mode, oob bool) string {
	return `<span id="mon-mode" class="tool-status ` + modeStateClass(cur) + `"` + oobAttr(oob) + `>` +
		html.EscapeString(string(cur)) + `</span>`
}

// monBudgetStatePill renders one governance budget's state pill, keyed by a
// stable per-budget id so the poller can update it out-of-band.
func monBudgetStatePill(name, state string, oob bool) string {
	return `<span id="` + monBudgetID(name) + `" class="tool-status ` + budgetStateClass(state) + `"` + oobAttr(oob) + `>` +
		html.EscapeString(state) + `</span>`
}

// monUpdatedStamp renders the "updated HH:MM:SS" liveness stamp with an honest
// data-age note (Wave 3.12): the poll tick reflects SERVER time, but the
// metrics on the cards come from a snapshot collected on a 30s ticker — a stamp
// that refreshed every 5 seconds while the numbers under it were up to half a
// minute old was a liveness lie. The snapshot age is rendered next to the poll
// time so both truths are visible. Kept out of any aria-live region so it is
// not announced to screen readers every 5s.
func monUpdatedStamp(now time.Time, snapAge time.Duration, oob bool) string {
	out := `<span class="text-sm muted" data-mon-updated id="mon-updated"` + oobAttr(oob) + `>updated ` +
		html.EscapeString(now.Format("15:04:05"))
	if snapAge >= 0 {
		out += ` · metrics ` + html.EscapeString(snapAge.Truncate(time.Second).String()) + ` old`
	}
	return out + `</span>`
}

// nowSnapAge returns the metrics snapshot's age for the stamp, or -1 when no
// snapshot is cached yet (the stamp then omits the age rather than inventing
// one). Deliberately cache-read-only: the stamp must never trigger a metric
// collection just to say how old the numbers are — the 30s ticker owns that.
func (a *App) nowSnapAge() time.Duration {
	if v := a.metricsSnapshot.Load(); v != nil {
		age := time.Since(v.(*adminMetricsSnapshot).SnapshotAt)
		if age < 0 {
			return 0
		}
		return age
	}
	return -1
}

// handleOSMonitoringLive is the HTMX poll endpoint behind the Monitoring page's
// invisible poller element. It returns only out-of-band fragments — the mode
// pill, every budget state pill, and the updated stamp — and nothing else, so
// the response is a pure fragment (never a full document). Reads only
// concurrency-safe process globals (mode.Global, budget.Global), so it is
// goroutine-safe under -race.
func (a *App) handleOSMonitoringLive(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") != "true" {
		http.Error(w, "HTMX request required", http.StatusBadRequest)
		return
	}

	now := time.Now()
	var b strings.Builder
	b.WriteString(monModePill(mode.Global.Current(), true))
	for _, bd := range budget.Global.Status(now) {
		b.WriteString(monBudgetStatePill(bd.Name, bd.State, true))
	}
	b.WriteString(monUpdatedStamp(now, a.nowSnapAge(), true))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}
