// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/johalputt/vayupress/internal/mode"
)

// TestMonBudgetID checks the live-pill id slug is deterministic, id-safe, and
// neutralises hostile budget names (so nothing hostile can reach an id/OOB
// target attribute).
func TestMonBudgetID(t *testing.T) {
	cases := map[string]string{
		"healthy":          "mon-b-healthy",
		"5xx errors":       "mon-b-5xx-errors",
		"P95 Latency":      "mon-b-p95-latency",
		`"><img onerror=x`: "mon-b----img-onerror-x",
	}
	for in, want := range cases {
		if got := monBudgetID(in); got != want {
			t.Errorf("monBudgetID(%q) = %q, want %q", in, got, want)
		}
	}
	// Determinism: the id computed at full-page render time must equal the id
	// computed on a later poll for the same budget, or OOB swaps miss.
	first := monBudgetID("Write queue")
	second := monBudgetID("Write queue")
	if first != second {
		t.Errorf("monBudgetID not deterministic: %q vs %q", first, second)
	}
}

// TestMonFragmentsCSPSafeAndOOB verifies each live fragment is CSP-clean, carries
// the correct stable id, escapes hostile input, and toggles hx-swap-oob only
// when served as an out-of-band poll update (not when rendered inline).
func TestMonFragmentsCSPSafeAndOOB(t *testing.T) {
	// Mode pill.
	inline := monModePill(mode.ModeNormal, false)
	assertCSPSafe(t, "mode pill inline", inline)
	if !strings.Contains(inline, `id="mon-mode"`) {
		t.Errorf("mode pill missing stable id:\n%s", inline)
	}
	if strings.Contains(inline, "hx-swap-oob") {
		t.Errorf("inline mode pill must not be OOB:\n%s", inline)
	}
	oob := monModePill(mode.ModeReadOnly, true)
	if !strings.Contains(oob, `hx-swap-oob="true"`) {
		t.Errorf("OOB mode pill missing hx-swap-oob:\n%s", oob)
	}
	if !strings.Contains(oob, "tool-status--off") {
		t.Errorf("read-only mode should map to off class:\n%s", oob)
	}

	// Budget state pill — hostile name must not break out of the id, hostile
	// state must be escaped.
	const hostileName = `"><script>`
	bp := monBudgetStatePill(hostileName, `at-risk<b>`, true)
	assertCSPSafe(t, "budget pill", bp)
	if strings.Contains(bp, "<script>") || strings.Contains(bp, "<b>") {
		t.Errorf("budget pill did not escape hostile input:\n%s", bp)
	}
	if !strings.Contains(bp, `id="`+monBudgetID(hostileName)+`"`) || strings.ContainsAny(monBudgetID(hostileName), `<>"'`) {
		t.Errorf("budget pill id not slugified safely:\n%s", bp)
	}
	if !strings.Contains(bp, `hx-swap-oob="true"`) {
		t.Errorf("OOB budget pill missing hx-swap-oob:\n%s", bp)
	}

	// Updated stamp. With a snapshot age the stamp says how old the numbers are;
	// with none (-1) it omits the age rather than inventing one.
	stamp := monUpdatedStamp(time.Date(2024, 1, 2, 9, 4, 5, 0, time.UTC), 12*time.Second, false)
	assertCSPSafe(t, "updated stamp", stamp)
	if !strings.Contains(stamp, `id="mon-updated"`) || !strings.Contains(stamp, "updated 09:04:05") {
		t.Errorf("stamp wrong:\n%s", stamp)
	}
	if !strings.Contains(stamp, "metrics 12s old") {
		t.Errorf("stamp must carry the honest snapshot age:\n%s", stamp)
	}
	if strings.Contains(stamp, "hx-swap-oob") {
		t.Errorf("inline stamp must not be OOB:\n%s", stamp)
	}
	ageless := monUpdatedStamp(time.Date(2024, 1, 2, 9, 4, 5, 0, time.UTC), -1, false)
	if strings.Contains(ageless, "metrics") {
		t.Errorf("stamp must not invent a snapshot age when none exists:\n%s", ageless)
	}
}

// TestOSMonitoringLive_HTMXRequest confirms the poll endpoint returns a pure
// out-of-band fragment (never a full document), keyed to the page's swap
// targets, and marked no-store.
func TestOSMonitoringLive_HTMXRequest(t *testing.T) {
	a := &App{}
	req := httptest.NewRequest(http.MethodGet, "/os/monitoring/live", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()

	a.handleOSMonitoringLive(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	assertCSPSafe(t, "live fragment", body)
	if strings.Contains(strings.ToLower(body), "<html") || strings.Contains(body, "<body") {
		t.Errorf("live response must be a fragment, not a full document:\n%s", body)
	}
	for _, want := range []string{`id="mon-mode"`, `id="mon-updated"`, `hx-swap-oob="true"`} {
		if !strings.Contains(body, want) {
			t.Errorf("live fragment missing %q:\n%s", want, body)
		}
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

// TestOSMonitoringLive_NonHTMXRequest confirms the partial endpoint rejects a
// direct (non-HTMX) request rather than leaking a bare fragment.
func TestOSMonitoringLive_NonHTMXRequest(t *testing.T) {
	a := &App{}
	req := httptest.NewRequest(http.MethodGet, "/os/monitoring/live", nil)
	rec := httptest.NewRecorder()

	a.handleOSMonitoringLive(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for non-HTMX request", rec.Code)
	}
}
