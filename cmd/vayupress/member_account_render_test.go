// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/members"
	"github.com/johalputt/vayupress/internal/settings"
)

// renderAccountPage drives the real handler with a real member session and returns
// the page HTML. Structural assertions on the shipped markup are worth more than
// assertions on a builder in isolation: the bug being guarded here — a section that
// silently stops being wrapped — only shows up in the assembled page.
func renderAccountPage(t *testing.T, paid bool) string {
	t.Helper()
	config.Cfg.DBPath = ":memory:"
	config.Cfg.Domain = "example.com"
	if err := dbpkg.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	t.Cleanup(func() {
		dbpkg.ClosePools()
		_ = dbpkg.DB.Close()
	})

	store := members.New(dbpkg.DB)
	a := &App{members: store, siteSettings: settings.New(dbpkg.DB)}
	m, err := store.UpsertScoped(t.Context(), "", "reader@example.com")
	if err != nil {
		t.Fatalf("create member: %v", err)
	}
	if paid {
		if err := store.SetTier(t.Context(), m.Email, members.TierPaid); err != nil {
			t.Fatalf("set tier: %v", err)
		}
	}
	token, err := store.CreateSession(t.Context(), m.ID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	req := httptest.NewRequest("GET", "/members/account", nil)
	req.AddCookie(&http.Cookie{Name: memberCookie, Value: token})
	rec := httptest.NewRecorder()
	a.handleMemberAccount(rec, req)
	if rec.Code != 200 {
		t.Fatalf("account page = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// TestAccountPageUsesTheMonetizationGrammar pins that the member account page is
// built from collapsible summary rows rather than a flat stack of equal-weight
// cards, matching the console's Monetization page.
func TestAccountPageUsesTheMonetizationGrammar(t *testing.T) {
	page := renderAccountPage(t, true)

	for _, want := range []string{
		`class="ma-acc"`, `class="ma-acc__sum"`, `class="ma-acc__ic"`,
		`class="ma-acc__title"`, `class="ma-acc__chev"`, `class="ma-acc__body"`,
		`class="ma-sec"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("account page is missing %q from the accordion grammar", want)
		}
	}
	// Native <details>: expanding must not depend on JavaScript.
	if !strings.Contains(page, "<details class=\"ma-acc\"") {
		t.Error("rows must be native <details>, so they work with no JavaScript")
	}
	// Exactly one row should start expanded — a page where everything is open is
	// the flat stack this replaced, and one where nothing is open is a wall of
	// closed doors.
	if got := strings.Count(page, `<details class="ma-acc" open>`); got != 1 {
		t.Errorf("%d rows start open, want exactly 1", got)
	}
	// The plan and billing summaries stay visible rather than being collapsed:
	// they are what the page is for.
	if !strings.Contains(page, "ma-card--plan") {
		t.Error("the plan card must stay visible, not be collapsed into a row")
	}
}

// TestAccountPageKeepsEverySection guards against a section quietly disappearing
// while being wrapped — the sign-in details and the preferences form must both
// still be present and reachable.
func TestAccountPageKeepsEverySection(t *testing.T) {
	page := renderAccountPage(t, false)
	for _, want := range []string{
		"Sign-in details",
		"reader@example.com",
		"Member since",
		"Name &amp; notifications",
		`name="reply_notify"`,
		`name="newsletter"`,
		`action="/members/account"`,
		"Save changes",
		"Compare plans", // free member: the upgrade comparison is offered
	} {
		if !strings.Contains(page, want) {
			t.Errorf("account page lost %q", want)
		}
	}
}

// TestAccountPageDump writes the rendered page for visual inspection when
// VP_DUMP_ACCOUNT_HTML names a path. It asserts nothing; it exists so the design
// can be reviewed in a browser against the real markup rather than a mock.
func TestAccountPageDump(t *testing.T) {
	path := os.Getenv("VP_DUMP_ACCOUNT_HTML")
	if path == "" {
		t.Skip("set VP_DUMP_ACCOUNT_HTML to write the rendered account page")
	}
	if err := os.WriteFile(path, []byte(renderAccountPage(t, false)), 0o600); err != nil {
		t.Fatalf("write dump: %v", err)
	}
}
