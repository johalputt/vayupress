// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

// Wave 2.2 — the unified attention line. The bell used to collect niceties
// (unread mail, comments) and stay silent while jobs failed and the disk filled.
// Every new signal is pinned here with its severity, and the dashboard strip is
// pinned to sort danger ahead of warn.

import (
	"net/http/httptest"
	"strings"
	"testing"

	dbpkg "github.com/johalputt/vayupress/internal/db"
)

func seedFailedJobs(t *testing.T, n int) {
	t.Helper()
	if _, err := dbpkg.DB.Exec(`DELETE FROM write_jobs WHERE op='attention-test'`); err != nil {
		t.Fatalf("clear test jobs: %v", err)
	}
	for i := 0; i < n; i++ {
		if _, err := dbpkg.DB.Exec(`INSERT INTO write_jobs(article_json,op,status,created_at) VALUES('{}','attention-test','failed',datetime('now'))`); err != nil {
			t.Fatalf("seed job: %v", err)
		}
	}
	t.Cleanup(func() { _, _ = dbpkg.DB.Exec(`DELETE FROM write_jobs WHERE op='attention-test'`) })
}

func TestAttentionSignalsReachTheBell(t *testing.T) {
	_, _ = newTestHarness(t)
	s := &osSettings{AccessLevel: accessAdmin}
	ctx := httptest.NewRequest("GET", "/os", nil).Context()

	// Each phase uses a fresh App: the metrics snapshot is cached on first
	// collect (a 30s ticker in production), so a seeded change is only visible
	// to a collector that has not run yet.
	baseline := &App{}
	for _, n := range baseline.osNotifications(ctx, s) {
		if n.Kind == "jobs" {
			t.Fatalf("no failed jobs seeded but the bell said: %q", n.Title)
		}
	}

	// A few failures ⇒ warn.
	seedFailedJobs(t, 2)
	warned := &App{}
	var jobs *osNotification
	for _, n := range warned.osNotifications(ctx, s) {
		if n.Kind == "jobs" {
			j := n
			jobs = &j
		}
	}
	if jobs == nil {
		t.Fatal("failed jobs did not reach the bell — the attention line ignored the one signal that means the site is going stale")
	}
	if jobs.Severity != "warn" {
		t.Errorf("2 failed jobs severity = %q, want warn", jobs.Severity)
	}
	if jobs.Href != "/os/monitoring" {
		t.Errorf("failed-jobs href = %q, want /os/monitoring", jobs.Href)
	}

	// A pile of failures ⇒ danger.
	seedFailedJobs(t, 12)
	danger := &App{}
	for _, n := range danger.osNotifications(ctx, s) {
		if n.Kind == "jobs" && n.Severity != "danger" {
			t.Errorf("12 failed jobs severity = %q, want danger", n.Severity)
		}
	}
}

func TestAttentionStripSortsDangerFirst(t *testing.T) {
	strip := osAttentionStrip([]osNotification{
		{Title: "Comments to review", Detail: "3 awaiting moderation", Href: "/os/comments", Count: 3, Kind: "comment"},
		{Title: "Failed jobs", Detail: "12 failed", Href: "/os/monitoring", Count: 12, Kind: "jobs", Severity: "danger"},
		{Title: "Storage filling up", Detail: "80% of your storage quota is in use", Href: "/os/storage", Count: 80, Kind: "storage", Severity: "warn"},
	})
	assertCSPSafe(t, "attention strip", strip)
	if strings.Index(strip, "Failed jobs") > strings.Index(strip, "Comments to review") {
		t.Error("danger must sort ahead of info in the attention strip")
	}
	if strings.Index(strip, "Failed jobs") > strings.Index(strip, "Storage filling up") {
		t.Error("danger must sort ahead of warn in the attention strip")
	}
	for _, want := range []string{`data-attention-strip`, `attention-chip--danger`, `attention-chip--warn`, `attention-chip--info`, `href="/os/monitoring"`} {
		if !strings.Contains(strip, want) {
			t.Errorf("attention strip missing %q", want)
		}
	}
	if got := osAttentionStrip(nil); strings.Contains(got, "attention-chip") {
		t.Error("an empty attention list must render an empty strip, not wallpaper")
	}
}
