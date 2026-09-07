// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

// Bulk endpoint tests — the ONE-request bulk apply must land every slug through
// the same helpers as the single-post endpoints, report per-slug outcomes (a
// missing slug is a failure, not a silent skip), and recompute the tab counts
// so the All/Published/Drafts tabs describe the catalogue as it now is.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dbpkg "github.com/johalputt/vayupress/internal/db"
)

func seedBulkPost(t *testing.T, slug, status string) {
	t.Helper()
	if _, err := dbpkg.DB.Exec(
		`INSERT INTO articles(id,title,slug,content,tags,status,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,datetime('now'),datetime('now'))`,
		slug, "Bulk "+slug, slug, "body", "", status,
	); err != nil {
		t.Fatalf("insert %s: %v", slug, err)
	}
}

func callBulk(t *testing.T, a *App, action string, slugs []string) (int, map[string]any) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"action": action, "slugs": slugs})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/os/api/posts/bulk", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.handleOSPostsBulk(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func bulkStatus(t *testing.T, slug string) string {
	t.Helper()
	var st string
	if err := dbpkg.DB.QueryRow(`SELECT status FROM articles WHERE slug=?`, slug).Scan(&st); err != nil {
		t.Fatalf("read back %s: %v", slug, err)
	}
	return st
}

func bulkCount(t *testing.T, where string) int {
	t.Helper()
	var n int
	if err := dbpkg.DB.QueryRow(`SELECT COUNT(1) FROM articles` + where).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestOSBulkPublishReportsPerSlugOutcomesAndCounts(t *testing.T) {
	_, _ = newTestHarness(t)

	seedBulkPost(t, "bulk-draft-1", "draft")
	seedBulkPost(t, "bulk-draft-2", "draft")
	seedBulkPost(t, "bulk-live", "published")

	a := &App{}
	code, body := callBulk(t, a, "published", []string{"bulk-draft-1", "bulk-draft-2", "missing-slug"})
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	if got := int(body["ok"].(float64)); got != 2 {
		t.Errorf("ok = %d, want 2 (the two real drafts)", got)
	}
	if got := int(body["failed"].(float64)); got != 1 {
		t.Errorf("failed = %d, want 1 (the missing slug)", got)
	}
	results := body["results"].([]any)
	last := results[2].(map[string]any)
	if last["ok"].(bool) || !strings.Contains(last["error"].(string), "no article") {
		t.Errorf("missing slug reported as %#v, want a per-slug failure naming the reason", last)
	}
	if got := bulkStatus(t, "bulk-draft-1"); got != "published" {
		t.Errorf("bulk-draft-1 status = %q, want published — the successes must stand despite the failure", got)
	}
	if got := bulkStatus(t, "bulk-draft-2"); got != "published" {
		t.Errorf("bulk-draft-2 status = %q, want published", got)
	}
	counts := body["counts"].(map[string]any)
	if int(counts["published"].(float64)) != 3 || int(counts["draft"].(float64)) != 0 || int(counts["all"].(float64)) != 3 {
		t.Errorf("counts = %v, want published=3 draft=0 all=3 — the tabs must describe the catalogue as it now is", counts)
	}
	// The per-slug payload carries the flipped pill + button so rows update in
	// place without a reload.
	first := results[0].(map[string]any)
	if !strings.Contains(first["pill"].(string), "Published") {
		t.Errorf("pill = %q, want the Published pill", first["pill"])
	}
	if !strings.Contains(first["button"].(string), "hx-post") {
		t.Errorf("button = %q, want the flipped HTMX toggle", first["button"])
	}
}

func TestOSBulkUnpublishAndDelete(t *testing.T) {
	_, _ = newTestHarness(t)

	seedBulkPost(t, "bulk-unpub-1", "published")
	seedBulkPost(t, "bulk-unpub-2", "published")
	seedBulkPost(t, "bulk-doomed", "draft")

	a := &App{}
	code, body := callBulk(t, a, "draft", []string{"bulk-unpub-1", "bulk-unpub-2"})
	if code != http.StatusOK || int(body["failed"].(float64)) != 0 {
		t.Fatalf("unpublish = %d / %v, want both published posts flipped", code, body)
	}
	if got := bulkStatus(t, "bulk-unpub-1"); got != "draft" {
		t.Errorf("bulk-unpub-1 = %q, want draft", got)
	}

	code, body = callBulk(t, a, "delete", []string{"bulk-doomed", "ghost"})
	if code != http.StatusOK {
		t.Fatalf("delete status = %d", code)
	}
	if got := int(body["ok"].(float64)); got != 1 {
		t.Errorf("delete ok = %d, want 1 (the doomed post; ghost never existed)", got)
	}
	if got := bulkCount(t, ` WHERE slug='bulk-doomed'`); got != 0 {
		t.Errorf("bulk-doomed still exists (%d rows) — bulk delete did not delete", got)
	}
	// A delete response carries no pill/button and no tab counts: the posts page
	// is stale in a different way (rows are removed client-side) and the counts
	// header of the page reloads with the next navigation.
	if _, has := body["counts"]; has {
		t.Error("delete response should not carry tab counts")
	}
}

func TestOSBulkValidatesActionAndSlugs(t *testing.T) {
	_, _ = newTestHarness(t)
	a := &App{}

	if code, _ := callBulk(t, a, "nuke", []string{"some-slug"}); code != http.StatusBadRequest {
		t.Errorf("bad action = %d, want 400", code)
	}
	if code, _ := callBulk(t, a, "published", nil); code != http.StatusBadRequest {
		t.Errorf("empty slugs = %d, want 400", code)
	}
	if code, _ := callBulk(t, a, "published", []string{"not a slug!"}); code != http.StatusBadRequest {
		t.Errorf("invalid slug = %d, want 400", code)
	}
	many := make([]string, osBulkMaxSlugs+1)
	for i := range many {
		many[i] = "slug-" + string(rune('a'+i%26)) + "-" + strings.Repeat("x", i%7)
	}
	if code, _ := callBulk(t, a, "published", many); code != http.StatusBadRequest {
		t.Errorf("oversized batch = %d, want 400", code)
	}
}

func TestOSBulkRouteIsRegisteredBehindCSRF(t *testing.T) {
	// Source-level pin: the route must exist with the same CSRF wrapper as its
	// single-post siblings, so a bulk apply can never bypass the token check.
	src := readSourceFile(t, "admin_os_ui.go")
	want := `Post("/os/api/posts/bulk", a.handleOSPostsBulk)`
	if !strings.Contains(src, want) {
		t.Fatalf("bulk route missing: %s", want)
	}
	if !strings.Contains(src, "CSRFTokenMiddleware).Post(\"/os/api/posts/bulk\"") {
		t.Fatal("the bulk route is not wrapped in CSRFTokenMiddleware")
	}
}
