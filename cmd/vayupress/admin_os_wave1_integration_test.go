// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/johalputt/vayupress/internal/auth"
)

// Wave-1 authoring lifecycle, exercised end-to-end over HTTP:
//   - a brand-new post is born a DRAFT (first save never publishes);
//   - quick-compose creates drafts;
//   - saving an existing post records a version snapshot and RESTORE rewinds;
//   - the status endpoint flips draft↔published on demand.

// wave1CSRFJSON POSTs a JSON body with the CSRF cookie/header pair the admin
// API expects from browser sessions (API-key callers are exempted by the
// middleware, but sending both mirrors the real editor).
func wave1CSRFJSON(t *testing.T, url, key string, body interface{}) *http.Response {
	t.Helper()
	csrf := auth.GenerateCSRFToken("")
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, _ := http.NewRequest("POST", url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "vp_csrf", Value: csrf})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// wave1ArticleViaAPI reads the JSON projection of one article back.
func wave1ArticleViaAPI(t *testing.T, srv *httptest.Server, key, slug string) map[string]interface{} {
	t.Helper()
	resp := doRequest(t, srv, "GET", "/api/v1/articles/"+slug, key, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("GET article %s want 200, got %d", slug, resp.StatusCode)
	}
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	return body
}

func TestWave1FirstSaveBirthesADraft(t *testing.T) {
	srv, _ := newTestHarness(t)

	resp := wave1CSRFJSON(t, srv.URL+"/os/api/editor/save", "test-key", map[string]interface{}{
		"slug":  "",
		"title": "Wave One Native",
		"blocks": []map[string]interface{}{
			{"type": "paragraph", "text": "half-formed thought"},
		},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("save want 200, got %d", resp.StatusCode)
	}
	var out map[string]string
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if out["slug"] == "" || out["postStatus"] != "draft" {
		t.Fatalf("create response = %v; want slug + postStatus=draft", out)
	}

	art := wave1ArticleViaAPI(t, srv, "test-key", out["slug"])
	if art["status"] != "draft" {
		t.Fatalf("freshly saved article status = %v, want draft — first save published!", art["status"])
	}
}

func TestWave1QuickComposeCreatesDraft(t *testing.T) {
	srv, key := newTestHarness(t)

	resp := wave1CSRFJSON(t, srv.URL+"/os/api/posts/quick-create", "test-key", map[string]string{"title": "Wave One Compose"})
	if resp.StatusCode != 200 {
		t.Fatalf("quick-create want 200, got %d", resp.StatusCode)
	}
	var out struct {
		Slug string `json:"slug"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()

	art := wave1ArticleViaAPI(t, srv, key, out.Slug)
	if art["status"] != "draft" {
		t.Fatalf("quick-composed article status = %v, want draft", art["status"])
	}
}

func TestWave1UpdateSnapshotsAndRestoreRewinds(t *testing.T) {
	srv, key := newTestHarness(t)

	create := wave1CSRFJSON(t, srv.URL+"/os/api/editor/save", "test-key", map[string]interface{}{
		"slug": "", "title": "Versioned Post",
		"blocks": []map[string]interface{}{{"type": "paragraph", "text": "original prose"}},
	})
	if create.StatusCode != 200 {
		t.Fatalf("create save want 200, got %d", create.StatusCode)
	}
	var first map[string]string
	json.NewDecoder(create.Body).Decode(&first)
	create.Body.Close()
	slug := first["slug"]
	if slug == "" {
		t.Fatal("no slug from create")
	}

	// Second save against the existing slug → the queue's update path must
	// snapshot v1 before overwriting.
	update := wave1CSRFJSON(t, srv.URL+"/os/api/editor/save", "test-key", map[string]interface{}{
		"slug": slug, "title": "Versioned Post",
		"blocks": []map[string]interface{}{{"type": "paragraph", "text": "rewritten prose"}},
	})
	if update.StatusCode != 200 {
		t.Fatalf("update save want 200, got %d", update.StatusCode)
	}
	update.Body.Close()

	lr := doRequest(t, srv, "GET", "/os/api/editor/versions/"+slug, key, nil)
	if lr.StatusCode != 200 {
		t.Fatalf("version list want 200, got %d", lr.StatusCode)
	}
	var list struct {
		Versions []struct {
			ID    int64  `json:"id"`
			Title string `json:"title"`
		} `json:"versions"`
	}
	json.NewDecoder(lr.Body).Decode(&list)
	lr.Body.Close()
	if len(list.Versions) == 0 {
		t.Fatal("History would still say 'No versions yet' — update wrote no snapshot")
	}

	restoreURL := srv.URL + "/os/api/editor/versions/" + slug + "/" +
		strconv.FormatInt(list.Versions[0].ID, 10) + "/restore"
	rr := wave1CSRFJSON(t, restoreURL, "test-key", map[string]string{})
	if rr.StatusCode != 200 {
		t.Fatalf("restore want 200, got %d", rr.StatusCode)
	}
	rr.Body.Close()

	art := wave1ArticleViaAPI(t, srv, key, slug)
	content, _ := art["content"].(string)
	if !strings.Contains(content, "original prose") || strings.Contains(content, "rewritten prose") {
		t.Fatalf("restore did not rewind content: %q", content)
	}
}

func TestWave1PublishToggleFlipsDraftToPublished(t *testing.T) {
	srv, key := newTestHarness(t)

	cr := wave1CSRFJSON(t, srv.URL+"/os/api/posts/quick-create", "test-key", map[string]string{"title": "Toggle Me"})
	var created struct {
		Slug string `json:"slug"`
	}
	json.NewDecoder(cr.Body).Decode(&created)
	cr.Body.Close()

	pr := wave1CSRFJSON(t, srv.URL+"/os/api/posts/status", "test-key", map[string]string{
		"slug": created.Slug, "status": "published",
	})
	if pr.StatusCode != 200 {
		t.Fatalf("publish want 200, got %d", pr.StatusCode)
	}
	pr.Body.Close()

	art := wave1ArticleViaAPI(t, srv, key, created.Slug)
	if art["status"] != "published" {
		t.Fatalf("after explicit publish status = %v, want published", art["status"])
	}
}
