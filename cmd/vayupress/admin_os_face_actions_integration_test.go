// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

// Wave 3.5 row-face quick actions: the publish and pin toggles exist twice per
// row (summary face + accordion body). Whichever copy is clicked, BOTH copies
// must flip and the pill/badge must update — a face that flips while the hidden
// copy still says the opposite is the stale-UI lie this wave removes.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	dbpkg "github.com/johalputt/vayupress/internal/db"
)

func seedFacePost(t *testing.T, slug, status string, featured int) {
	t.Helper()
	if _, err := dbpkg.DB.Exec(`INSERT INTO articles(id,title,slug,content,tags,status,featured,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,datetime('now'),datetime('now'))`,
		"face-"+slug, "Face "+slug, slug, "body", "", status, featured); err != nil {
		t.Fatalf("seed post: %v", err)
	}
	t.Cleanup(func() { _, _ = dbpkg.DB.Exec(`DELETE FROM articles WHERE slug=?`, slug) })
}

// TestFaceStatusFragmentParity drives the status-fragment endpoint with
// src=face: the response must return the flipped FACE copy in place and update
// the body copy plus the pill out-of-band. The body-src path keeps its own test
// (TestOSPostToggleFragmentFlipsStatus).
func TestFaceStatusFragmentParity(t *testing.T) {
	_, _ = newTestHarness(t)
	seedFacePost(t, "face-status", "draft", 0)
	a := &App{}

	form := url.Values{"status": {"published"}, "src": {"face"}}
	req := httptest.NewRequest(http.MethodPost, "/os/api/posts/face-status/status-fragment", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("slug", "face-status")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	a.handleOSPostToggleFragment(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// In-place element: the flipped face copy (icon-only, face id, no OOB marker).
	if !strings.Contains(body, `id="post-pubface-face-status"`) || !strings.Contains(body, `>↧</span></button>`) {
		t.Errorf("expected flipped face copy in place, got:\n%s", body)
	}
	// The body copy and the pill ride out-of-band.
	if !strings.Contains(body, `id="post-pub-face-status" data-src="body" hx-swap-oob="true"`) {
		t.Errorf("expected the body copy as an out-of-band swap, got:\n%s", body)
	}
	if !strings.Contains(body, `id="post-status-face-status" hx-swap-oob="true"`) {
		t.Errorf("expected the status pill as an out-of-band swap, got:\n%s", body)
	}
	var st, feat string
	if err := dbpkg.DB.QueryRow(`SELECT status, COALESCE(featured,'') FROM articles WHERE slug=?`, "face-status").Scan(&st, &feat); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if st != "published" {
		t.Errorf("persisted status = %q, want published", st)
	}
}

// TestFacePinFragmentParity drives the pin-fragment endpoint with src=face.
func TestFacePinFragmentParity(t *testing.T) {
	_, _ = newTestHarness(t)
	seedFacePost(t, "face-pin", "published", 0)
	a := &App{}

	form := url.Values{"pinned": {"1"}, "src": {"face"}}
	req := httptest.NewRequest(http.MethodPost, "/os/api/posts/face-pin/pin-fragment", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("slug", "face-pin")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	a.handleOSPostPinFragment(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `id="post-pinface-face-pin"`) || !strings.Contains(body, `>📍</span></button>`) {
		t.Errorf("expected flipped face pin copy in place, got:\n%s", body)
	}
	if !strings.Contains(body, `id="post-pin-face-pin" data-src="body" hx-swap-oob="true"`) {
		t.Errorf("expected the body pin copy as an out-of-band swap, got:\n%s", body)
	}
	if !strings.Contains(body, `id="ppin-face-pin" hx-swap-oob="true"`) || !strings.Contains(body, "📌 Pinned") {
		t.Errorf("expected the pinned badge as an out-of-band swap, got:\n%s", body)
	}
	var feat int
	if err := dbpkg.DB.QueryRow(`SELECT COALESCE(featured,0) FROM articles WHERE slug=?`, "face-pin").Scan(&feat); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if feat != 1 {
		t.Errorf("persisted featured = %d, want 1", feat)
	}
}

// TestPostRowFaceActions pins the row markup: every rendered post row carries
// the two face toggles in its summary, CSP-safe.
func TestPostRowFaceActions(t *testing.T) {
	facePub := osPostStatusFaceButton("some-slug", "draft")
	assertCSPSafe(t, "face publish button", facePub)
	for _, want := range []string{
		`id="post-pubface-some-slug"`,
		`data-src="face"`,
		`hx-vals='{"status":"published","src":"face"}'`,
		`aria-label="Publish post"`,
	} {
		if !strings.Contains(facePub, want) {
			t.Errorf("face publish button missing %q in:\n%s", want, facePub)
		}
	}
	facePin := osPostPinFaceButton("some-slug", false)
	assertCSPSafe(t, "face pin button", facePin)
	if !strings.Contains(facePin, `id="post-pinface-some-slug"`) || !strings.Contains(facePin, `hx-vals='{"pinned":"1","src":"face"}'`) {
		t.Errorf("face pin button wrong:\n%s", facePin)
	}
}
