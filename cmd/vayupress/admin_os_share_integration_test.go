// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

// Wave 4.4 — the draft share endpoint. A "share draft" button that worked on
// published posts would mint tokens implying exclusivity over content that is
// already public; the endpoint refuses with an honest 409 instead.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/preview"
)

func newPreviewSignerForTest(t *testing.T) *preview.Signer {
	t.Helper()
	return preview.New("test-preview-secret")
}

func TestDraftShareEndpoint(t *testing.T) {
	_, _ = newTestHarness(t)
	if _, err := dbpkg.DB.Exec(`INSERT INTO articles(id,title,slug,content,tags,status,created_at,updated_at)
		 VALUES('sh1','Public One','sh1-public','body','','published',datetime('now'),datetime('now')),
		       ('sh2','Hidden Draft','sh2-draft','body','','draft',datetime('now','+1 second'),datetime('now','+1 second'))`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() { _, _ = dbpkg.DB.Exec(`DELETE FROM articles WHERE slug IN ('sh1-public','sh2-draft')`) })
	a := &App{}
	if a.previewSigner == nil {
		a.previewSigner = newPreviewSignerForTest(t)
	}

	call := func(slug string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/os/api/posts/"+slug+"/share", strings.NewReader("{}"))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("slug", slug)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()
		a.handleOSPostShare(rec, req)
		return rec
	}

	// A draft shares: 200, URL carries the preview token.
	rec := call("sh2-draft")
	if rec.Code != http.StatusOK {
		t.Fatalf("draft share status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		URL   string `json:"url"`
		Token string `json:"token"`
		TTL   string `json:"ttl"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(out.URL, "/sh2-draft?preview=") || out.Token == "" {
		t.Errorf("share response = %+v, want a preview URL and token", out)
	}
	if out.TTL != "48h" {
		t.Errorf("share ttl = %q, want 48h (an expiring link is the point)", out.TTL)
	}

	// A published post refuses with a conflict, not a token.
	published := call("sh1-public")
	if published.Code != http.StatusConflict {
		t.Errorf("published share status = %d, want 409 — sharing a public post pretends exclusivity that does not exist", published.Code)
	}

	// A garbage slug is a 400 before anything else.
	if rec := call(""); rec.Code != http.StatusBadRequest {
		t.Errorf("bad slug status = %d, want 400", rec.Code)
	}
}
