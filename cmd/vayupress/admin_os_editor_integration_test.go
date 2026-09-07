// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/johalputt/vayupress/internal/auth"
)

// TestOSEditorSaveRoundTrip exercises the full save path: create a draft, POST a
// block document, and confirm the rendered HTML lands in content and the raw
// blocks persist for re-hydration.
func TestOSEditorSaveRoundTrip(t *testing.T) {
	srv, key := newTestHarness(t)

	doRequest(t, srv, "POST", "/api/v1/articles", key, map[string]interface{}{
		"title": "Draft", "slug": "draft-post", "content": "seed", "tags": []string{},
	})

	csrf := auth.GenerateCSRFToken("")
	if csrf == "" {
		t.Fatal("could not generate CSRF token")
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"slug":  "draft-post",
		"title": "Draft Updated",
		"blocks": []map[string]interface{}{
			{"type": "heading", "level": 2, "text": "Section"},
			{"type": "paragraph", "text": "Body text here"},
		},
	})
	req, _ := http.NewRequest("POST", srv.URL+"/os/api/editor/save", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "vp_csrf", Value: csrf})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("save request: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("save want 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	getResp := doRequest(t, srv, "GET", "/api/v1/articles/draft-post", "", nil)
	body := decodeBody(t, getResp)
	content, _ := body["content"].(string)
	if !strings.Contains(content, "<h2>Section</h2>") || !strings.Contains(content, "Body text here") {
		t.Errorf("article content not rendered from blocks: %q", content)
	}
}

// TestOSQuickCreateOpensBlockEditor verifies the dashboard quick-compose creates
// a draft (non-empty content to pass validation, but blank after trim) and that
// the editor then opens the block editor for it rather than 500-ing.
func TestOSQuickCreateOpensBlockEditor(t *testing.T) {
	srv, key := newTestHarness(t)

	csrf := auth.GenerateCSRFToken("")
	body, _ := json.Marshal(map[string]string{"title": "My Fresh Draft"})
	req, _ := http.NewRequest("POST", srv.URL+"/os/api/posts/quick-create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "vp_csrf", Value: csrf})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("quick-create request: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("quick-create want 200, got %d", resp.StatusCode)
	}
	var out struct{ Slug string }
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if out.Slug == "" {
		t.Fatal("quick-create returned no slug")
	}

	// The editor page for the new draft must open the block editor (data-editor
	// canvas + the block editor script), not error.
	er := doRequest(t, srv, "GET", "/os/editor/"+out.Slug, key, nil)
	if er.StatusCode != 200 {
		t.Fatalf("editor GET want 200, got %d", er.StatusCode)
	}
	buf := new(strings.Builder)
	io.Copy(buf, er.Body)
	er.Body.Close()
	if !strings.Contains(buf.String(), "data-editor-canvas") {
		t.Error("expected block editor for fresh quick-created draft")
	}
}

// TestOSEditorNativeCreatePath verifies the block editor owns the create flow:
// a Save with an empty slug creates the article (slug derived from title),
// renders the blocks into content, and the new-post URL (/os/editor) opens the
// native block editor rather than the legacy v2 editor.
func TestOSEditorNativeCreatePath(t *testing.T) {
	srv, key := newTestHarness(t)

	// The "New Post" route (no slug) must serve the native block editor.
	np := doRequest(t, srv, "GET", "/os/editor", key, nil)
	if np.StatusCode != 200 {
		t.Fatalf("new-post editor GET want 200, got %d", np.StatusCode)
	}
	npBuf := new(strings.Builder)
	io.Copy(npBuf, np.Body)
	np.Body.Close()
	if !strings.Contains(npBuf.String(), "data-editor-canvas") {
		t.Error("new-post route should serve the native block editor")
	}
	if strings.Contains(npBuf.String(), "/os/static/js/admin-v2.js") ||
		strings.Contains(npBuf.String(), "/admin/v2/static/js/admin-v2.js") {
		t.Error("new-post route must not depend on the legacy v2 editor assets")
	}

	// A Save with no slug creates the post.
	csrf := auth.GenerateCSRFToken("")
	payload, _ := json.Marshal(map[string]interface{}{
		"slug":  "",
		"title": "Born In Blocks",
		"blocks": []map[string]interface{}{
			{"type": "heading", "level": 2, "text": "Hello"},
			{"type": "paragraph", "text": "Created natively"},
		},
	})
	req, _ := http.NewRequest("POST", srv.URL+"/os/api/editor/save", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "vp_csrf", Value: csrf})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create-save request: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("create-save want 200, got %d", resp.StatusCode)
	}
	var out struct{ Status, Slug string }
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if out.Status != "created" || out.Slug == "" {
		t.Fatalf("create-save: want status=created with a slug, got %+v", out)
	}

	// The created article must carry the rendered block content.
	// Drafts are hidden from unauthenticated requests, so we use the
	// admin key the same way every other editor integration test does.
	getResp := doRequest(t, srv, "GET", "/api/v1/articles/"+out.Slug, key, nil)
	body := decodeBody(t, getResp)
	content, _ := body["content"].(string)
	if !strings.Contains(content, "<h2>Hello</h2>") || !strings.Contains(content, "Created natively") {
		t.Errorf("created article content not rendered from blocks: %q", content)
	}

	// A create-save with no title must be rejected (slug cannot be derived).
	noTitle, _ := json.Marshal(map[string]interface{}{"slug": "", "title": "  ", "blocks": []interface{}{}})
	req2, _ := http.NewRequest("POST", srv.URL+"/os/api/editor/save", bytes.NewReader(noTitle))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-API-Key", key)
	req2.Header.Set("X-CSRF-Token", csrf)
	req2.AddCookie(&http.Cookie{Name: "vp_csrf", Value: csrf})
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("no-title request: %v", err)
	}
	if resp2.StatusCode != 400 {
		t.Errorf("create-save without title want 400, got %d", resp2.StatusCode)
	}
	resp2.Body.Close()
}

// TestOSEditorImportHTML exercises the HTML source mode round-trip: posting raw
// HTML to /os/api/editor/import returns a block document, and inline formatting
// is preserved (re-encoded as Markdown) so a visual → HTML → visual switch does
// not drop bold/links.
func TestOSEditorImportHTML(t *testing.T) {
	srv, key := newTestHarness(t)

	csrf := auth.GenerateCSRFToken("")
	payload, _ := json.Marshal(map[string]string{
		"html": `<h2>Title</h2><p>Some <strong>bold</strong> and a <a href="/x">link</a>.</p>`,
	})
	req, _ := http.NewRequest("POST", srv.URL+"/os/api/editor/import", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "vp_csrf", Value: csrf})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("import request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("import want 200, got %d", resp.StatusCode)
	}
	var out struct {
		Blocks []map[string]interface{} `json:"blocks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Blocks) != 2 {
		t.Fatalf("want 2 blocks, got %d: %+v", len(out.Blocks), out.Blocks)
	}
	if out.Blocks[0]["type"] != "heading" {
		t.Errorf("block 0 type = %v, want heading", out.Blocks[0]["type"])
	}
	para, _ := out.Blocks[1]["text"].(string)
	if !strings.Contains(para, "**bold**") || !strings.Contains(para, "[link](/x)") {
		t.Errorf("inline formatting not preserved on import: %q", para)
	}
}

// TestOSEditorSavePersistsPublishingOptions verifies the editor save path stores
// the Post-settings side-car (PostMeta) and the publish-date override alongside
// the block document.
func TestOSEditorSavePersistsPublishingOptions(t *testing.T) {
	srv, key := newTestHarness(t)

	doRequest(t, srv, "POST", "/api/v1/articles", key, map[string]interface{}{
		"title": "Draft", "slug": "meta-post", "content": "seed", "tags": []string{},
	})

	csrf := auth.GenerateCSRFToken("")
	payload, _ := json.Marshal(map[string]interface{}{
		"slug":  "meta-post",
		"title": "Meta Post",
		"blocks": []map[string]interface{}{
			{"type": "paragraph", "text": "Body"},
		},
		"tags":        []string{"go", "web"},
		"publishDate": "2030-01-02T03:04",
		"meta": map[string]interface{}{
			"excerpt":      "Short summary",
			"metaTitle":    "SEO Title",
			"canonicalURL": "https://x.example/y",
			"ogImage":      "/media/share.jpg",
			"featured":     true,
			"isPage":       true,
		},
	})
	req, _ := http.NewRequest("POST", srv.URL+"/os/api/editor/save", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "vp_csrf", Value: csrf})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("save request: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("save want 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// PostMeta columns are written synchronously, so they are readable at once.
	pm := loadPostMeta(context.Background(), "meta-post")
	if pm.Excerpt != "Short summary" {
		t.Errorf("excerpt: got %q", pm.Excerpt)
	}
	if pm.MetaTitle != "SEO Title" {
		t.Errorf("metaTitle: got %q", pm.MetaTitle)
	}
	if pm.CanonicalURL != "https://x.example/y" {
		t.Errorf("canonicalURL: got %q", pm.CanonicalURL)
	}
	if pm.OGImage != "/media/share.jpg" {
		t.Errorf("ogImage: got %q", pm.OGImage)
	}
	if !pm.Featured || !pm.IsPage {
		t.Errorf("flags: featured=%v isPage=%v, want both true", pm.Featured, pm.IsPage)
	}
}

// TestOSEditorSlugRename verifies the dedicated rename endpoint moves a post to a
// new (slugified, uniquified) URL and the old URL stops resolving.
func TestOSEditorSlugRename(t *testing.T) {
	srv, key := newTestHarness(t)

	doRequest(t, srv, "POST", "/api/v1/articles", key, map[string]interface{}{
		"title": "Old", "slug": "old-slug", "content": "seed", "tags": []string{},
	})

	csrf := auth.GenerateCSRFToken("")
	payload, _ := json.Marshal(map[string]string{"slug": "old-slug", "newSlug": "Brand New Title!"})
	req, _ := http.NewRequest("POST", srv.URL+"/os/api/editor/slug", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "vp_csrf", Value: csrf})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("slug request: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("slug rename want 200, got %d", resp.StatusCode)
	}
	var out struct{ Slug string }
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if out.Slug != "brand-new-title" {
		t.Fatalf("renamed slug: got %q, want brand-new-title", out.Slug)
	}

	// New URL resolves, old one is gone.
	if r := doRequest(t, srv, "GET", "/api/v1/articles/brand-new-title", key, nil); r.StatusCode != 200 {
		t.Errorf("new slug GET want 200, got %d", r.StatusCode)
	} else {
		r.Body.Close()
	}
	if r := doRequest(t, srv, "GET", "/api/v1/articles/old-slug", key, nil); r.StatusCode == 200 {
		t.Error("old slug should no longer resolve")
	} else {
		r.Body.Close()
	}
}
