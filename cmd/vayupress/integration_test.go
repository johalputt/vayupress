// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/microcosm-cc/bluemonday"

	"github.com/johalputt/vayupress/internal/api"
	"github.com/johalputt/vayupress/internal/auth"
	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/events"
	"github.com/johalputt/vayupress/internal/plugins"
	"github.com/johalputt/vayupress/internal/queue"
	"github.com/johalputt/vayupress/internal/render"
	"github.com/johalputt/vayupress/internal/search"
	"github.com/johalputt/vayupress/internal/versions"
)

// noopSearch satisfies search.Service with no-op implementations for tests.
type noopSearch struct{}

func (n *noopSearch) Search(_ context.Context, _ string, _ int) (search.Result, error) {
	return search.Result{Hits: []search.Hit{}}, nil
}
func (n *noopSearch) Index(_ context.Context, _, _, _, _ string, _ []string, _ int64) error {
	return nil
}
func (n *noopSearch) Delete(_ context.Context, _ string) error            { return nil }
func (n *noopSearch) Ping(_ context.Context) error                        { return nil }
func (n *noopSearch) DocCount(_ context.Context) (int, error)             { return 0, nil }
func (n *noopSearch) Snapshot() ([]byte, string)                          { return []byte(`{"v":"0","posts":[]}`), "0" }
func (n *noopSearch) Load(_ context.Context) error                        { return nil }
func (n *noopSearch) SaveIndex(_ context.Context, _ string) error         { return nil }
func (n *noopSearch) LoadIndex(_ context.Context, _ string) (bool, error) { return false, nil }

// directWriter inserts/updates/deletes directly into the articles table so
// integration tests can read back results without running the queue worker. It
// mirrors the worker's transactional article_tags sync so tag lookups behave
// exactly as they do in production.
type directWriter struct{}

func (directWriter) Enqueue(ctx context.Context, art dbpkg.Article, op string) error {
	tagsCSV := ""
	for i, t := range art.Tags {
		if i > 0 {
			tagsCSV += ","
		}
		tagsCSV += t
	}
	switch op {
	case "insert":
		return dbpkg.RunInTx(ctx, dbpkg.DB, func(tx *sql.Tx) error {
			// Mirror production insert (internal/queue): the status column is
			// persisted, with "" falling back to the historical default. Without
			// this the harness silently republished every draft-born article.
			status := strings.TrimSpace(art.Status)
			if status == "" {
				status = "published"
			}
			if _, err := tx.Exec(
				`INSERT INTO articles(id,title,slug,content,tags,created_at,updated_at,status) VALUES(?,?,?,?,?,?,?,?)`,
				art.ID, art.Title, art.Slug, art.Content, tagsCSV,
				art.CreatedAt.Format(time.RFC3339), art.UpdatedAt.Format(time.RFC3339), status,
			); err != nil {
				return err
			}
			return dbpkg.SyncArticleTagsByIDTx(tx, art.ID, art.CreatedAt, art.Tags)
		})
	case "update":
		return dbpkg.RunInTx(ctx, dbpkg.DB, func(tx *sql.Tx) error {
			// Mirror production update: snapshot the overwritten row first so
			// version history behaves in tests exactly as it does live.
			var vID, vTitle, vContent, vTags string
			if err := tx.QueryRow(`SELECT id,title,content,COALESCE(tags,'') FROM articles WHERE slug=?`, art.Slug).
				Scan(&vID, &vTitle, &vContent, &vTags); err == nil {
				_, _ = tx.Exec(`INSERT INTO article_versions(article_id,slug,title,content,tags,label) VALUES(?,?,?,?,?,?)`,
					vID, art.Slug, vTitle, vContent, vTags, "pre-update")
			}
			if _, err := tx.Exec(
				`UPDATE articles SET title=?,content=?,tags=?,updated_at=? WHERE slug=?`,
				art.Title, art.Content, tagsCSV,
				art.UpdatedAt.Format(time.RFC3339), art.Slug,
			); err != nil {
				return err
			}
			return dbpkg.SyncArticleTagsBySlugTx(tx, art.Slug, art.Tags)
		})
	case "delete":
		return dbpkg.RunInTx(ctx, dbpkg.DB, func(tx *sql.Tx) error {
			if err := dbpkg.DeleteArticleTagsBySlugTx(tx, art.Slug); err != nil {
				return err
			}
			_, err := tx.Exec(`DELETE FROM articles WHERE slug=?`, art.Slug)
			return err
		})
	}
	return fmt.Errorf("unknown op: %s", op)
}

var _ queue.Writer = directWriter{}

// testClientSeq generates a distinct simulated client IP per test request.
var testClientSeq int64

// newTestHarness spins up a full HTTP test server backed by a temp SQLite DB.
// Callers must call the returned cleanup func when the test ends.
func newTestHarness(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()

	os.Setenv("DB_PATH", filepath.Join(dir, "test.db"))
	os.Setenv("API_KEY", "test-key")
	os.Setenv("DOMAIN", "localhost")
	os.Setenv("PORT", "0")
	os.Setenv("CACHE_DIR", dir)
	os.Setenv("STORAGE_QUOTA_GB", "10")
	config.Load()

	// Drain CachePurge's async sitemap/feed/robots writers at the end of each
	// test. Registered before the temp-dir cleanup (which t.TempDir queued
	// earlier) so it runs first (LIFO): the fire-and-forget writers finish before
	// the temp dir is removed AND before the next test's config.Load mutates the
	// process-global config.Cfg — closing a data race the -race detector would
	// otherwise flag across the integration suite.
	t.Cleanup(render.WaitForPurges)

	if err := dbpkg.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	// Release the WAL read pools BEFORE the temp-dir cleanup runs (LIFO: this
	// registered-after-TempDir cleanup executes first). On Windows an open pool
	// handle keeps test.db locked, so otherwise every harness test fails in
	// teardown regardless of its assertions.
	t.Cleanup(func() {
		dbpkg.ClosePools()
		dbpkg.DB.Close()
	})

	auth.InitCSRFSecret()

	a := &App{
		policy:         bluemonday.UGCPolicy(),
		outboundClient: &http.Client{Timeout: 5 * time.Second},
		pluginRegistry: plugins.NewRegistry(),
		eventBus:       events.NewBus(),
		articles: &api.ArticleService{
			Repo:  dbpkg.NewArticleRepo(dbpkg.DB),
			Queue: directWriter{},
		},
		search:       &noopSearch{},
		versionStore: versions.New(dbpkg.DB),
	}
	a.pluginManager = plugins.New(a.pluginRegistry)

	// Drain the App's tracked background goroutines (IndexNow announcement,
	// event-driven indexing) BEFORE the DB pools close and before the next
	// test's config.Load mutates the process globals those goroutines read.
	// LIFO: registered after the ClosePools cleanup, so it runs before it.
	t.Cleanup(a.bgWG.Wait)

	r := chi.NewRouter()
	a.registerRoutes(r, dir)

	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	return srv, "test-key"
}

func doRequest(t *testing.T, srv *httptest.Server, method, path string, apiKey string, body interface{}) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	// The harness connects from 127.0.0.1 — a default trusted proxy — so set a
	// distinct X-Forwarded-For per request to mirror real traffic arriving via
	// the localhost reverse proxy. Without it, every request would share the
	// single 127.0.0.1 per-IP rate-limit/lockout bucket and conflate unrelated
	// requests (auth.ClientIP keys on host, not the ephemeral source port).
	seq := atomic.AddInt64(&testClientSeq, 1)
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.%d.%d", (seq/254)%254, seq%254+1))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func decodeBody(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	defer resp.Body.Close()
	var m map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return m
}

// =============================================================================
// Tests
// =============================================================================

func TestIntegration_CreateArticle_Returns202(t *testing.T) {
	srv, key := newTestHarness(t)
	resp := doRequest(t, srv, "POST", "/api/v1/articles", key, map[string]interface{}{
		"title": "Hello World", "slug": "hello-world",
		"content": "Integration test content.", "tags": []string{"test"},
	})
	if resp.StatusCode != 202 {
		t.Fatalf("want 202, got %d", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	if body["slug"] != "hello-world" {
		t.Errorf("want slug hello-world, got %v", body["slug"])
	}
	if body["status"] != "queued" {
		t.Errorf("want status queued, got %v", body["status"])
	}
}

func TestIntegration_GetArticle_AfterCreate(t *testing.T) {
	srv, key := newTestHarness(t)
	doRequest(t, srv, "POST", "/api/v1/articles", key, map[string]interface{}{
		"title": "Readable", "slug": "readable-slug",
		"content": "Some content.", "tags": []string{},
	})
	resp := doRequest(t, srv, "GET", "/api/v1/articles/readable-slug", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	if body["title"] != "Readable" {
		t.Errorf("want title Readable, got %v", body["title"])
	}
}

func TestIntegration_GetArticle_NotFound(t *testing.T) {
	srv, _ := newTestHarness(t)
	resp := doRequest(t, srv, "GET", "/api/v1/articles/no-such-slug", "", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	errMap, _ := body["error"].(map[string]interface{})
	if errMap["code"] != "not_found" {
		t.Errorf("want code not_found, got %v", errMap["code"])
	}
}

func TestIntegration_CreateArticle_SlugConflict(t *testing.T) {
	srv, key := newTestHarness(t)
	payload := map[string]interface{}{
		"title": "Dup", "slug": "dup-slug", "content": "x.", "tags": []string{},
	}
	doRequest(t, srv, "POST", "/api/v1/articles", key, payload)
	resp := doRequest(t, srv, "POST", "/api/v1/articles", key, payload)
	if resp.StatusCode != 409 {
		t.Fatalf("want 409, got %d", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	errMap, _ := body["error"].(map[string]interface{})
	if errMap["code"] != "slug_conflict" {
		t.Errorf("want slug_conflict, got %v", errMap["code"])
	}
}

func TestIntegration_ListArticles_Empty(t *testing.T) {
	srv, _ := newTestHarness(t)
	resp := doRequest(t, srv, "GET", "/api/v1/articles", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	articles, _ := body["articles"].([]interface{})
	if len(articles) != 0 {
		t.Errorf("want empty list, got %d items", len(articles))
	}
}

func TestIntegration_DeleteArticle(t *testing.T) {
	srv, key := newTestHarness(t)
	doRequest(t, srv, "POST", "/api/v1/articles", key, map[string]interface{}{
		"title": "To Delete", "slug": "to-delete", "content": "bye.", "tags": []string{},
	})
	resp := doRequest(t, srv, "DELETE", "/api/v1/articles/to-delete", key, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	get := doRequest(t, srv, "GET", "/api/v1/articles/to-delete", "", nil)
	if get.StatusCode != 404 {
		t.Fatalf("want 404 after delete, got %d", get.StatusCode)
	}
}

func TestIntegration_RequiresAPIKey(t *testing.T) {
	srv, _ := newTestHarness(t)
	resp := doRequest(t, srv, "POST", "/api/v1/articles", "", map[string]interface{}{
		"title": "Unauthorized", "slug": "unauth", "content": "x.", "tags": []string{},
	})
	if resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}
