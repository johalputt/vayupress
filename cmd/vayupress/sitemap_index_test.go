// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
)

// TestSitemapIndexCoversEveryPost is the regression guard for a silent, total
// SEO failure.
//
// The sitemap was one file with `LIMIT 50000`, then every tag page appended
// after it. On the install that reported this — 234,480 published posts — that
// omitted 184,480 of them outright: those URLs were never announced to any
// search engine, and no error was raised anywhere, because truncation is what
// LIMIT is for. The appended tags then pushed the file past the protocol's
// 50,000-URL cap, at which point a crawler is entitled to reject the WHOLE
// document rather than the overflow.
//
// So the failure was not "a few posts are missed". It was a file that looked
// authoritative and described a site that did not exist.
func TestSitemapIndexCoversEveryPost(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DB_PATH", filepath.Join(dir, "sm.db"))
	t.Setenv("API_KEY", "k")
	t.Setenv("DOMAIN", "example.test")
	t.Setenv("CACHE_DIR", dir)
	t.Setenv("STORAGE_QUOTA_GB", "10")
	config.Load()
	if err := dbpkg.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	t.Cleanup(func() {
		dbpkg.ClosePools()
		_ = dbpkg.DB.Close()
	})

	// Shrink the chunk so the boundary is reachable: 7 posts over chunks of 3
	// means three children, the last one partial.
	prev := sitemapChunk
	sitemapChunk = 3
	t.Cleanup(func() { sitemapChunk = prev })

	repo := dbpkg.NewArticleRepo(dbpkg.DB)
	ctx := context.Background()
	want := map[string]bool{}
	for i := 0; i < 7; i++ {
		slug := "post-" + string(rune('a'+i))
		now := time.Now()
		if err := repo.Create(ctx, dbpkg.Article{
			ID: slug, Title: "T" + slug, Slug: slug, Content: "<p>b</p>",
			Tags: []string{"tagx"}, Status: "published", CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("seed %s: %v", slug, err)
		}
		want[slug] = false
	}

	writeSitemapScoped("example.test", "", false, "sitemap.xml")

	idx, err := os.ReadFile(filepath.Join(dir, "sitemap.xml"))
	if err != nil {
		t.Fatalf("no sitemap index written: %v", err)
	}
	if !strings.Contains(string(idx), "<sitemapindex") {
		t.Fatalf("sitemap.xml is not an index:\n%s", idx)
	}
	// Read every child the index names and account for all seven posts.
	children := 0
	for n := 1; n <= 10; n++ {
		child := sitemapChildRel("sitemap.xml", n)
		body, err := os.ReadFile(filepath.Join(dir, child))
		if err != nil {
			break
		}
		children++
		if !strings.Contains(string(idx), child) {
			t.Errorf("%s exists but the index does not list it — its URLs are unreachable", child)
		}
		if got := strings.Count(string(body), "<url>"); got > sitemapChunk {
			t.Errorf("%s holds %d URLs, over the %d cap — a crawler may reject the whole file",
				child, got, sitemapChunk)
		}
		for slug := range want {
			if strings.Contains(string(body), "/"+slug+"<") {
				want[slug] = true
			}
		}
	}
	if children != 3 {
		t.Errorf("7 posts at a chunk of 3 produced %d children, want 3", children)
	}
	for slug, seen := range want {
		if !seen {
			t.Errorf("post %q appears in NO sitemap child — it is invisible to every crawler "+
				"that trusts the sitemap", slug)
		}
	}
	// Tags live in their own child so the taxonomy can never be what tips a post
	// file over the cap.
	if _, err := os.Stat(filepath.Join(dir, sitemapTagsRel("sitemap.xml"))); err != nil {
		t.Errorf("no tags sitemap written: %v", err)
	}
	if !strings.Contains(string(idx), sitemapTagsRel("sitemap.xml")) {
		t.Error("the index does not list the tags child")
	}
}
