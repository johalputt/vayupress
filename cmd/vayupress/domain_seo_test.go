// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/search"
)

// setupSEOTestDB configures a temp SQLite DB + cache dir and seeds three
// published articles: two on the primary (domain_id "") and one on a secondary
// domain ("sec"). It returns the cache dir so callers can read generated
// artefacts back.
func setupSEOTestDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	os.Setenv("DB_PATH", filepath.Join(dir, "seo.db"))
	os.Setenv("API_KEY", "test-key")
	os.Setenv("DOMAIN", "example.test")
	os.Setenv("CACHE_DIR", dir)
	os.Setenv("STORAGE_QUOTA_GB", "10")
	config.Load()
	if err := dbpkg.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	t.Cleanup(func() {
		dbpkg.ClosePools()
		_ = dbpkg.DB.Close()
	})

	repo := dbpkg.NewArticleRepo(dbpkg.DB)
	ctx := context.Background()
	now := time.Now()
	mk := func(slug, domainID string, tags []string) {
		if err := repo.Create(ctx, dbpkg.Article{
			ID: slug, Title: slug, Slug: slug, Content: "<p>body of " + slug + "</p>",
			Tags: tags, Status: "published", DomainID: domainID, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("create %s: %v", slug, err)
		}
	}
	mk("primary-one", "", []string{"news"})
	mk("primary-two", "", []string{"news", "guide"})
	mk("secondary-one", "sec", []string{"shop"})
	return dir
}

func TestWriteSitemapScoped(t *testing.T) {
	dir := setupSEOTestDB(t)

	// Global (single-domain / primary) artefact: every published slug, primary host.
	writeSitemapScoped(config.Cfg.Domain, "", false, "sitemap_global.xml")
	// sitemap.xml is a sitemapindex now, so the URLs live in its children. The
	// invariant under test is unchanged — every published slug is reachable from
	// the entry point — only the number of hops to reach it.
	global := readSitemapAll(t, dir, "sitemap_global.xml")
	for _, want := range []string{"example.test/primary-one", "example.test/primary-two", "example.test/secondary-one"} {
		if !strings.Contains(global, want) {
			t.Errorf("global sitemap missing %q\n%s", want, global)
		}
	}

	// Secondary-scoped artefact: only the secondary domain's slug, its own host.
	writeSitemapScoped("shop.example", "sec", true, "sitemap_sec.xml")
	sec := readSitemapAll(t, dir, "sitemap_sec.xml")
	if !strings.Contains(sec, "shop.example/secondary-one") {
		t.Errorf("secondary sitemap missing its own post\n%s", sec)
	}
	if strings.Contains(sec, "primary-one") || strings.Contains(sec, "primary-two") {
		t.Errorf("secondary sitemap leaked a primary post\n%s", sec)
	}
	// A secondary tag (shop) is listed; a primary-only tag (guide) is not.
	if !strings.Contains(sec, "/tags/shop") {
		t.Errorf("secondary sitemap missing its own tag page\n%s", sec)
	}
	if strings.Contains(sec, "/tags/guide") {
		t.Errorf("secondary sitemap leaked a primary-only tag page\n%s", sec)
	}
}

func TestWriteRSSScoped(t *testing.T) {
	dir := setupSEOTestDB(t)

	writeRSSScoped("shop.example", "sec", true, "feed_sec.xml")
	sec := readFile(t, dir, "feed_sec.xml")
	if !strings.Contains(sec, "shop.example/secondary-one") {
		t.Errorf("secondary feed missing its own post\n%s", sec)
	}
	if strings.Contains(sec, "primary-one") || strings.Contains(sec, "primary-two") {
		t.Errorf("secondary feed leaked a primary post\n%s", sec)
	}
	// Channel link should carry the secondary host, not the configured primary.
	if !strings.Contains(sec, "<link>https://shop.example</link>") {
		t.Errorf("secondary feed channel link is not the secondary host\n%s", sec)
	}
}

func TestDomainSlugSetAndFilterHits(t *testing.T) {
	setupSEOTestDB(t)
	ctx := context.Background()

	set := domainSlugSet(ctx, "sec", []string{"primary-one", "secondary-one", "primary-two"})
	if _, ok := set["secondary-one"]; !ok {
		t.Fatal("domainSlugSet dropped the owned slug")
	}
	if _, ok := set["primary-one"]; ok {
		t.Fatal("domainSlugSet included a foreign slug")
	}

	hits := []search.Hit{{Slug: "primary-one"}, {Slug: "secondary-one"}, {Slug: "primary-two"}}
	kept := filterHitsByDomain(ctx, hits, "sec", 10)
	if len(kept) != 1 || kept[0].Slug != "secondary-one" {
		t.Fatalf("filterHitsByDomain = %+v, want only secondary-one", kept)
	}

	// Primary scope keeps exactly its two posts, in rank order.
	keptPrim := filterHitsByDomain(ctx, hits, "", 10)
	if len(keptPrim) != 2 || keptPrim[0].Slug != "primary-one" || keptPrim[1].Slug != "primary-two" {
		t.Fatalf("primary filter = %+v, want primary-one then primary-two", keptPrim)
	}

	// The limit truncates after filtering.
	if got := filterHitsByDomain(ctx, hits, "", 1); len(got) != 1 {
		t.Fatalf("limit not applied: got %d, want 1", len(got))
	}
}

func TestScopedSearchIndex(t *testing.T) {
	setupSEOTestDB(t)
	ctx := context.Background()
	purgeDomainSearchIndex() // isolate from any other test's memo

	base := "abc123"
	payload, _ := json.Marshal(clientIndexView{V: base, N: 3, Posts: []clientPostView{
		{T: "primary-one", U: "primary-one"},
		{T: "secondary-one", U: "secondary-one"},
		{T: "primary-two", U: "primary-two"},
	}})

	out, version := a0().scopedSearchIndex(ctx, "sec", base, payload)
	if version != base+"-dsec" {
		t.Fatalf("scoped version = %q, want %q", version, base+"-dsec")
	}
	var idx clientIndexView
	if err := json.Unmarshal(out, &idx); err != nil {
		t.Fatalf("unmarshal scoped index: %v", err)
	}
	if len(idx.Posts) != 1 || idx.Posts[0].U != "secondary-one" {
		t.Fatalf("scoped index posts = %+v, want only secondary-one", idx.Posts)
	}
	if idx.N != 1 {
		t.Fatalf("scoped index N = %d, want 1 (domain's published count)", idx.N)
	}

	// Same base version is served from the memo (identical bytes).
	out2, _ := a0().scopedSearchIndex(ctx, "sec", base, payload)
	if string(out2) != string(out) {
		t.Fatal("memo returned a different payload for the same base version")
	}
}

// a0 returns a bare App sufficient for the domain-scope helpers under test (they
// touch only the global DB + config, not App state).
func a0() *App { return &App{} }

func readFile(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// readSitemapAll returns the index concatenated with every child it names, so a
// test can assert on "what the sitemap says" without caring how many files that
// is spread across.
func readSitemapAll(t *testing.T, dir, indexRel string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString(readFile(t, dir, indexRel))
	for n := 1; n <= 50; n++ {
		child := sitemapChildRel(indexRel, n)
		body, err := os.ReadFile(filepath.Join(dir, child))
		if err != nil {
			break
		}
		b.Write(body)
	}
	if body, err := os.ReadFile(filepath.Join(dir, sitemapTagsRel(indexRel))); err == nil {
		b.Write(body)
	}
	return b.String()
}
