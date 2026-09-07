// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
)

// The attack, and why the media quota does not stop it.
//
// MediaDir now has a ceiling, so a key holding nothing but media:write can no
// longer fill the disk through the upload path. It can still fill it through the
// endpoint next door. POST /api/v1/admin/embed/unfurl sits in the SAME
// capability section (api_capabilities.go maps /api/v1/admin/embed to
// SectionMedia, and api_capabilities_test.go pins it at ActionWrite), fetches a
// page the caller nominates, and writes a PERMANENT embed_cache row carrying the
// og:title, og:description and og:site_name it found there.
//
// Every quantity in that row is chosen by whoever wrote the page:
//
//   - the page may be up to maxUnfurlBytes (1 MB), and the og content attribute
//     is read with ([^"']*) — one tag can therefore carry most of that megabyte;
//   - the row key is the request URL, so a query string the caller varies makes
//     every request a new row rather than an update;
//   - nothing prunes the table. There is no retention job, no eviction and no
//     ceiling — migration 027 creates it and nothing has ever deleted from it.
//
// So the outcome the quota was written to prevent arrives anyway, by the same
// credential, one endpoint sideways: the filesystem fills, SQLite cannot write,
// and the install answers 502. A ceiling on MediaDir that leaves an unbounded
// sink on the same disk, reachable by the same key, has moved the finding rather
// than closed it.
//
// Both dimensions have to be bounded, and each has its own test below, because
// bounding only one leaves the attack intact: a cap on row count with megabyte
// rows still buys gigabytes, and a cap on row size with unlimited rows still
// buys everything.

// embedCacheTestDB brings up a real migrated database for the cache tests. The
// assertions are counted in SQL against the actual table, not against what the
// writer believed it wrote.
//
// Both process-globals it disturbs are put back. config.Load() rewrites the
// WHOLE of config.Cfg, not the handful of fields this test cares about, so
// restoring t.Setenv's environment is not enough — the loaded struct outlives
// the test and every later test in the binary then runs against a media
// directory that has been deleted and a quota nobody set. That is not
// hypothetical: it turned a green suite red, in a media test three files away,
// while each test passed on its own.
func embedCacheTestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DB_PATH", filepath.Join(dir, "embedcache.db"))
	t.Setenv("API_KEY", "k")
	t.Setenv("DOMAIN", "example.test")
	t.Setenv("CACHE_DIR", dir)
	t.Setenv("MEDIA_DIR", filepath.Join(dir, "media"))

	prevCfg := config.Cfg
	config.Load()

	prevDB := dbpkg.DB
	if err := dbpkg.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	t.Cleanup(func() {
		// ClosePools first: on Windows the pool connections keep embedcache.db
		// open and the t.TempDir RemoveAll fails after the assertions passed.
		dbpkg.ClosePools()
		_ = dbpkg.DB.Close()
		dbpkg.DB = prevDB
		config.Cfg = prevCfg
		invalidateMediaUsage()
	})
}

// One unfurl of one hostile page must not be able to deposit a megabyte of that
// page's own text into the database.
func TestEmbedCacheRefusesToStoreAPageWorthOfText(t *testing.T) {
	embedCacheTestDB(t)

	// What one 1 MB page can carry through the og parser, in each field that is
	// persisted verbatim.
	flood := strings.Repeat("A", maxUnfurlBytes/2)
	a := &App{}
	a.saveEmbedCache("https://attacker.test/one", &unfurlResponse{
		URL:         "https://attacker.test/" + flood,
		Title:       flood,
		Description: flood,
		Provider:    flood,
	})

	var title, description, provider, resolved int
	err := dbpkg.DB.QueryRow(
		`SELECT LENGTH(title), LENGTH(description), LENGTH(provider), LENGTH(resolved_url)
		   FROM embed_cache WHERE url = ?`, "https://attacker.test/one",
	).Scan(&title, &description, &provider, &resolved)
	if err != nil {
		t.Fatalf("read back the cached row: %v", err)
	}

	for _, f := range []struct {
		name string
		got  int
		max  int
	}{
		{"title", title, maxCachedEmbedTitle},
		{"description", description, maxCachedEmbedDescription},
		{"provider", provider, maxCachedEmbedProvider},
		{"resolved_url", resolved, maxCachedEmbedURL},
	} {
		if f.got > f.max {
			t.Errorf("embed_cache.%s stored %d chars, ceiling is %d.\n"+
				"That text came from a page the caller nominated, so its length is the caller's "+
				"choice. Persisting it whole turns one request into a megabyte of permanent "+
				"database, and the database is the thing the media quota exists to keep room for.",
				f.name, f.got, f.max)
		}
	}
	// A bound that stores nothing is not a bound either — the card still has to
	// render, so the beginning of the text has to survive.
	if title == 0 || description == 0 {
		t.Errorf("title=%d description=%d — the cap threw the whole field away, which breaks "+
			"every legitimate embed card instead of the attack", title, description)
	}
}

// The cap is a rune count, and this is the test that says so.
//
// Mutation-found, and the mutation it was written for is the whole reason it
// exists: replacing the boundary-aware cut with s[:max] passed every other test
// in this file, because they all clamp ASCII, where bytes and characters are the
// same thing. The text being clamped here is not ASCII — it is whatever the
// caller put in an og:title — so a byte cut lands mid-sequence and stores a
// truncated title that is no longer valid UTF-8. That is a data-integrity bug
// arriving through a security limit, which is the worst way to acquire one: the
// limit gets blamed for the corruption and relaxed.
func TestEmbedCacheClampCutsOnACharacterBoundary(t *testing.T) {
	embedCacheTestDB(t)

	// One ASCII byte in front of multi-byte characters, so the cap does NOT land
	// on a character boundary by luck — with an aligned string a byte cut and a
	// rune cut agree and the test proves nothing.
	long := "A" + strings.Repeat("…", maxCachedEmbedTitle*2)

	a := &App{}
	a.saveEmbedCache("https://attacker.test/utf8", &unfurlResponse{URL: "https://attacker.test/utf8", Title: long})

	var got string
	if err := dbpkg.DB.QueryRow(`SELECT title FROM embed_cache WHERE url = ?`,
		"https://attacker.test/utf8").Scan(&got); err != nil {
		t.Fatalf("read back the cached title: %v", err)
	}
	if !utf8.ValidString(got) {
		t.Errorf("the stored title is not valid UTF-8 (%d bytes) — the cut landed inside a "+
			"character. A length limit must not be able to corrupt the text it shortens.", len(got))
	}
	if n := utf8.RuneCountInString(got); n != maxCachedEmbedTitle {
		t.Errorf("stored %d characters, want exactly the %d-character cap. Counting bytes instead "+
			"of characters makes the real limit vary with the alphabet the caller writes in.",
			n, maxCachedEmbedTitle)
	}
	if !strings.HasPrefix(long, got) {
		t.Errorf("the stored title is not a prefix of what was cached — clamping must shorten " +
			"the text, never rewrite it")
	}
}

// Bounding each row is not enough on its own: the row key is the caller's URL,
// so unlimited rows of any size is still an unlimited table.
func TestEmbedCacheStopsGrowingAtItsCeiling(t *testing.T) {
	embedCacheTestDB(t)

	// Shrink the ceiling rather than write thousands of rows — the property under
	// test is "the table stops growing", and it does not depend on the number.
	prev := maxEmbedCacheRows
	maxEmbedCacheRows = 8
	t.Cleanup(func() { maxEmbedCacheRows = prev })

	a := &App{}
	const attempts = 40
	for i := 0; i < attempts; i++ {
		// The shape of the attack: one URL per request, so ON CONFLICT never fires
		// and every request is an INSERT.
		u := "https://attacker.test/?n=" + strconv.Itoa(i)
		a.saveEmbedCache(u, &unfurlResponse{URL: u, Title: "t" + strconv.Itoa(i), Description: "d"})
	}

	var rows int
	if err := dbpkg.DB.QueryRow(`SELECT COUNT(*) FROM embed_cache`).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows > maxEmbedCacheRows {
		t.Fatalf("%d unfurls of distinct URLs left %d rows, ceiling is %d.\n"+
			"Nothing evicts, so the table is a function of how many URLs the caller sent. "+
			"media:write is the narrowest key the panel issues and it must not be able to grow "+
			"the database without limit.", attempts, rows, maxEmbedCacheRows)
	}

	// Eviction has to drop the OLDEST, or the cache stops serving the URLs anyone
	// is actually working with and a hostile flood evicts the operator's own work
	// while surviving itself.
	var newestPresent bool
	last := "https://attacker.test/?n=" + strconv.Itoa(attempts-1)
	if err := dbpkg.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM embed_cache WHERE url = ?)`, last).Scan(&newestPresent); err != nil {
		t.Fatalf("look up the newest row: %v", err)
	}
	if !newestPresent {
		t.Errorf("the most recently cached URL was evicted while older ones survived — "+
			"eviction is dropping the wrong end, so the cache both fails to cache and fails "+
			"to bound (rows=%d)", rows)
	}
	var oldestPresent bool
	if err := dbpkg.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM embed_cache WHERE url = ?)`,
		"https://attacker.test/?n=0").Scan(&oldestPresent); err != nil {
		t.Fatalf("look up the oldest row: %v", err)
	}
	if oldestPresent {
		t.Errorf("the first of %d rows is still present under a ceiling of %d — whatever was "+
			"deleted, it was not the oldest", attempts, maxEmbedCacheRows)
	}
}

// A cached row still has to be usable after the caps, or the fix has traded a
// disk-fill for a broken feature. This drives the real read path.
func TestBoundedEmbedCacheStillServesWhatItStored(t *testing.T) {
	embedCacheTestDB(t)

	a := &App{}
	a.saveEmbedCache("https://example.test/post", &unfurlResponse{
		URL:         "https://example.test/post",
		Title:       "A perfectly ordinary title",
		Description: "A perfectly ordinary description.",
		Provider:    "example.test",
		Kind:        "video",
		EmbedSrc:    "https://www.youtube-nocookie.com/embed/abcdef",
	})

	got := a.loadEmbedCache("https://example.test/post")
	if got == nil {
		t.Fatal("a row written by saveEmbedCache did not come back from loadEmbedCache")
	}
	if got.Title != "A perfectly ordinary title" || got.Description != "A perfectly ordinary description." {
		t.Errorf("an ordinary embed was altered on the way through the cache: %+v", got)
	}
	if got.Kind != "video" || got.EmbedSrc == "" {
		t.Errorf("video resolution did not survive caching: %+v", got)
	}
}
