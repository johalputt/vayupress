// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	dbpkg "github.com/johalputt/vayupress/internal/db"
)

// Wave-1 guarantees pinned here:
//  1. An INSERT job persists the article's own status — a draft stays a draft.
//     Before this the insert SQL omitted the column entirely, so the schema
//     default 'published' silently published every authoring-surface create.
//  2. An INSERT job with an empty status keeps the historical behaviour
//     ('published'), so jobs enqueued by older binaries replay unchanged.
//  3. Every UPDATE job snapshots the row it overwrites into article_versions —
//     before Wave 1 nothing ever wrote a version and the editor's History modal
//     could only ever say "No versions yet."

func enqueueArticle(t *testing.T, op string, art dbpkg.Article) {
	t.Helper()
	raw, err := json.Marshal(art)
	if err != nil {
		t.Fatalf("marshal article: %v", err)
	}
	if _, err := dbpkg.WDB.Exec(`INSERT INTO write_jobs(article_json,op) VALUES(?,?)`, string(raw), op); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
}

func mustProcess(t *testing.T) {
	t.Helper()
	if empty := processOneJob(0); empty {
		t.Fatal("queue unexpectedly empty — job was not picked up")
	}
}

func articleStatus(t *testing.T, slug string) string {
	t.Helper()
	var status string
	if err := dbpkg.DB.QueryRow(`SELECT COALESCE(status,'') FROM articles WHERE slug=?`, slug).Scan(&status); err != nil {
		t.Fatalf("read back %s: %v", slug, err)
	}
	return status
}

func TestInsertJobPersistsDraftStatus(t *testing.T) {
	now := time.Now().UTC()
	enqueueArticle(t, "insert", dbpkg.Article{
		ID: "w1-draft-id", Title: "Wave One Draft", Slug: "w1-draft",
		Content: "<p>d</p>", Status: "draft", CreatedAt: now, UpdatedAt: now,
	})
	mustProcess(t)
	if got := articleStatus(t, "w1-draft"); got != "draft" {
		t.Fatalf("draft-born article stored with status %q; first save must never publish", got)
	}
}

func TestInsertJobEmptyStatusKeepsPublishedDefault(t *testing.T) {
	now := time.Now().UTC()
	enqueueArticle(t, "insert", dbpkg.Article{
		ID: "w1-pub-id", Title: "Legacy Replay", Slug: "w1-legacy",
		Content: "<p>p</p>", Status: "", CreatedAt: now, UpdatedAt: now,
	})
	mustProcess(t)
	if got := articleStatus(t, "w1-legacy"); got != "published" {
		t.Fatalf("empty-status insert = %q, want published (old-job replay compatibility)", got)
	}
}

func TestUpdateJobSnapshotsOverwrittenVersion(t *testing.T) {
	const slug = "w1-versioned"
	now := time.Now().UTC()

	enqueueArticle(t, "insert", dbpkg.Article{
		ID: "w1-ver-id", Title: "V1 Title", Slug: slug,
		Content: "<p>version one</p>", Tags: []string{"a"}, Status: "published",
		CreatedAt: now, UpdatedAt: now,
	})
	mustProcess(t)

	enqueueArticle(t, "update", dbpkg.Article{
		ID: "w1-ver-id", Title: "V2 Title", Slug: slug,
		Content: "<p>version two</p>", Tags: []string{"b"}, Status: "published",
		CreatedAt: now, UpdatedAt: now,
	})
	mustProcess(t)

	var n int
	if err := dbpkg.DB.QueryRow(`SELECT COUNT(1) FROM article_versions WHERE slug=?`, slug).Scan(&n); err != nil {
		t.Fatalf("count versions: %v", err)
	}
	if n != 1 {
		t.Fatalf("article_versions rows for %s = %d, want exactly 1 (one update = one snapshot)", slug, n)
	}
	var title, content, label string
	if err := dbpkg.DB.QueryRow(`SELECT title,content,label FROM article_versions WHERE slug=?`, slug).
		Scan(&title, &content, &label); err != nil {
		t.Fatalf("scan snapshot: %v", err)
	}
	if title != "V1 Title" || !strings.Contains(content, "version one") {
		t.Errorf("snapshot does not capture the OVERWRITTEN state: title=%q content=%q", title, content)
	}
	if label == "" {
		t.Error("snapshot written without a label")
	}
}
