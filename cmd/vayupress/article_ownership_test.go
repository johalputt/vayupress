// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/johalputt/vayupress/internal/api"
	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/queue"
	"github.com/johalputt/vayupress/internal/render"
	"github.com/johalputt/vayupress/internal/users"
)

// The audit finding, in the attacker's voice:
//
//	I am an author. Not an administrator — an author. A contractor you gave a
//	login to, or a mailbox you assigned the "author" role, which is what
//	mapMailRole hands out by default.
//
//	Your Posts manager already lists me every article on the install, including
//	every hosted customer's, because handleOSPosts filters on is_page=0 and
//	nothing else. So I do not have to guess a slug.
//
//	  POST   /os/api/editor/save   {"slug":"<theirs>","title":"…","blocks":[…]}
//	  DELETE /os/api/posts/<theirs>
//
//	The first goes to articles.Update, which calls the explicitly UNSCOPED
//	Repo.Get — no author check, no domain check. The second is
//	DELETE FROM articles WHERE slug=?, with the comments deleted after it and
//	your public caches purged so the page is gone from the live site
//	immediately. versions.Store.Save has no non-test caller, so there is no
//	snapshot to put back.
//
// Your own console says accessAuthor means "author — own content".

func ownershipApp(t *testing.T) *App {
	t.Helper()
	// os.MkdirTemp with an explicitly-ordered cleanup, not t.TempDir. The write
	// queue and the cache purge both create files under CACHE_DIR after the test
	// body returns, and t.TempDir's RemoveAll fails the test on a directory that
	// is not empty — a green suite reporting red for a reason that has nothing to
	// do with what is being tested.
	dir, err := os.MkdirTemp("", "vp-ownership")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) }) // registered first, so it runs LAST
	t.Setenv("DB_PATH", filepath.Join(dir, "own.db"))
	t.Setenv("API_KEY", "test-key")
	t.Setenv("DOMAIN", "example.com")
	t.Setenv("CACHE_DIR", dir)
	config.Load()
	if err := dbpkg.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	t.Cleanup(func() {
		dbpkg.ClosePools()
		_ = dbpkg.DB.Close()
	})
	// handleOSEditorSave / handleOSPostDelete fire CachePurge, whose async
	// sitemap/feed/robots regenerations read config.Cfg.CacheDir on a background
	// goroutine. Registered LAST so it runs FIRST at teardown (LIFO): drain those
	// writes before this test returns, or the next test's config.Load races them
	// under -race. WaitForPurges exists in render for exactly this.
	t.Cleanup(render.WaitForPurges)
	return &App{
		userStore: users.New(dbpkg.DB),
		articles: &api.ArticleService{
			Repo:  dbpkg.NewArticleRepo(dbpkg.DB),
			Queue: queue.NewSQLiteWriter(dbpkg.DB, 10000),
		},
	}
}

// seedOwnedArticle writes a row directly, so the fixture states exactly who owns it
// and which domain it belongs to rather than inheriting whatever the create
// path happens to do.
func seedOwnedArticle(t *testing.T, slug, authorID, domainID string) {
	t.Helper()
	if _, err := dbpkg.DB.Exec(
		`INSERT INTO articles(id,title,slug,content,tags,created_at,updated_at,status,author_id,domain_id,is_page)
		 VALUES(?,?,?,?,?,?,?,'published',?,?,0)`,
		"id-"+slug, "Title of "+slug, slug, "<p>original</p>", "",
		time.Now().UTC(), time.Now().UTC(), authorID, domainID); err != nil {
		t.Fatalf("seed %s: %v", slug, err)
	}
}

// articleBlocks reads the stored block document, NOT the rendered content.
//
// The content column is written through the async write queue, so asserting on
// it would pass whether the save was refused or merely not drained yet — a test
// that cannot tell those apart proves nothing. persistBlocksJSON runs
// synchronously in the same handler, so it is the honest witness to whether the
// save actually happened.
func articleBlocks(t *testing.T, slug string) string {
	t.Helper()
	var c string
	if err := dbpkg.DB.QueryRow(`SELECT COALESCE(blocks_json,'') FROM articles WHERE slug=?`, slug).Scan(&c); err != nil {
		return "" // gone
	}
	return c
}

func articleExists(t *testing.T, slug string) bool {
	t.Helper()
	var n int
	if err := dbpkg.DB.QueryRow(`SELECT COUNT(*) FROM articles WHERE slug=?`, slug).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", slug, err)
	}
	return n > 0
}

// asAuthor builds a request from a principal the console resolved to author
// level — both halves matter: the user (for the id comparison) and the level
// the middleware stamped.
func asAuthor(req *http.Request, u *users.User) *http.Request {
	ctx := context.WithValue(req.Context(), ctxUserKey, u)
	ctx = context.WithValue(ctx, ctxAccessKey, accessAuthor)
	return req.WithContext(ctx)
}

func asEditor(req *http.Request, u *users.User) *http.Request {
	ctx := context.WithValue(req.Context(), ctxUserKey, u)
	ctx = context.WithValue(ctx, ctxAccessKey, accessEditor)
	return req.WithContext(ctx)
}

func saveAs(t *testing.T, a *App, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	a.handleOSEditorSave(rec, req)
	return rec
}

func saveReq(slug, title string) *http.Request {
	body := `{"slug":"` + slug + `","title":"` + title + `","blocks":[{"type":"paragraph","text":"replaced by this save"}]}`
	req := httptest.NewRequest(http.MethodPost, "/os/api/editor/save", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestAnAuthorCannotRewriteAnotherAuthorsPost(t *testing.T) {
	a := ownershipApp(t)
	seedOwnedArticle(t, "someone-elses-post", "user-owner", "")
	intruder := &users.User{ID: "user-intruder", Email: "contractor@example.com", Role: users.RoleAuthor}

	rec := saveAs(t, a, asAuthor(saveReq("someone-elses-post", "Rewritten"), intruder))

	if rec.Code != http.StatusForbidden {
		t.Errorf("an author rewrote another author's post and got %d, want 403.\n\nbody: %s",
			rec.Code, rec.Body.String())
	}
	if got := articleBlocks(t, "someone-elses-post"); got != "" {
		t.Fatalf("the block document was rewritten to %q. The status code is not the control — "+
			"what matters is that the page was not replaced.", got)
	}
}

// The tenant break, which is the reason this is high and not a workflow nicety.
func TestAnAuthorCannotTouchAnotherDomainsPost(t *testing.T) {
	a := ownershipApp(t)
	seedOwnedArticle(t, "customer-post", "", "domain-of-a-paying-customer")
	author := &users.User{ID: "user-author", Email: "staff@example.com", Role: users.RoleAuthor}

	rec := saveAs(t, a, asAuthor(saveReq("customer-post", "Defaced"), author))
	if rec.Code != http.StatusForbidden {
		t.Errorf("an author on this install rewrote a HOSTED CUSTOMER's post and got %d, want 403",
			rec.Code)
	}
	if got := articleBlocks(t, "customer-post"); got != "" {
		t.Fatalf("a hosted customer's page was rewritten (%q) by an author of another site on "+
			"the same install — that is a tenant-isolation break, and it is live on their "+
			"domain the moment the caches purge", got)
	}
}

func TestAnAuthorCannotDeleteAnotherDomainsPost(t *testing.T) {
	a := ownershipApp(t)
	seedOwnedArticle(t, "customer-post-2", "", "domain-of-a-paying-customer")
	author := &users.User{ID: "user-author", Email: "staff@example.com", Role: users.RoleAuthor}

	req := asAuthor(httptest.NewRequest(http.MethodDelete, "/os/api/posts/customer-post-2", nil), author)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("slug", "customer-post-2")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	a.handleOSPostDelete(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("an author deleted a hosted customer's post and got %d, want 403", rec.Code)
	}
	if !articleExists(t, "customer-post-2") {
		t.Fatal("the post is gone, and so are its comments. There is no snapshot to restore " +
			"from: versions.Store.Save has no non-test call site.")
	}
}

// ---------------------------------------------------------------------------
// The controls. Each of these is somebody's ordinary Tuesday.
// ---------------------------------------------------------------------------

func TestAnAuthorStillEditsTheirOwnPost(t *testing.T) {
	a := ownershipApp(t)
	seedOwnedArticle(t, "my-own-post", "user-me", "")
	me := &users.User{ID: "user-me", Email: "me@example.com", Role: users.RoleAuthor}

	rec := saveAs(t, a, asAuthor(saveReq("my-own-post", "My Revision"), me))
	if rec.Code == http.StatusForbidden {
		t.Fatalf("an author was refused their OWN post — the editor is broken for every "+
			"author on the install.\n\nbody: %s", rec.Body.String())
	}
	if got := articleBlocks(t, "my-own-post"); got == "" {
		t.Error("the save returned success but no block document was stored, so the author's " +
			"own edit did not land")
	}
}

// Content that predates multi-author attribution carries no author_id. Refusing
// it would make an author's own legacy posts uneditable on any install that has
// been running for a while, so primary-site unattributed content stays open —
// and the test says so, because a silent allowance is how a hole gets called a
// feature later.
func TestAnAuthorStillEditsUnattributedPrimarySiteContent(t *testing.T) {
	a := ownershipApp(t)
	seedOwnedArticle(t, "legacy-post", "", "")
	author := &users.User{ID: "user-author", Email: "staff@example.com", Role: users.RoleAuthor}

	rec := saveAs(t, a, asAuthor(saveReq("legacy-post", "Tidied Up"), author))
	if rec.Code == http.StatusForbidden {
		t.Errorf("an author was refused an unattributed post on the primary site.\n\n"+
			"Imported and migrated content carries no author_id, so this refuses people their "+
			"own archive.\n\nbody: %s", rec.Body.String())
	}
}

// Editors and administrators edit across authors — that is the job. Tightening
// them would break the console's ordinary review workflow, so the guard must not.
func TestAnEditorStillEditsAnyPost(t *testing.T) {
	a := ownershipApp(t)
	seedOwnedArticle(t, "reviewed-post", "user-someone", "")
	ed := &users.User{ID: "user-editor", Email: "editor@example.com", Role: users.RoleEditor}

	rec := saveAs(t, a, asEditor(saveReq("reviewed-post", "Edited For Style"), ed))
	if rec.Code == http.StatusForbidden {
		t.Fatalf("an EDITOR was refused another author's post — editing across authors is "+
			"what the editor role is for.\n\nbody: %s", rec.Body.String())
	}
}
