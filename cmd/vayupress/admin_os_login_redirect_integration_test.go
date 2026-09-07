// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/johalputt/vayupress/internal/auth"
	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/users"
)

// TestHandleOSLoginRedirectsWhenAuthed is the regression guard for the reported
// bug: opening /os/login while already signed in re-showed the form instead of
// forwarding to the dashboard. With a live session cookie present, the handler
// must 303 to /os and render no form.
func TestHandleOSLoginRedirectsWhenAuthed(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("DB_PATH", filepath.Join(dir, "login.db"))
	os.Setenv("API_KEY", "test-key")
	os.Setenv("DOMAIN", "localhost")
	os.Setenv("CACHE_DIR", dir)
	config.Load()

	if err := dbpkg.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	t.Cleanup(func() {
		// ClosePools first: on Windows the pool connections keep login.db open
		// and the t.TempDir RemoveAll fails after the assertions have passed.
		dbpkg.ClosePools()
		dbpkg.DB.Close()
	})

	a := &App{
		userStore: users.New(dbpkg.DB),
		sessions:  auth.NewSessionStore(dbpkg.DB),
	}
	ctx := context.Background()

	u, err := a.userStore.Create(ctx, "op@example.com", "Operator", "correct horse battery", users.RoleAdmin)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	token, err := a.sessions.Create(ctx, u.ID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Signed-in visit: cookie present → must redirect to the dashboard.
	req := httptest.NewRequest(http.MethodGet, "/os/login", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
	rec := httptest.NewRecorder()
	a.handleOSLogin(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (redirect to dashboard when already signed in)", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/os" {
		t.Errorf("Location = %q, want /os", loc)
	}
	// The redirect itself must be uncacheable too — a cached 303 (or a cached
	// 200 form from an earlier visit) would defeat the session-aware routing.
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("redirect Cache-Control = %q, want it to contain no-store", cc)
	}

	// Stale/unknown cookie: no live session → must render the form (200), not
	// redirect. Proves the guard resolves the session rather than trusting the
	// mere presence of a cookie.
	req2 := httptest.NewRequest(http.MethodGet, "/os/login", nil)
	req2.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "deadbeef-not-a-session"})
	rec2 := httptest.NewRecorder()
	a.handleOSLogin(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("stale-cookie status = %d, want 200 (render form)", rec2.Code)
	}
}
