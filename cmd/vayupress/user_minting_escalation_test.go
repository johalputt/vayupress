// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/johalputt/vayupress/internal/apikeys"
	"github.com/johalputt/vayupress/internal/auth"
	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/users"
)

// The audit finding, in the attacker's voice:
//
//	I hold one issued key, granted only settings:write — the most commonly
//	handed-out section, since redirects, webhooks, i18n, email templates and the
//	outbox all live under it. One request to POST /api/v1/admin/users with
//	{"role":"admin"} and I own the install. The capability table maps that prefix
//	to SectionSettings so keyMayCall passes me; the handler's own gate is
//	isAdminRequest, which finds no session and returns HasValidAPIKey — true for
//	ANY key. CSRF is not in my way: CSRFTokenMiddleware short-circuits on a valid
//	key. Now I sign in at /os/login with the password I chose, and my account
//	survives revocation of the key that created it.
//
// These tests exercise the real handlers, not the source text. The previous
// generation of this file asserted that a function body CONTAINED a helper name,
// which this repository has already recorded as the wrong shape: it fails an
// honest refactor and passes a regression that deletes the call and leaves the
// word in a comment. A privilege escalation deserves a test that actually tries
// the escalation.

func mintingTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DB_PATH", filepath.Join(dir, "minting.db"))
	t.Setenv("API_KEY", "test-key")
	t.Setenv("DOMAIN", "localhost")
	t.Setenv("CACHE_DIR", dir)
	config.Load()
	if err := dbpkg.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	t.Cleanup(func() {
		dbpkg.ClosePools()
		_ = dbpkg.DB.Close()
	})
	_ = os.Unsetenv("VAYU_SECRET")
	return &App{userStore: users.New(dbpkg.DB), sessions: auth.NewSessionStore(dbpkg.DB)}
}

// scopedKeyRequest builds a request carrying an issued key with exactly the
// grants given — the credential an integration would legitimately hold.
func scopedKeyRequest(method, path, body string, grants ...[2]string) *http.Request {
	p := apikeys.NewPermissions()
	for _, g := range grants {
		p.Grant(apikeys.Section(g[0]), apikeys.Action(g[1]))
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// The header MUST be present, and this is the whole reason the first version
	// of these tests was worthless. isAdminRequest — the predicate the fix
	// replaces — answers auth.HasValidAPIKey(r), which reads the presented key
	// header and knows nothing about the KeyInfo in context. With no header it
	// returned false, every request got 403 for the wrong reason, and the attack
	// tests passed against the VULNERABLE code. Two mutations survived and said
	// so.
	//
	// A real scoped call carries both: RequireAPIKey validates the presented key
	// and stamps the resolved (scoped) identity. Reproducing both is what makes
	// this an attack rather than a request that was never authenticated.
	req.Header.Set("X-API-Key", config.Cfg.APIKey)
	return auth.RequestWithKeyInfo(req, apikeys.KeyInfo{
		ID: "k-scoped", Label: "integration", Scope: apikeys.ScopeExternal, Perms: p,
	})
}

// TestScopedKeyCannotMintAnAdministrator is the finding itself.
func TestScopedKeyCannotMintAnAdministrator(t *testing.T) {
	a := mintingTestApp(t)

	req := scopedKeyRequest(http.MethodPost, "/api/v1/admin/users",
		`{"email":"x@attacker.tld","name":"x","password":"hunter2hunter2","role":"admin"}`,
		[2]string{"settings", "write"})
	rec := httptest.NewRecorder()
	a.handleUserCreate(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("a settings:write key created an account and got %d, want 403.\n\n"+
			"That account is a password login with role admin. It survives revocation of the "+
			"key that made it, so the operator loses the install and revoking the key does not "+
			"take it back.\n\nbody: %s", rec.Code, rec.Body.String())
	}
	if u, err := a.userStore.GetByEmail(context.Background(), "x@attacker.tld"); err == nil && u != nil {
		t.Fatal("the account exists in the store. The status code is not the control — " +
			"what matters is that nothing was written.")
	}
}

// TestScopedKeyCannotPromoteAnExistingAccount closes the same hole by its other
// door: no need to create anything if an existing account can be raised.
func TestScopedKeyCannotPromoteAnExistingAccount(t *testing.T) {
	a := mintingTestApp(t)
	ctx := context.Background()
	if _, err := a.userStore.Create(ctx, "author@example.com", "Author", "correct horse battery", users.RoleAuthor); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := scopedKeyRequest(http.MethodPut, "/api/v1/admin/users/author@example.com/role",
		`{"role":"admin"}`, [2]string{"settings", "write"})
	rec := httptest.NewRecorder()
	a.handleUserSetRole(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("a settings:write key promoted an account and got %d, want 403", rec.Code)
	}
	u, err := a.userStore.GetByEmail(ctx, "author@example.com")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if u.Role == users.RoleAdmin {
		t.Fatal("the account is now an administrator. Creating and promoting are the same " +
			"trust class and both must refuse a scoped key.")
	}
}

// TestScopedKeyCannotDeleteAnAccount. Destroying logins is the same class:
// a key that can delete every administrator locks the operator out.
func TestScopedKeyCannotDeleteAnAccount(t *testing.T) {
	a := mintingTestApp(t)
	ctx := context.Background()
	if _, err := a.userStore.Create(ctx, "owner@example.com", "Owner", "correct horse battery", users.RoleAdmin); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := scopedKeyRequest(http.MethodDelete, "/api/v1/admin/users/owner@example.com", "",
		[2]string{"settings", "write"})
	rec := httptest.NewRecorder()
	a.handleUserDelete(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("a settings:write key deleted an account and got %d, want 403", rec.Code)
	}
	if u, err := a.userStore.GetByEmail(ctx, "owner@example.com"); err != nil || u == nil {
		t.Fatal("the administrator was deleted by a scoped key — that is a lockout, " +
			"reachable from the narrowest credential the panel issues")
	}
}

// THE CONTROL, and it is the whole reason this fix is shaped the way it is.
//
// docs/INSTALLATION.md promises: "The existing API-key path keeps working
// unchanged — admin pages accept EITHER a valid API key OR a login session."
// Tightening these handlers to a session would have closed the hole and broken
// that promise, and an operator whose automation stopped would rightly revert
// the fix. keyLifecycleAuthorized draws the line where the codebase already
// draws it for minting keys: a human admin session, or a SUPERUSER key.
//
// So this test fails if the remediation was over-tightened.
func TestSuperuserKeyStillManagesAccounts(t *testing.T) {
	a := mintingTestApp(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users",
		strings.NewReader(`{"email":"staff@example.com","name":"Staff","password":"correct horse battery","role":"editor"}`))
	req.Header.Set("Content-Type", "application/json")
	req = auth.RequestWithKeyInfo(req, apikeys.SuperuserKeyInfo("k-root", "root", apikeys.ScopeExternal))
	rec := httptest.NewRecorder()
	a.handleUserCreate(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("a SUPERUSER key was refused (%d) — the documented API-key path for account "+
			"management is broken, and an operator's automation stops working.\n\nbody: %s",
			rec.Code, rec.Body.String())
	}
	if u, err := a.userStore.GetByEmail(context.Background(), "staff@example.com"); err != nil || u == nil {
		t.Fatal("the superuser key got 200 but no account was created")
	}
}

// A human administrator session must also still work, which is the other half of
// the documented "either/or".
func TestAdminSessionStillManagesAccounts(t *testing.T) {
	a := mintingTestApp(t)
	ctx := context.Background()
	owner, err := a.userStore.Create(ctx, "boss@example.com", "Boss", "correct horse battery", users.RoleAdmin)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users",
		strings.NewReader(`{"email":"hire@example.com","name":"Hire","password":"correct horse battery","role":"author"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), ctxUserKey, owner))
	rec := httptest.NewRecorder()
	a.handleUserCreate(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("an administrator SESSION was refused (%d) — the console's own staff form "+
			"is broken.\n\nbody: %s", rec.Code, rec.Body.String())
	}
}

// A session that is NOT an administrator must be refused too. Without this,
// keyLifecycleAuthorized could be widened to "any session user" and every test
// above would still pass — the mutation that does exactly that survived the
// first version of this file.
func TestNonAdminSessionCannotMintAnAdministrator(t *testing.T) {
	a := mintingTestApp(t)
	ctx := context.Background()
	editor, err := a.userStore.Create(ctx, "editor@example.com", "Editor", "correct horse battery", users.RoleEditor)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users",
		strings.NewReader(`{"email":"pwn@example.com","name":"P","password":"correct horse battery","role":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), ctxUserKey, editor))
	rec := httptest.NewRecorder()
	a.handleUserCreate(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("an EDITOR session created an account and got %d, want 403", rec.Code)
	}
	if u, err := a.userStore.GetByEmail(ctx, "pwn@example.com"); err == nil && u != nil {
		t.Fatal("an editor minted an administrator — role is not being checked, only session presence")
	}
}

// The account-creating request must leave an audit trail. Before this fix
// neither create nor role-change wrote one, so a new row in the staff list was
// the only evidence an escalation had happened.
func TestAccountCreationIsAudited(t *testing.T) {
	a := mintingTestApp(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users",
		strings.NewReader(`{"email":"audited@example.com","name":"A","password":"correct horse battery","role":"editor"}`))
	req.Header.Set("Content-Type", "application/json")
	req = auth.RequestWithKeyInfo(req, apikeys.SuperuserKeyInfo("k-root", "root", apikeys.ScopeExternal))
	rec := httptest.NewRecorder()
	a.handleUserCreate(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("setup: create failed %d", rec.Code)
	}

	var n int
	if err := dbpkg.DB.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action = 'user.create' AND target = ?`,
		"audited@example.com").Scan(&n); err != nil {
		t.Skipf("audit_log not queryable in this harness: %v", err)
	}
	if n == 0 {
		t.Error("creating a login wrote no audit entry, so the only trace of an account " +
			"appearing is the account itself")
	}
}

var _ = json.Marshal
