// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/johalputt/vayupress/internal/auth"
	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/users"
	vmail "github.com/johalputt/vayupress/internal/vayuos/mail"
)

// The audit finding, in the attacker's voice:
//
//	I have your mailbox password. I do not use it for mail — I sign in at
//	/os/login, where handleOSLoginSubmit falls through CMS auth into
//	authMailAccount and mints me a vp_session cookie good for seven days. Your
//	mailbox is role "administrator", so that cookie is full VayuOS
//	administration: settings, API keys, staff accounts, backups, power.
//
//	Then you notice. You run the documented remediation — recovery code, reset
//	link, or an administrator reset from the console. It revokes every app
//	password, every member session, every outstanding reset link, and holds your
//	queued mail. It emails you: "For your security, everything that could still
//	be signed in was disconnected." It even tells you the number: 0 web sessions
//	ended.
//
//	It never touched the sessions table. My cookie still resolves, because
//	resolveMailSessionUser only refuses when HashFor returns EMPTY — and a
//	CHANGED hash is not an empty one. I keep your install for the rest of the
//	week, and you have been told in writing that I am gone.
//
// Two defects, one fix. The reset had no way to end a console session
// (SessionStore could only Destroy the token presenting itself), and the notice
// counted a different store's rows while claiming to cover everything.

// resetSessionApp builds an App whose session store and mail engine share ONE
// database, which is what makes this test meaningful: the reset pipeline and
// the credential it must destroy have to be looking at the same rows.
func resetSessionApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DB_PATH", filepath.Join(dir, "reset.db"))
	t.Setenv("API_KEY", "test-key")
	t.Setenv("DOMAIN", "example.com")
	t.Setenv("CACHE_DIR", dir)
	config.Load()
	if err := dbpkg.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	// ClosePools first: on Windows the pool connections keep reset.db open and
	// the t.TempDir RemoveAll fails after the assertions have already passed.
	t.Cleanup(func() {
		dbpkg.ClosePools()
		_ = dbpkg.DB.Close()
	})

	cfg := vmail.DefaultConfig()
	cfg.Enabled = true
	cfg.Domain = "example.com"
	cfg.Hostname = "mail.example.com"
	cfg.StorageDir = dir
	cfg.InboundEnabled = false
	e := vmail.NewEngine(&cfg, nil, dbpkg.DB)
	if err := e.Start(context.Background()); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() { _ = e.Stop(context.Background()) })

	hash, err := auth.HashSecretArgon2id("the-password-the-attacker-stole")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := e.Accounts().Create(context.Background(),
		"boss@example.com", hash, "Boss", "administrator"); err != nil {
		t.Fatalf("seed mailbox: %v", err)
	}
	return &App{vayuMail: e, sessions: auth.NewSessionStore(dbpkg.DB), userStore: users.New(dbpkg.DB)}
}

// Found while building the tests below, and it is a defect of its own: the
// sessions table declared user_id as a foreign key into users(id), and every
// connection opens with PRAGMA foreign_keys=ON — but a mailbox console session
// is stored as "vmail:<address>", and resolveMailSessionUser states plainly that
// "the synthesized user is never persisted". There is no users row to point at,
// so the INSERT was refused and /os/login's mailbox fallback answered
// "could not start session". Nothing tested it, because until now nothing in the
// suite had ever minted one.
//
// Migration 088 rebuilds the table without that constraint. This test is what
// stops it coming back: re-add the foreign key and the sign-in below stops
// working again, loudly, instead of in production.
func TestAMailboxCredentialCanSignInToTheConsole(t *testing.T) {
	a := resetSessionApp(t)

	form := url.Values{"email": {"boss@example.com"}, "password": {"the-password-the-attacker-stole"}}
	req := httptest.NewRequest(http.MethodPost, "/os/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.9:5000"
	rec := httptest.NewRecorder()
	a.handleOSLoginSubmit(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("a valid mailbox credential got %d at /os/login, want 303.\n\n"+
			"The documented mailbox sign-in cannot issue a session at all.\n\nbody: %s",
			rec.Code, rec.Body.String())
	}
	var session string
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookie {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("no session cookie was set, so the redirect lands straight back on the login page")
	}
	uid, err := a.sessions.Validate(context.Background(), session)
	if err != nil {
		t.Fatalf("the issued session does not resolve: %v", err)
	}
	if uid != "vmail:boss@example.com" {
		t.Errorf("session principal = %q, want %q", uid, "vmail:boss@example.com")
	}
}

func TestMailPasswordResetEndsTheConsoleSessionItAuthorised(t *testing.T) {
	a := resetSessionApp(t)
	ctx := context.Background()

	// The attacker's cookie: exactly what handleOSLoginSubmit mints for a
	// mailbox credential.
	stolen, err := a.sessions.Create(ctx, "vmail:boss@example.com")
	if err != nil {
		t.Fatalf("mint session: %v", err)
	}
	if _, err := a.sessions.Validate(ctx, stolen); err != nil {
		t.Fatalf("the session does not resolve before the reset, so this test proves nothing: %v", err)
	}

	deps, ok := a.mailResetDepsFor()
	if !ok {
		t.Fatal("mail reset deps unavailable")
	}
	out, err := applyMailPasswordReset(ctx, deps, "boss@example.com",
		"a brand new password", mailResetByCode, "boss@example.com")
	if err != nil {
		t.Fatalf("reset failed: %v", err)
	}

	if _, err := a.sessions.Validate(ctx, stolen); err == nil {
		t.Fatal("the console session still resolves after a full password reset.\n\n" +
			"The holder has been emailed that everything signed in was disconnected. For an " +
			"administrator-role mailbox this is install-wide VayuOS access retained for the " +
			"remaining seven days of the cookie's TTL, through the exact remediation the " +
			"product documents.")
	}

	// And the notice must not understate what it did. Reporting 0 while ending a
	// session is the same class of defect as the one above, pointing the other
	// way: the operator reads it and believes nothing was signed in.
	if out.SessionsRevoked < 1 {
		t.Errorf("SessionsRevoked = %d after ending a live console session.\n\n"+
			"The recovery email prints this number under the sentence \"everything that could "+
			"still be signed in was disconnected\".", out.SessionsRevoked)
	}
}

// The control: a reset must end THAT mailbox's sessions and nobody else's. A
// DELETE with a wrong or missing predicate would satisfy the test above by
// signing out the entire install.
func TestMailPasswordResetLeavesOtherPrincipalsSignedIn(t *testing.T) {
	a := resetSessionApp(t)
	ctx := context.Background()

	bystander, err := a.sessions.Create(ctx, "vmail:dana@example.com")
	if err != nil {
		t.Fatalf("mint bystander session: %v", err)
	}
	staff, err := a.sessions.Create(ctx, "user-1")
	if err != nil {
		t.Fatalf("mint staff session: %v", err)
	}

	deps, ok := a.mailResetDepsFor()
	if !ok {
		t.Fatal("mail reset deps unavailable")
	}
	if _, err := applyMailPasswordReset(ctx, deps, "boss@example.com",
		"a brand new password", mailResetByCode, "boss@example.com"); err != nil {
		t.Fatalf("reset failed: %v", err)
	}

	if _, err := a.sessions.Validate(ctx, bystander); err != nil {
		t.Error("resetting boss@example.com signed out dana@example.com — the delete is not " +
			"scoped to the mailbox being recovered")
	}
	if _, err := a.sessions.Validate(ctx, staff); err != nil {
		t.Error("resetting a mailbox signed out a CMS staff session; a recovery that logs the " +
			"whole install out is an outage wearing a security fix")
	}
}

// DestroyForUser is the primitive, and it is worth pinning on its own: nothing
// else in the product could evict a principal, so a regression here is silent
// until someone is attacked.
func TestDestroyForUserEndsEverySessionForOnePrincipal(t *testing.T) {
	a := resetSessionApp(t)
	ctx := context.Background()

	var tokens []string
	for i := 0; i < 3; i++ {
		tok, err := a.sessions.Create(ctx, "vmail:boss@example.com")
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		tokens = append(tokens, tok)
	}
	other, err := a.sessions.Create(ctx, "vmail:dana@example.com")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	n, err := a.sessions.DestroyForUser(ctx, "vmail:boss@example.com")
	if err != nil {
		t.Fatalf("DestroyForUser: %v", err)
	}
	if n != 3 {
		t.Errorf("DestroyForUser reported %d, want 3 — the count is printed to the holder", n)
	}
	for i, tok := range tokens {
		if _, err := a.sessions.Validate(ctx, tok); err == nil {
			t.Errorf("session %d of 3 survived; one device left signed in is the whole problem", i+1)
		}
	}
	if _, err := a.sessions.Validate(ctx, other); err != nil {
		t.Error("another principal's session was destroyed")
	}
}
