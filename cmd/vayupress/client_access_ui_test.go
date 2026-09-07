// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/domain"
	"github.com/johalputt/vayupress/internal/users"
)

// newTestUserStore builds a store over the REAL migrated schema, so a test
// cannot pass against a users table that the product does not have — the
// client_domain_id column arrives in migration 079 and the whole point here is
// that it is written.
func newTestUserStore(t *testing.T) *users.Store {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DB_PATH", filepath.Join(dir, "clients.db"))
	t.Setenv("CACHE_DIR", dir)
	t.Setenv("DOMAIN", "localhost")
	if os.Getenv("API_KEY") == "" {
		t.Setenv("API_KEY", "test-key")
	}
	config.Load()
	if err := dbpkg.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	db := dbpkg.DB
	// ClosePools first: on Windows the pool connections keep clients.db open and
	// the t.TempDir RemoveAll fails after the assertions have already passed.
	t.Cleanup(func() {
		dbpkg.ClosePools()
		_ = db.Close()
	})
	return users.New(db)
}

// RoleClient shipped enforced and uncreatable.
//
// The role was validated, the confinement was tested, the client's own page was
// built — and the team page's role picker offered admin/editor/author, with no
// writer for client_domain_id anywhere in the codebase. There was no way to make
// one of these accounts from the panel, which makes every other part of the
// client surface unreachable: a confinement nobody can be placed inside is not a
// security property, it is dead code.

func clientDomain() domain.Domain {
	return domain.Domain{
		ID: "s1", Host: "client.example", SiteType: domain.SiteBlog,
		Status: domain.StatusActive,
	}
}

func TestTheOperatorCanIssueAClientLoginFromTheDomainPage(t *testing.T) {
	page := scopedConsolePage(clientDomain(), 0, 0, 0, true, nil, nil, nil, nil)
	assertCSPSafe(t, "scopedConsolePage", page)

	if !strings.Contains(page, "data-client-create") {
		t.Fatal("the domain page cannot issue a client login. RoleClient is enforced everywhere " +
			"and creatable nowhere, so the entire client surface is unreachable")
	}
	for _, want := range []string{`id="client-email"`, `id="client-password"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the client form is missing %q", want)
		}
	}
	// With no client yet, the page must say so plainly rather than showing an
	// empty table an operator reads as a rendering fault.
	if !strings.Contains(page, "No client login yet") {
		t.Error("a domain with no client login does not say so")
	}
	script := domainManageScript("n1")
	if !strings.Contains(script, "[data-client-create]") || !strings.Contains(script, "/client") {
		t.Error("the issue-login button is rendered but nothing is wired to the endpoint")
	}
}

// A hostile display name must not escape the table it is listed in. This is the
// one field on the card that comes from stored data rather than the operator's
// own keystrokes in this request.
func TestAHostileClientNameCannotBreakOutOfTheList(t *testing.T) {
	page := scopedConsolePage(clientDomain(), 0, 0, 0, true, []users.User{
		{Email: `a@x.test`, Name: `"><script>alert(1)</script>`},
	}, nil, nil, nil)
	assertCSPSafe(t, "scopedConsolePage", page)
	if strings.Contains(page, "<script>alert(1)</script>") {
		t.Errorf("a stored client name reached the page as markup:\n%s", page)
	}
}

// The store is where "a client is always bound to a domain" has to be true,
// because there are three ways to write a user row and only one of them is this
// card. A rule enforced in the handler is a rule the next handler forgets.
func TestAClientAccountCannotExistWithoutItsDomain(t *testing.T) {
	st := newTestUserStore(t)
	ctx := context.Background()

	if _, err := st.CreateClient(ctx, "a@x.test", "A", "correct-horse", ""); err == nil {
		t.Error("a client was created with no domain binding. '' is the PRIMARY domain's " +
			"sentinel everywhere in this codebase, so that account is not an unconfigured " +
			"client — it is a customer holding a login scoped to the agency's own install")
	}
	// The ordinary creation path must refuse the role outright rather than
	// creating one with an empty binding, which authenticates and reaches nothing.
	if _, err := st.Create(ctx, "b@x.test", "B", "correct-horse", users.RoleClient); err == nil {
		t.Error("Create() minted a client with no binding; CreateClient must be the only way in")
	}
	// And a staff account must not be convertible into a client, which would also
	// leave the binding empty.
	if _, err := st.Create(ctx, "c@x.test", "C", "correct-horse", users.RoleAuthor); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRole(ctx, "c@x.test", users.RoleClient); err == nil {
		t.Error("SetRole promoted a staff account to client, leaving the binding empty")
	}
}

// Demotion has to clear the binding. A stale domain id riding along on an
// account that is no longer a client is a scope waiting to be re-applied by any
// future code that reads the column before checking the role.
func TestDemotingAClientClearsTheBinding(t *testing.T) {
	st := newTestUserStore(t)
	ctx := context.Background()
	if _, err := st.CreateClient(ctx, "d@x.test", "D", "correct-horse", "s1"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRole(ctx, "d@x.test", users.RoleAuthor); err != nil {
		t.Fatal(err)
	}
	u, err := st.GetByEmail(ctx, "d@x.test")
	if err != nil {
		t.Fatal(err)
	}
	if u.ClientDomainID != "" {
		t.Errorf("after demotion the account still carries domain %q", u.ClientDomainID)
	}
}

// The password the operator types is a handover credential, not a permanent one.
// The one account whose password the studio should stop knowing is the one it
// just handed over.
func TestAnIssuedClientMustChangeThePasswordTheOperatorChose(t *testing.T) {
	st := newTestUserStore(t)
	u, err := st.CreateClient(context.Background(), "e@x.test", "E", "correct-horse", "s1")
	if err != nil {
		t.Fatal(err)
	}
	if !u.MustChangePassword {
		t.Error("the operator's chosen password remains the client's live credential, so the " +
			"studio permanently knows the password to an account it promised was the client's")
	}
}
