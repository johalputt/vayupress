// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/members"
)

// These tests pin the rule the user's report exposed: two addresses whose mail
// delivery failed outright still appeared as members, and "Member joined" was
// logged for both. Requesting a sign-in link must be worth nothing on its own —
// membership begins only when the emailed token comes back.

func newVerificationApp(t *testing.T) *App {
	t.Helper()
	config.Cfg.DBPath = ":memory:"
	if err := dbpkg.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	t.Cleanup(func() {
		dbpkg.ClosePools()
		_ = dbpkg.DB.Close()
	})
	return &App{members: members.New(dbpkg.DB)}
}

func requestSignInLink(t *testing.T, a *App, email string) int {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/members/login",
		strings.NewReader(`{"email":"`+email+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.handleMemberLogin(rec, req)
	return rec.Code
}

// TestRequestingALinkCreatesNoMember is the core fix. An address that is merely
// typed into the form — including one on a domain whose mail will bounce — must
// leave nothing behind in the members table.
func TestRequestingALinkCreatesNoMember(t *testing.T) {
	a := newVerificationApp(t)
	ctx := context.Background()

	if code := requestSignInLink(t, a, "gnnweoet@undeliverable.invalid"); code != 200 {
		t.Fatalf("login request = %d, want 200", code)
	}
	if a.members.Exists(ctx, "gnnweoet@undeliverable.invalid") {
		t.Error("requesting a sign-in link must not create a member")
	}
	var total int
	if err := dbpkg.DB.QueryRow(`SELECT COUNT(1) FROM members`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Errorf("members table holds %d rows after a link request, want 0", total)
	}
	// No signup event either — "Member joined" must not appear in the activity feed
	// for somebody who never joined.
	var events int
	if err := dbpkg.DB.QueryRow(`SELECT COUNT(1) FROM member_events WHERE type=?`, members.EventSignup).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Errorf("recorded %d signup events for an unconfirmed address, want 0", events)
	}
}

// TestConsumingTheLinkCreatesTheMember is the other half: the flow must still
// work. Opening the emailed link creates the member, verified, with a session.
func TestConsumingTheLinkCreatesTheMember(t *testing.T) {
	a := newVerificationApp(t)
	ctx := context.Background()

	if code := requestSignInLink(t, a, "reader@example.com"); code != 200 {
		t.Fatalf("login request = %d, want 200", code)
	}
	// Take the token the way the emailed link carries it.
	token, err := a.members.CreateLoginToken(ctx, "reader@example.com")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/members/verify?token="+token, nil)
	rec := httptest.NewRecorder()
	a.handleMemberVerify(rec, req)

	if rec.Code != 303 {
		t.Fatalf("verify = %d, want 303 to the account page", rec.Code)
	}
	m, err := a.members.Get(ctx, "reader@example.com")
	if err != nil {
		t.Fatalf("member should exist after verification: %v", err)
	}
	if m.VerifiedAt == nil {
		t.Error("a member created by verification must be marked verified")
	}
	if n, err := a.members.CountUnverified(ctx); err != nil || n != 0 {
		t.Errorf("verification must not leave an unconfirmed row (n=%d err=%v)", n, err)
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), memberCookie) {
		t.Error("verification should start a member session")
	}
}

// TestLinkRequestIsIndistinguishableForKnownAndUnknownAddresses keeps the
// anti-enumeration property intact: the endpoint must not become a way to ask
// "is this address a member?" now that it no longer creates one.
func TestLinkRequestIsIndistinguishableForKnownAndUnknownAddresses(t *testing.T) {
	a := newVerificationApp(t)
	if _, err := a.members.UpsertScoped(context.Background(), "", "known@example.com"); err != nil {
		t.Fatal(err)
	}
	known := requestSignInLink(t, a, "known@example.com")
	unknown := requestSignInLink(t, a, "unknown@example.com")
	if known != unknown {
		t.Errorf("known = %d, unknown = %d — the responses must be identical", known, unknown)
	}
}

// TestUnverifiedCleanupCardOnlyAppearsWhenThereIsSomethingToClean checks the
// console does not carry a permanent warning: the card exists only while
// unconfirmed rows do.
func TestUnverifiedCleanupCardOnlyAppearsWhenThereIsSomethingToClean(t *testing.T) {
	if got := unverifiedMembersCardHTML(0); got != "" {
		t.Errorf("card rendered with nothing to clean: %q", got)
	}
	one := unverifiedMembersCardHTML(1)
	if !strings.Contains(one, "Remove all 1") || !strings.Contains(one, "1 address was") {
		t.Errorf("singular wording is wrong: %s", one)
	}
	many := unverifiedMembersCardHTML(2)
	if !strings.Contains(many, "Remove all 2") || !strings.Contains(many, "2 addresses were") {
		t.Errorf("plural wording is wrong: %s", many)
	}
}
