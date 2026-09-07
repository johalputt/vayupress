// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestAuthPageIsNeverStoredByASharedCache guards the "I am logged in but the site
// shows me the sign-in page, and editing the URL gets me in" report.
//
// The sign-in page already redirects an authenticated visitor, but a CDN or
// reverse proxy that STORED the form could serve it to somebody holding a valid
// session — defeating the redirect before the origin is ever consulted. The
// response must therefore be unstorable by a shared cache and must vary on the
// cookie that decides its content.
func TestAuthPageIsNeverStoredByASharedCache(t *testing.T) {
	rr := httptest.NewRecorder()
	setAuthPageNoCache(rr)
	h := rr.Header()

	cc := h.Get("Cache-Control")
	for _, want := range []string{"private", "no-store"} {
		if !strings.Contains(cc, want) {
			t.Errorf("Cache-Control = %q, must contain %q so no shared cache stores it", cc, want)
		}
	}
	// A shared cache keyed without the cookie could hand one visitor's page to
	// another; Vary: Cookie is what forbids that.
	if got := h.Get("Vary"); !strings.Contains(got, "Cookie") {
		t.Errorf("Vary = %q, want Cookie", got)
	}
	// Belt and braces for edges that honour the CDN-specific directive first.
	if got := h.Get("CDN-Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("CDN-Cache-Control = %q, want no-store", got)
	}
	if h.Get("Pragma") == "" || h.Get("Expires") == "" {
		t.Error("legacy no-cache headers should still be present for old intermediaries")
	}
}

// TestSignInPathsReplaceTheExistingSession pins the rule that authentication
// REPLACES whatever identity the browser was carrying rather than stacking on it.
// Both member sign-in paths must destroy the incoming session server-side, so a
// pre-authentication session can never survive authentication (session fixation)
// and opening a sign-in link for one account while signed in as another cannot
// leave two live identities whose precedence decides who you are.
func TestSignInPathsReplaceTheExistingSession(t *testing.T) {
	for _, tc := range []struct{ name, file string }{
		{"magic link", "handlers_members.go"},
		{"mailbox portal", "handlers_portal.go"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := readSourceFile(t, tc.file)
			// The destroy must appear before the new session is minted.
			destroy := strings.Index(src, "DestroySession(r.Context(), c.Value)")
			create := strings.Index(src, "a.members.CreateSession(r.Context(), m.ID)")
			if destroy < 0 {
				t.Fatal("sign-in must destroy any incoming member session")
			}
			if create < 0 {
				t.Fatal("expected a member session to be created here")
			}
			if destroy > create {
				t.Error("the incoming session must be destroyed BEFORE the new one is issued")
			}
		})
	}
}

// TestMemberLogoutEndsTheOperatorIdentityToo guards the "I log out and it signs me
// straight back in as the previous account" report. resolveCommenter accepts a
// signed-in operator as a member-equivalent on the public site, so clearing only
// the member cookie left that identity standing and the visitor was immediately
// shown as signed in again. Signing out has to mean signed out.
func TestMemberLogoutEndsTheOperatorIdentityToo(t *testing.T) {
	src := readSourceFile(t, "handlers_members.go")
	i := strings.Index(src, "func (a *App) handleMemberLogout(")
	if i < 0 {
		t.Fatal("handleMemberLogout not found")
	}
	body := src[i:]
	if j := strings.Index(body[10:], "\nfunc "); j > 0 {
		body = body[:j+10]
	}
	for _, want := range []string{
		"a.members.DestroySession", // the member session
		"a.sessions.Destroy",       // the console session, server-side
		"auth.ClearSessionCookie",  // and its cookie
	} {
		if !strings.Contains(body, want) {
			t.Errorf("member logout must call %s so no identity survives", want)
		}
	}
}

// readSourceFile loads a file from this package for a structural assertion. These
// are auth invariants that are cheaper to pin at the source than to reconstruct
// through a full HTTP stack with two cooperating session stores.
//
// CRLF is normalised to LF: a checkout whose files were saved with Windows line
// endings never contains the "\n}\n"-style markers these structural tests slice
// on, and every extraction then failed with "X is gone from Y" — reporting a
// refactor that never happened.
func readSourceFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}
