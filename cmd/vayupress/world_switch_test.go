// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/settings"
	"github.com/johalputt/vayupress/internal/users"
)

// The audit finding, in the attacker's voice:
//
//	I put a link on a page of your own site. You are signed in as administrator,
//	because you always are. You click it.
//
//	  GET /os/world?target=tor
//
//	That handler persisted settings.KeyTorSpaceEnabled="on" install-wide and
//	spawned the Tor instance — the identical state change its sibling makes
//	behind POST + CSRF at /os/spaces/toggle. This route carried no CSRF
//	middleware, and auth.CSRFTokenMiddleware returns early for GET regardless.
//	SameSite=Strict blocks a purely cross-site initiator, but a same-site link —
//	one rendered on your own public pages — is not cross-site. The 303 puts you
//	back on /os and nothing looks wrong.
//
// The doc comment on the handler already claimed the correct behaviour:
// "side-effect-light: it just sets/clears the view cookie (enabling the Tor
// world itself is the separate CSRF-checked space toggle)". The code did the
// opposite — the claim-is-not-a-control failure this repo keeps paying for.

func worldSwitchApp(t *testing.T) *App {
	t.Helper()
	dir, err := os.MkdirTemp("", "vp-world")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("DB_PATH", filepath.Join(dir, "world.db"))
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
	return &App{siteSettings: settings.New(dbpkg.DB), userStore: users.New(dbpkg.DB)}
}

func worldSwitchAsAdmin(t *testing.T, a *App, target string) *httptest.ResponseRecorder {
	t.Helper()
	admin := &users.User{ID: "admin-1", Email: "boss@example.com", Role: users.RoleAdmin}
	req := httptest.NewRequest(http.MethodGet, "/os/world?target="+target, nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxUserKey, admin))
	rec := httptest.NewRecorder()
	a.handleWorldSwitch(rec, req)
	return rec
}

func torSpaceSetting(t *testing.T, a *App) string {
	t.Helper()
	return a.siteSettings.Get(context.Background(), settings.ForPrimary(), settings.KeyTorSpaceEnabled)
}

func TestTheWorldSwitchDoesNotEnableTheTorSpace(t *testing.T) {
	a := worldSwitchApp(t)
	if got := torSpaceSetting(t, a); got == "on" {
		t.Fatalf("the Tor Space is already on (%q) before the request, so this test proves nothing", got)
	}

	worldSwitchAsAdmin(t, a, "tor")

	if got := torSpaceSetting(t, a); got == "on" {
		t.Error("a GET turned the Anonymous Tor Space on install-wide.\n\n" +
			"That is a persisted state change on a link, on a route with no CSRF check — and " +
			"CSRFTokenMiddleware would return early for GET even if it had one. Any same-site " +
			"page the signed-in operator clicks flips it, and the redirect lands them back on " +
			"/os with nothing visibly wrong.")
	}
}

// And it must not silently do nothing either: the operator clicked "Tor" and
// deserves to arrive somewhere they can act. /os/spaces carries the
// CSRF-protected toggle.
func TestTheWorldSwitchSendsTheOperatorToTheSpacesPageWhenItIsOff(t *testing.T) {
	a := worldSwitchApp(t)
	rec := worldSwitchAsAdmin(t, a, "tor")

	if loc := rec.Header().Get("Location"); loc != "/os/spaces" {
		t.Errorf("switching to Tor while the space is off redirected to %q, want /os/spaces.\n\n"+
			"Refusing the side effect is only half the fix; the operator has to land on the "+
			"page that can grant it, or the button reads as broken.", loc)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == worldCookie && c.Value == "tor" {
			t.Error("the view cookie was set to tor while the space is off, so the console " +
				"would try to proxy to an instance that does not exist")
		}
	}
}

// The control: once the space IS enabled — through the CSRF-protected toggle —
// the switch does exactly what its comment says, and sets the view cookie.
func TestTheWorldSwitchStillEntersAnEnabledTorSpace(t *testing.T) {
	a := worldSwitchApp(t)
	if err := a.siteSettings.SetMany(context.Background(), settings.ForPrimary(),
		map[string]string{settings.KeyTorSpaceEnabled: "on"}); err != nil {
		t.Fatalf("enable space: %v", err)
	}

	rec := worldSwitchAsAdmin(t, a, "tor")

	var got string
	for _, c := range rec.Result().Cookies() {
		if c.Name == worldCookie {
			got = c.Value
		}
	}
	if got != "tor" {
		t.Errorf("the view cookie is %q after switching into an ENABLED Tor Space, want \"tor\" "+
			"— the operator cannot reach their own Tor console", got)
	}
}

// Leaving the Tor view must keep working unconditionally. An operator who can
// enter a world and not leave it is stuck, and that has happened here before
// (the 30-day cookie).
func TestTheWorldSwitchAlwaysLetsTheOperatorBackToClearnet(t *testing.T) {
	a := worldSwitchApp(t)
	rec := worldSwitchAsAdmin(t, a, "clearnet")

	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == worldCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("switching back to clearnet did not clear the view cookie")
	}
}

// The route also fell to the permissive author default in osPathMinLevel: it
// matched no area and is not under /os/api/, so the fail-closed API rule never
// saw it either.
func TestTheWorldSwitchRouteIsAdminGated(t *testing.T) {
	if got := osPathMinLevel("/os/world"); got != accessAdmin {
		t.Errorf("osPathMinLevel(\"/os/world\") = %d, want accessAdmin (%d).\n\n"+
			"Switching the console between the clearnet and Tor worlds is an infrastructure "+
			"control and sits with /os/spaces and /os/tor, not with the content pages.",
			got, accessAdmin)
	}
}
